/**
 * coral-bridge.mjs
 *
 * Thin HTTP → MCP bridge that exposes a single POST /mcp/sql endpoint.
 * The FastAPI backend calls this to run SQL against Coral data sources
 * (OSV, CISA KEV, GitHub, NVD).
 *
 * Environment variables:
 *   CORAL_BRIDGE_HOST   — bind host        (default: 127.0.0.1)
 *   CORAL_BRIDGE_PORT   — bind port        (default: 8787)
 *   CORAL_BRIDGE_TOKEN  — optional bearer  (default: none)
 *   CORAL_MCP_COMMAND   — MCP executable   (default: wsl)
 *   CORAL_MCP_ARGS      — JSON array args  (default: ["/root/.local/bin/coral","mcp-stdio"])
 *   CORAL_SQL_TOOL      — force tool name  (default: auto-detect)
 */

import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// ── resolve SDK path relative to THIS file, not cwd ──────────────────────────
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sdkBase   = path.resolve(__dirname, "../node_modules/@modelcontextprotocol/sdk/dist/esm/client");

const { Client }             = await import(pathToFileURL(path.join(sdkBase, "index.js")).href);
const { StdioClientTransport } = await import(pathToFileURL(path.join(sdkBase, "stdio.js")).href);

// ── config ────────────────────────────────────────────────────────────────────
const HOST            = process.env.CORAL_BRIDGE_HOST  || "127.0.0.1";
const PORT            = Number(process.env.CORAL_BRIDGE_PORT  || "8787");
const TOKEN           = process.env.CORAL_BRIDGE_TOKEN || "";
const CORAL_COMMAND   = process.env.CORAL_MCP_COMMAND  || "wsl";
const CORAL_ARGS      = process.env.CORAL_MCP_ARGS
  ? JSON.parse(process.env.CORAL_MCP_ARGS)
  : ["/root/.local/bin/coral", "mcp-stdio"];
const FORCED_TOOL     = process.env.CORAL_SQL_TOOL     || "";

// ── MCP client (lazy, singleton) ──────────────────────────────────────────────
let _clientPromise   = null;
let _toolNamePromise = null;

async function getClient() {
  if (!_clientPromise) {
    _clientPromise = (async () => {
      const client = new Client({ name: "kevguard-coral-bridge", version: "1.0.0" });
      const transport = new StdioClientTransport({
        command: CORAL_COMMAND,
        args:    CORAL_ARGS,
        stderr:  "pipe",
      });
      await client.connect(transport);
      return client;
    })();
  }
  return _clientPromise;
}

async function getSqlToolName(client) {
  if (FORCED_TOOL) return FORCED_TOOL;
  if (!_toolNamePromise) {
    _toolNamePromise = (async () => {
      const { tools = [] } = await client.listTools();
      const tool =
        tools.find(t => t.name === "sql") ??
        tools.find(t => /sql|query|execute/i.test(t.name)) ??
        tools[0];
      if (!tool) throw new Error("No MCP tools exposed by Coral server");
      return tool.name;
    })();
  }
  return _toolNamePromise;
}

// ── row extraction ─────────────────────────────────────────────────────────────
function extractRows(content = []) {
  const text = content
    .filter(b => b?.type === "text" && typeof b.text === "string")
    .map(b => b.text)
    .join("\n")
    .trim();

  if (!text) return content;

  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed.items))           return parsed.items;
    if (Array.isArray(parsed.rows))            return parsed.rows;
    if (Array.isArray(parsed.vulnerabilities)) return parsed.vulnerabilities;
    if (Array.isArray(parsed))                 return parsed;
    return [parsed];
  } catch {
    return [{ text }];
  }
}

async function runSql(sql) {
  const client   = await getClient();
  const toolName = await getSqlToolName(client);
  const result   = await client.callTool({ name: toolName, arguments: { sql } });
  return extractRows(result.content);
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────
function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type":   "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8") || "{}";
}

// ── HTTP server ────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/mcp/sql") {
    return sendJson(res, 404, { error: "Not found" });
  }

  if (TOKEN && req.headers["x-coral-bridge-token"] !== TOKEN) {
    return sendJson(res, 401, { error: "Unauthorized" });
  }

  let body;
  try {
    body = JSON.parse(await readBody(req));
  } catch {
    return sendJson(res, 400, { error: "Invalid JSON" });
  }

  if (!body?.sql || typeof body.sql !== "string") {
    return sendJson(res, 400, { error: "`sql` field is required" });
  }

  try {
    const rows = await runSql(body.sql);
    sendJson(res, 200, { rows });
  } catch (err) {
    sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Coral bridge listening on http://${HOST}:${PORT}`);
});
