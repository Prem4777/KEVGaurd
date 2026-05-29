import { NextResponse } from "next/server";
import { getSqlLog, clearSqlLog } from "@/lib/coral";

export async function GET() {
  return NextResponse.json({ entries: getSqlLog() });
}

export async function DELETE() {
  clearSqlLog();
  return NextResponse.json({ ok: true });
}
