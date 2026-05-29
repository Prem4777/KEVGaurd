type ScanStatus = "queued" | "scanning" | "completed" | "failed";

export type PersistedFinding = {
  packageName: string;
  ecosystem: string;
  vulnerabilityId: string;
  cveId?: string | null;
  kevStatus: boolean;
  severity: string;
  summary: string;
  fix: string;
  affectedVersions?: string | null;
  advisoryUrl?: string | null;
  epssScore?: number | null;
  isDirect?: boolean;
};

export type ScanJob = {
  id: string;
  repositoryUrl: string;
  owner: string;
  repo: string;
  branch?: string | null;
  commitSha?: string | null;
  status: ScanStatus;
  createdAt: string;
};

const jobs = new Map<string, ScanJob>();
const findingsByJob = new Map<string, PersistedFinding[]>();
/** commitSha → scanJobId for cache hits */
const shaIndex = new Map<string, string>();

function makeId() {
  return (
    globalThis.crypto?.randomUUID?.() ??
    `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
  );
}

export async function createScanJob(input: {
  repositoryUrl: string;
  owner: string;
  repo: string;
  branch?: string | null;
  commitSha?: string | null;
}) {
  const job: ScanJob = {
    id: makeId(),
    repositoryUrl: input.repositoryUrl,
    owner: input.owner,
    repo: input.repo,
    branch: input.branch ?? null,
    commitSha: input.commitSha ?? null,
    status: "scanning",
    createdAt: new Date().toISOString(),
  };
  jobs.set(job.id, job);
  findingsByJob.set(job.id, []);
  return job;
}

export async function completeScanJob(scanJobId: string) {
  const job = jobs.get(scanJobId);
  if (job) {
    job.status = "completed";
    if (job.commitSha) shaIndex.set(job.commitSha, job.id);
  }
}

export async function failScanJob(scanJobId: string) {
  const job = jobs.get(scanJobId);
  if (job) job.status = "failed";
}

export async function saveScanFindings(
  scanJobId: string,
  findings: PersistedFinding[],
) {
  if (findings.length === 0) return;
  const existing = findingsByJob.get(scanJobId) ?? [];
  findingsByJob.set(scanJobId, [...existing, ...findings.map((f) => ({ ...f }))]);
}

export async function listRecentScans(limit = 10) {
  const sortedJobs = Array.from(jobs.values()).sort((a, b) =>
    a.createdAt < b.createdAt ? 1 : -1,
  );
  return sortedJobs.slice(0, limit).map((job) => {
    const jobFindings = findingsByJob.get(job.id) ?? [];
    const vulnerableDependencies = new Set(jobFindings.map((f) => f.packageName));
    const kevCount = jobFindings.filter((f) => f.kevStatus).length;
    return {
      ...job,
      findingsCount: jobFindings.length,
      vulnerableDependencies: vulnerableDependencies.size,
      kevCount,
    };
  });
}

export async function getScanById(scanId: string) {
  const job = jobs.get(scanId);
  if (!job) return null;
  const findings = findingsByJob.get(scanId) ?? [];
  return { job, findings };
}

/** Returns a completed scan for the same commit SHA, or null (cache miss). */
export async function findScanByCommitSha(commitSha: string) {
  const jobId = shaIndex.get(commitSha);
  if (!jobId) return null;
  return getScanById(jobId);
}
