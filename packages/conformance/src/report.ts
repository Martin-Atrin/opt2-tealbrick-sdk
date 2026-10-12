// Report shape (CONFORMANCE §6): JSON (machine) + markdown (human); target, spec digest, SDK versions, every check id
// with result and asserted value, captured-payload scan summary. Exit code 0 only if every check passes.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { digest } from "@opt2-tealbrick/manifest";
import { SPEC_VERSION } from "@opt2-tealbrick/spec";
import type { Json } from "@opt2-tealbrick/spec/sdk";

/**
 * `pass` / `fail`: a real assertion ran. `not_applicable`: the manifest under test declares nothing this check can
 * exercise (reason required; does not fail the run). `not_run`: the check needs an input this run did not get (e.g. a
 * restartable app); `not_implemented`: the check is listed but not built yet. Both FAIL the run (never a silent pass).
 */
export type CheckStatus = "pass" | "fail" | "not_applicable" | "not_run" | "not_implemented";
export const FAILING_STATUSES: ReadonlySet<CheckStatus> = new Set(["fail", "not_run", "not_implemented"]);

export interface CheckResult {
  /** stable id from CONFORMANCE §4 (`A2`, `C4`, …) or a sub-id (`A2.no_proof`, `cred.p1.app_op_rejects_person`) */
  id: string;
  title: string;
  status: CheckStatus;
  /** what was observed (status code, error code, value) */
  asserted: string;
  /** what the spec requires */
  expected: string;
  ms?: number;
}

export type Target = "app" | "manifest" | "bridge" | "relay" | "core";

export interface PayloadScan {
  /** number of captured payloads (requests and responses on the fake surfaces) */
  payloads: number;
  /** what was searched for (labels only, never the values) */
  patterns: string[];
  /** findings: `<where>: <pattern label>` — empty means clean */
  findings: string[];
}

export interface Report {
  target: Target;
  specVersion: string;
  /** digest of the imported spec schema set (CONFORMANCE §3 drift guard) */
  specDigest: string;
  sdk: { majors: number[]; reported: string | null };
  subject: string;
  startedAt: string;
  finishedAt: string;
  ok: boolean;
  counts: Record<CheckStatus, number>;
  checks: CheckResult[];
  payloadScan: PayloadScan;
  notes: string[];
}

const SCHEMA_FILES = ["manifest.schema.json", "workspace-config.schema.json", "instance-slice.schema.json"] as const;

/** sha256(JCS) of the three spec schemas as imported from @opt2-tealbrick/spec (the fakes validate against these). */
export function specDigest(): string {
  const set: Record<string, Json> = {};
  for (const f of SCHEMA_FILES) {
    const path = fileURLToPath(import.meta.resolve(`@opt2-tealbrick/spec/schemas/${f}`));
    set[f] = JSON.parse(readFileSync(path, "utf8")) as Json;
  }
  return digest(set);
}

export function buildReport(input: {
  target: Target;
  subject: string;
  startedAt: Date;
  checks: CheckResult[];
  payloadScan?: PayloadScan;
  sdk?: { majors: number[]; reported: string | null };
  notes?: string[];
}): Report {
  const counts: Record<CheckStatus, number> = { pass: 0, fail: 0, not_applicable: 0, not_run: 0, not_implemented: 0 };
  for (const c of input.checks) counts[c.status]++;
  const scan = input.payloadScan ?? { payloads: 0, patterns: [], findings: [] };
  return {
    target: input.target,
    specVersion: SPEC_VERSION,
    specDigest: specDigest(),
    sdk: input.sdk ?? { majors: [], reported: null },
    subject: input.subject,
    startedAt: input.startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    ok: input.checks.length > 0 && input.checks.every((c) => !FAILING_STATUSES.has(c.status)) && scan.findings.length === 0,
    counts,
    checks: input.checks,
    payloadScan: scan,
    notes: input.notes ?? [],
  };
}

/**
 * Exit code (CONFORMANCE §6): 0 only if every check passes. Explicit opt-in `allowNotRun` (CLI `--allow-not-run`):
 * a run whose only non-passes are `not_run` / `not_applicable` exits 0 — use it where the missing checks are owned
 * elsewhere (e.g. sign-in checks owned by QA in a read-only live run). Any `fail` or `not_implemented` still exits 1.
 */
export function exitCode(report: Report, opts: { allowNotRun?: boolean } = {}): 0 | 1 {
  if (report.ok) return 0;
  return opts.allowNotRun && onlyNotRun(report) ? 0 : 1;
}

/** True when nothing failed: the only non-passes are not_run / not_applicable. */
export function onlyNotRun(report: Report): boolean {
  const c = report.counts as Record<string, number>;
  return (c.fail ?? 0) === 0 && (c.not_implemented ?? 0) === 0;
}

/** Human result label: `PASS`, `PASS (n not_run)` when nothing failed but some checks did not run, else `FAIL`. */
export function resultLabel(report: Report): string {
  if (report.ok) return "PASS";
  const n = (report.counts as Record<string, number>).not_run ?? 0;
  return onlyNotRun(report) && n > 0 ? `PASS (${n} not_run)` : "FAIL";
}

const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

export function renderMarkdown(r: Report): string {
  const lines = [
    `# Conformance report: ${r.target}`,
    "",
    `- Subject: ${r.subject}`,
    `- Result: **${resultLabel(r)}** (${Object.entries(r.counts)
      .filter(([, n]) => n > 0)
      .map(([k, n]) => `${n} ${k}`)
      .join(", ")})`,
    `- Spec: ${r.specVersion}, schema digest \`${r.specDigest}\``,
    `- SDK: majors ${r.sdk.majors.join(", ") || "n/a"}; reported ${r.sdk.reported ?? "n/a"}`,
    `- Run: ${r.startedAt} → ${r.finishedAt}`,
    `- Payload scan: ${r.payloadScan.payloads} payloads, ${r.payloadScan.findings.length} findings`,
    "",
    "Conformance is NOT release evidence (CONFORMANCE §1).",
    "",
    "| Check | Status | Asserted | Expected |",
    "|---|---|---|---|",
    ...r.checks.map((c) => `| ${cell(c.id)} ${cell(c.title)} | ${c.status} | ${cell(c.asserted)} | ${cell(c.expected)} |`),
  ];
  if (r.payloadScan.findings.length > 0) lines.push("", "## Payload scan findings", "", ...r.payloadScan.findings.map((f) => `- ${f}`));
  if (r.notes.length > 0) lines.push("", "## Notes", "", ...r.notes.map((n) => `- ${n}`));
  return `${lines.join("\n")}\n`;
}
