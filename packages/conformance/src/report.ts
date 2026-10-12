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
 * `waived` (v0.1.13, C89): a check that would fail / not_run under an active waiver (`--waive <id>@<until>` or
 * `tealbrick-conformance.json`) while the conformance version < `until`; the asserted text keeps the real result.
 */
export type CheckStatus = "pass" | "fail" | "not_applicable" | "not_run" | "not_implemented" | "waived";
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
  /** waivers given for this run (v0.1.13, C89): applied, expired (version ≥ until) or unused (the check did not fail) */
  waivers?: WaiverOutcome[];
}

/** One waiver (CLI `--waive <id>@<until>` or `tealbrick-conformance.json` `{waivers: [{id, until, reason}]}`). */
export interface Waiver {
  id: string;
  /** conformance package version from which the waiver is ignored */
  until: string;
  reason: string;
}
export interface WaiverOutcome extends Waiver {
  /** `applied`: a failing check reported as waived; `expired`: version ≥ until, ignored; `unused`: the check did not fail */
  state: "applied" | "expired" | "unused";
  /** status the check had before the waiver (null when the id was not reported) */
  realStatus: CheckStatus | null;
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
  const counts = countStatuses(input.checks);
  const scan = input.payloadScan ?? { payloads: 0, patterns: [], findings: [] };
  return {
    target: input.target,
    specVersion: SPEC_VERSION,
    specDigest: specDigest(),
    sdk: input.sdk ?? { majors: [], reported: null },
    subject: input.subject,
    startedAt: input.startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    ok: runOk(input.checks, scan),
    counts,
    checks: input.checks,
    payloadScan: scan,
    notes: input.notes ?? [],
  };
}

function countStatuses(checks: readonly CheckResult[]): Record<CheckStatus, number> {
  const counts: Record<CheckStatus, number> = { pass: 0, fail: 0, not_applicable: 0, not_run: 0, not_implemented: 0, waived: 0 };
  for (const c of checks) counts[c.status]++;
  return counts;
}

function runOk(checks: readonly CheckResult[], scan: PayloadScan): boolean {
  return checks.length > 0 && checks.every((c) => !FAILING_STATUSES.has(c.status)) && scan.findings.length === 0;
}

/** Dotted numeric version compare (`0.1.10` > `0.1.9`); a pre-release suffix is ignored. */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) => v.replace(/^v/, "").split(/[-+]/)[0].split(".").map((x) => Number(x) || 0);
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  return 0;
}

/**
 * Waivers (CONFORMANCE v0.1.13, C89): while `version` < `until`, a check that would fail / not_run / not_implemented
 * reports `waived` (its asserted text keeps the real result and the reason) and does not fail the run; at or after
 * `until` the waiver is ignored and a note says so. Counts and `ok` are recomputed; the outcome of every waiver is
 * listed in `report.waivers`.
 */
export function applyWaivers(report: Report, waivers: readonly Waiver[], version: string): void {
  if (waivers.length === 0) return;
  const out: WaiverOutcome[] = [];
  for (const w of waivers) {
    const hits = report.checks.filter((c) => c.id === w.id);
    const realStatus = hits[0]?.status ?? null;
    if (compareVersions(version, w.until) >= 0) {
      out.push({ ...w, state: "expired", realStatus });
      report.notes.push(`waiver ${w.id}@${w.until} ignored: conformance ${version} ≥ ${w.until} (${w.reason})`);
      continue;
    }
    const failing = hits.filter((c) => FAILING_STATUSES.has(c.status));
    for (const c of failing) {
      c.asserted = `${c.status}: ${c.asserted} — waived until ${w.until}: ${w.reason}`;
      c.status = "waived";
    }
    out.push({ ...w, state: failing.length > 0 ? "applied" : "unused", realStatus });
    if (failing.length === 0) report.notes.push(`waiver ${w.id}@${w.until} unused: the check ${realStatus ? `is ${realStatus}` : "was not reported"}`);
  }
  report.waivers = out;
  report.counts = countStatuses(report.checks);
  report.ok = runOk(report.checks, report.payloadScan);
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

/**
 * `--allow-not-run`: the report text must match the exit rule actually used — drop the default "not_run checks fail
 * the run" note and say what this run did instead.
 */
export function applyAllowNotRun(report: Report): void {
  report.notes = report.notes.filter((n) => !n.startsWith("not_run checks fail the run"));
  const nr = (report.counts as Record<string, number>).not_run ?? 0;
  if (nr > 0) {
    report.notes.push(
      onlyNotRun(report)
        ? `--allow-not-run: ${nr} not_run checks do not fail this run (nothing failed; exit 0)`
        : `--allow-not-run: ${nr} not_run checks are tolerated, but the run still fails (fail / not_implemented present)`,
    );
  }
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
  if (r.waivers?.length) lines.push("", "## Waivers", "", "| Check | Until | State | Real status | Reason |", "|---|---|---|---|---|", ...r.waivers.map((w) => `| ${cell(w.id)} | ${cell(w.until)} | ${w.state} | ${w.realStatus ?? "-"} | ${cell(w.reason)} |`));
  if (r.notes.length > 0) lines.push("", "## Notes", "", ...r.notes.map((n) => `- ${n}`));
  return `${lines.join("\n")}\n`;
}
