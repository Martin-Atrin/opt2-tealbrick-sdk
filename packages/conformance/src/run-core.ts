// Portal Core target runner (CONFORMANCE §2 `tb-conformance core --url <gateway> [--live-readonly]`): the static
// layer on the spec route table, then — with a gateway URL — the live layer. Checks that need a signed-in test
// account report not_run, so a run without one never passes (exit code 1) but still reports every count.
import { ROUTES, type RouteOp } from "@opt2-tealbrick/spec/routes";
import { runCoreStatic } from "./checks/core.ts";
import { API_BASE, LiveClient, liveNotRun, runCoreLive } from "./checks/core-live.ts";
import { loadSpecTypes, stringUnion, type TypeIndex } from "./checks/core-types.ts";
import { buildReport, FAILING_STATUSES, type Report } from "./report.ts";
import { exampleProductIds } from "./targets.ts";

export interface CoreTargetOptions {
  /** gateway origin (a trailing `/api/v1` is stripped); omitted → static checks only, live ids not_run */
  url?: string;
  /** only side-effect-free probes: never device.start or any write (POSTs only when refused by construction) */
  liveReadonly?: boolean;
  /** ms between requests (default 220 → ≤ 5 req/s) */
  minIntervalMs?: number;
  /** request budget (default 600) */
  maxRequests?: number;
  timeoutMs?: number;
  /** test seams: a different route table / type index (sensitivity tests); default = the spec's */
  routes?: readonly RouteOp[];
  types?: TypeIndex;
  extraProductIds?: string[];
}

/** Origin of the gateway URL (a trailing API base path is accepted and dropped). */
export function gatewayOrigin(url: string): string {
  const u = new URL(url);
  const path = u.pathname.replace(/\/+$/, "");
  if (path !== "" && path !== API_BASE) throw new Error(`--url must be the gateway origin (optionally with ${API_BASE}), got path ${u.pathname}`);
  return u.origin;
}

export async function runCoreTarget(opts: CoreTargetOptions = {}): Promise<Report> {
  const startedAt = new Date();
  const routes = opts.routes ?? ROUTES;
  const types = opts.types ?? loadSpecTypes();
  const staticResults = runCoreStatic({ routes, types, productIds: [...exampleProductIds(), ...(opts.extraProductIds ?? [])] });
  const notes: string[] = [];
  let live = liveNotRun("no --url given: static checks only");
  let subject = "route table (static only)";
  if (opts.url) {
    const origin = gatewayOrigin(opts.url);
    subject = `${origin}${API_BASE}`;
    const client = new LiveClient({
      origin,
      readonly: opts.liveReadonly === true,
      ...(opts.minIntervalMs !== undefined ? { minIntervalMs: opts.minIntervalMs } : {}),
      ...(opts.maxRequests !== undefined ? { maxRequests: opts.maxRequests } : {}),
      ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    });
    live = await runCoreLive({ client, routes, errorCodes: stringUnion(types, "ErrorCode") });
    notes.push(
      `mode: ${opts.liveReadonly ? "--live-readonly (no sign-in, no device.start, no writes; POSTs only where refused before any state change)" : "live (device.start refusal + shape probes allowed; no sign-in)"}`,
      `requests sent: ${client.sent} (≥ ${client.opts.minIntervalMs} ms apart, budget ${client.opts.maxRequests})`,
    );
  }
  const checks = [...staticResults, ...live];
  const report = buildReport({ target: "core", subject, startedAt, checks, notes });
  const c = report.counts;
  report.notes.push(`summary: ${c.pass} pass, ${c.fail} fail, ${c.not_run} not_run, ${c.not_applicable} not_applicable, ${c.not_implemented} not_implemented (${checks.length} checks)`);
  const failing = checks.filter((x) => x.status === "fail");
  if (failing.length > 0) report.notes.push(...failing.map((x) => `FAIL ${x.id}: ${x.asserted}`));
  if (checks.some((x) => FAILING_STATUSES.has(x.status) && x.status === "not_run")) report.notes.push("not_run checks fail the run (CONFORMANCE §6: exit 0 only if every check passes)");
  return report;
}
