// App target runner (CONFORMANCE §2 "App, Portal mode"): boots (or points at) an app wired to the fake bridge through
// the SDK-API §13 env names, waits for its claim and first slice, runs the manifest checks and every app check, and
// returns the §6 report. `start(env)` is the programmatic harness: it boots the app with `env` and returns its URL,
// a stop function and optionally `backupNow` (RunningApp.backups.runNow) for the A7 round-trip. `start` runs IN this
// process; the CLI's `--start <module>` passes forkStart(module), which boots the module in a child process per start.
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { manifestDigest } from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import type { AppClient } from "./app-client.ts";
import { runAppChecks } from "./checks/app.ts";
import { APP_CHECK_IDS } from "./checks/catalog.ts";
import { runManifestChecks } from "./checks/manifest.ts";
import { createFakeBridge, type FakeAgent, type FakeBridge } from "./fake-bridge.ts";
import { request } from "./http.ts";
import { buildReport, type PayloadScan, type Report } from "./report.ts";
import { bad, Suite } from "./suite.ts";

export interface AppStartResult {
  /** private-network origin of the app (e.g. http://127.0.0.1:8080) */
  url: string;
  stop(): Promise<void>;
  /** triggers one backup into TB_BACKUP_DIR (A7 round-trip) */
  backupNow?(): Promise<void>;
}

export interface RunAppOptions {
  /** parsed manifest JSON (or use `manifestPath`) */
  manifest?: unknown;
  manifestPath?: string;
  /** programmatic harness: boot the app with `env` (called in-process; wrap with forkStart(module) for a child process) */
  start?: (env: Record<string, string>) => Promise<AppStartResult>;
  /** an app booted elsewhere with the env passed to `onEnv` (no restart / backup checks: they report not_run) */
  url?: string;
  onEnv?: (env: Record<string, string>) => void;
  /** extra env merged into the app env */
  env?: Record<string, string>;
  /** known-good inputs per op id (generic fixtures; never needed for the standard ops) */
  inputs?: Record<string, Json>;
  /** generated deploy template JSON (A9) */
  deployTemplate?: unknown;
  /** per-wait timeout in ms (slice install, status push); default 20 000 */
  timeoutMs?: number;
  /** claim + first slice timeout in ms; default 30 000 */
  bootTimeoutMs?: number;
  /** data directory for the app (default: a fresh temp dir, removed afterwards) */
  dataDir?: string;
  keepData?: boolean;
  /** source trees for M5 */
  scanDirs?: string[];
  agents?: FakeAgent[];
}

export function loadManifest(opts: { manifest?: unknown; manifestPath?: string }): unknown {
  if (opts.manifest !== undefined) return opts.manifest;
  if (!opts.manifestPath) throw new TypeError("runApp: manifest or manifestPath required");
  return JSON.parse(readFileSync(opts.manifestPath, "utf8"));
}

/** The env an app under test boots with (SDK-API §13); the only secrets are TB_ENROL_CODE and TB_KEK (C8). */
export function appEnv(bridge: FakeBridge, dataDir: string, extra: Record<string, string> = {}): Record<string, string> {
  const backup = join(dataDir, "backup");
  mkdirSync(backup, { recursive: true });
  return {
    TB_INSTANCE_ID: bridge.ids.ins,
    TB_ENROL_CODE: bridge.enrolCode,
    TB_BRIDGE_URL: bridge.url,
    TB_PORTAL_KEYS: JSON.stringify(bridge.portalJwks()),
    TB_KEK: randomBytes(32).toString("base64url"),
    TB_DATA_DIR: dataDir,
    TB_BACKUP_DIR: backup,
    TB_LOG_LEVEL: "warn",
    ...extra,
  };
}

export async function runApp(opts: RunAppOptions): Promise<Report> {
  const startedAt = new Date();
  const json = loadManifest(opts);
  const mres = await runManifestChecks(json, {
    ...(opts.manifestPath ? { manifestPath: opts.manifestPath } : {}),
    ...(opts.scanDirs ? { scanDirs: opts.scanDirs } : {}),
    m5NotApplicable: "M5 applies to Core / bridge / SDK source trees (run `tb-conformance manifest <file> --scan <dir>`)",
  });
  const s = new Suite();
  s.results.push(...mres.results);
  const manifest = mres.manifest;
  const subjectOf = (url: string) => `${manifest ? `${manifest.id}@${manifest.version}` : "invalid manifest"} at ${url}`;
  if (!manifest) {
    for (const id of APP_CHECK_IDS) s.record(id, "app check", "app checks need a valid manifest", bad("manifest invalid (M1)"));
    return buildReport({ target: "app", subject: subjectOf(opts.url ?? "(not started)"), startedAt, checks: s.results });
  }
  if (!opts.start && !opts.url) throw new TypeError("runApp: start or url required");

  const bridge = await createFakeBridge({ manifest: manifest as Manifest, ...(opts.agents ? { agents: opts.agents } : {}) });
  const ownDir = opts.dataDir === undefined;
  const dataDir = opts.dataDir ?? mkdtempSync(join(tmpdir(), "tb-conformance-"));
  const env = appEnv(bridge, dataDir, opts.env);
  const timeoutMs = opts.timeoutMs ?? 20_000;
  let app: AppStartResult | null = null;
  let client: AppClient | null = null;
  let scan: PayloadScan | undefined;
  const notes: string[] = [];
  try {
    if (opts.start) app = await opts.start(env);
    else opts.onEnv?.(env);
    const url = app?.url ?? (opts.url as string);
    client = bridge.client(url);
    try {
      await bridge.control.waitForClaim(opts.bootTimeoutMs ?? 30_000);
      await bridge.control.waitForSliceRevision(1, opts.bootTimeoutMs ?? 30_000);
      // the URL must reach the app under test (not e.g. another process holding the port)
      const h = await request(`${url}/tb/v1/health`, { timeoutMs: 5000 }).catch((e: unknown) => ({ status: 0, body: String(e) }));
      const served = (h.body as { manifestDigest?: unknown } | null)?.manifestDigest;
      if (h.status !== 200 || served !== manifestDigest(manifest as Manifest)) {
        throw new Error(`${url} does not answer as the app under test (GET /tb/v1/health → ${h.status}${served ? `, manifestDigest ${String(served)}` : ""}); is another process listening on that port?`);
      }
    } catch (e) {
      const why = `boot failed: ${e instanceof Error ? e.message : String(e)} (claims ${bridge.claims.length}, status pushes ${bridge.statuses.length}, refusals ${bridge.violations.map((v) => v.code).join(",") || "none"})`;
      for (const id of APP_CHECK_IDS) s.record(id, "app check", "app claims and installs its first slice", bad(why));
      return buildReport({ target: "app", subject: subjectOf(url), startedAt, checks: s.results, sdk: { majors: bridge.sdkMajors, reported: null }, notes: [why] });
    }
    const start = opts.start;
    scan = await runAppChecks(s, {
      bridge,
      client: () => client as AppClient,
      manifest: manifest as Manifest,
      env,
      ...(start
        ? {
            restart: async (extra: Record<string, string> = {}) => {
              await app?.stop();
              app = await start({ ...env, ...extra });
              client = bridge.client(app.url);
            },
          }
        : {}),
      ...(app?.backupNow ? { backupNow: () => (app as AppStartResult).backupNow?.() ?? Promise.resolve() } : {}),
      inputs: opts.inputs ?? {},
      ...(opts.deployTemplate !== undefined ? { deployTemplate: opts.deployTemplate } : {}),
      timeoutMs,
    });
    if (!opts.start) notes.push("--url mode: restart and backup checks need a restartable app (start()/--cmd) and report not_run");
    return buildReport({
      target: "app",
      subject: subjectOf(client.url),
      startedAt,
      checks: s.results,
      ...(scan ? { payloadScan: scan } : {}),
      sdk: { majors: bridge.sdkMajors, reported: bridge.claims[0]?.request.sdkVersion ?? null },
      notes,
    });
  } finally {
    await app?.stop().catch(() => undefined);
    await bridge.close();
    if (ownDir && !opts.keepData) rmSync(dataDir, { recursive: true, force: true });
  }
}
