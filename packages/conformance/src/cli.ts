#!/usr/bin/env node
// tb-conformance — CONFORMANCE §2 targets:
//   tb-conformance app (--start <module.ts> | --cmd "<command>" [--url <origin>] | --url <origin> --env-out <file>) --manifest <file> [options]
//     --start: the module default-exports `start(env) → Promise<{ url, stop, backupNow? }>` (runApp's harness contract);
//     the CLI runs it in a child process (forkStart), a fresh one per (re)start, so the app's own process changes (the
//     SDK's root → uid 1000 drop) never reach the suite
//   tb-conformance manifest <file> [--scan <dir>]... [--expect-digest <sha256:…>]
//   tb-conformance core [--url <gateway origin>] [--live-readonly] [--max-requests <n>] [--interval-ms <ms>]
//     static route-table checks; with --url also live probes (--live-readonly: no sign-in, no writes)
//   tb-conformance bridge (--start <module.ts> | --cmd "<command>") [--groups a,b] [--pause-latency <ms>]
//     --start: default export `start(env) → Promise<{ publicUrl, internalUrl, stop }>`, run in a child process like the
//     app's; --cmd: a separate process with
//     the suite env (TB_PORTAL_URL, TB_ENROL_CODE, TB_KEK, TB_PUBLIC_URL, TB_DATA_DIR, PORT, TB_INTERNAL_PORT) merged
//   tb-conformance relay --cmd "<stdio relay command>" [--login-cmd "<agent login command>"]
// Output: markdown (default) or JSON (--json); --report <base> also writes <base>.json and <base>.md. Exit code 0 only
// when every check passes (CONFORMANCE §6).
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import type { BridgeStartResult } from "./bridge-world.ts";
import { spawnCommand } from "./command.ts";
import { checkStartModule, forkStart } from "./fork-start.ts";
import { request } from "./http.ts";
import { exitCode, type Report, renderMarkdown, resultLabel } from "./report.ts";
import { type AppStartResult, loadManifest, runApp } from "./run-app.ts";
import { runBridgeTarget } from "./run-bridge.ts";
import { runCoreTarget } from "./run-core.ts";
import { runRelayTarget } from "./run-relay.ts";
import { runManifestTarget } from "./targets.ts";

const USAGE = `usage:
  tb-conformance app (--start <module.ts> | --cmd "<command>" [--url <origin>] | --url <origin> --env-out <file>) --manifest <file>
                     [--inputs <file.json>] [--deploy-template <file.json>] [--timeout <ms>] [--json] [--report <base>]
  tb-conformance manifest <file> [--scan <dir>]... [--expect-digest <sha256:…>] [--json] [--report <base>]
  tb-conformance core [--url <gateway origin>] [--live-readonly] [--max-requests <n>] [--interval-ms <ms>] [--json] [--report <base>]
  tb-conformance bridge (--start <module.ts> | --cmd "<command>") [--groups <a,b>] [--pause-latency <ms>] [--timeout <ms>] [--json] [--report <base>]
  tb-conformance relay --cmd "<stdio relay command>" [--login-cmd "<agent login command>"] [--timeout <ms>] [--json] [--report <base>]
  every target: [--allow-not-run]  exit 0 when nothing failed and the only non-passes are not_run (default: not_run fails, CONFORMANCE §6)`;

const readJson = (p: string): unknown => JSON.parse(readFileSync(p, "utf8"));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Spawns `cmd` directly (no shell, C55) with the conformance env; ready when `url` answers HTTP. */
function commandHarness(cmd: string, url: string, bootMs: number) {
  return async (env: Record<string, string>): Promise<AppStartResult> => {
    const child: ChildProcess = spawnCommand(cmd, { env: { ...process.env, ...env }, stdio: ["ignore", "inherit", "inherit"], detached: true });
    const deadline = Date.now() + bootMs;
    for (;;) {
      if (child.exitCode !== null) throw new Error(`app command exited with ${child.exitCode}`);
      try {
        await request(`${url}/tb/v1/health`, { timeoutMs: 1000 });
        break;
      } catch {
        if (Date.now() > deadline) throw new Error(`app did not answer at ${url} within ${bootMs} ms`);
        await sleep(200);
      }
    }
    return {
      url,
      stop: async () => {
        if (child.exitCode !== null || child.pid === undefined) return;
        const exited = new Promise((r) => child.once("exit", r));
        try {
          process.kill(-child.pid, "SIGTERM");
        } catch {
          child.kill("SIGTERM");
        }
        await Promise.race([exited, sleep(5000)]);
        if (child.exitCode === null) {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            child.kill("SIGKILL");
          }
        }
      },
    };
  };
}

/** `--start <module>`: default export (or named `start`) = the harness `start(env)`, checked up front (usage error),
 * then run in a child process per start (forkStart). */
async function loadStart<T extends object>(path: string): Promise<(env: Record<string, string>) => Promise<T>> {
  await checkStartModule(path);
  return forkStart<T>(path);
}

function emit(report: Report, json: boolean, base?: string): void {
  if (base) {
    writeFileSync(`${base}.json`, `${JSON.stringify(report, null, 2)}\n`);
    writeFileSync(`${base}.md`, renderMarkdown(report));
  }
  process.stdout.write(json ? `${JSON.stringify(report, null, 2)}\n` : renderMarkdown(report));
}

export async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      url: { type: "string" },
      cmd: { type: "string" },
      start: { type: "string" },
      manifest: { type: "string" },
      inputs: { type: "string" },
      "deploy-template": { type: "string" },
      "env-out": { type: "string" },
      timeout: { type: "string" },
      scan: { type: "string", multiple: true },
      "expect-digest": { type: "string" },
      "live-readonly": { type: "boolean", default: false },
      "max-requests": { type: "string" },
      "interval-ms": { type: "string" },
      groups: { type: "string" },
      "pause-latency": { type: "string" },
      "login-cmd": { type: "string" },
      "echo-logs": { type: "boolean", default: false },
      json: { type: "boolean", default: false },
      "allow-not-run": { type: "boolean", default: false },
      report: { type: "string" },
      help: { type: "boolean", default: false },
    },
  });
  const [target, file] = positionals;
  if (values.help || !target) {
    process.stderr.write(`${USAGE}\n`);
    return values.help ? 0 : 2;
  }
  let report: Report;
  switch (target) {
    case "manifest": {
      const path = file ?? values.manifest;
      if (!path) throw new Error("manifest: file required");
      report = await runManifestTarget({ manifestPath: path, ...(values.scan ? { scanDirs: values.scan } : {}), ...(values["expect-digest"] ? { expectDigest: values["expect-digest"] } : {}) });
      break;
    }
    case "app": {
      if (!values.manifest) throw new Error("app: --manifest <file> required");
      if (!values.start && !values.cmd && !values.url) throw new Error("app: --start, --cmd or --url required");
      if ([values.start, values.cmd].filter(Boolean).length > 1) throw new Error("app: use one of --start and --cmd");
      if (!values.start && !values.cmd && !values["env-out"]) throw new Error("app: --url mode needs --env-out <file> (the env the app must boot with)");
      const envOut = values["env-out"];
      const manifest = loadManifest({ manifestPath: values.manifest }) as { runtime?: { port?: number } };
      const timeoutMs = values.timeout ? Number(values.timeout) : 20_000;
      const url = (values.url ?? `http://127.0.0.1:${manifest.runtime?.port ?? 8080}`).replace(/\/$/, "");
      const harness = values.start ? await loadStart<AppStartResult>(values.start) : null;
      report = await runApp({
        manifestPath: values.manifest,
        ...(harness
          ? { start: harness }
          : values.cmd
            ? { start: commandHarness(values.cmd, url, Math.max(timeoutMs, 30_000)) }
            : {
                url,
                // the env holds this run's one-time enrolment code and KEK: written to a 0600 file, never printed
                onEnv: (env: Record<string, string>) => {
                  writeFileSync(envOut as string, Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n").concat("\n"), { mode: 0o600 });
                  process.stderr.write(`tb-conformance: boot the app at ${url} with the env in ${envOut}; waiting for its claim\n`);
                },
                bootTimeoutMs: 120_000,
              }),
        ...(values.inputs ? { inputs: readJson(values.inputs) as Record<string, never> } : {}),
        ...(values["deploy-template"] ? { deployTemplate: readJson(values["deploy-template"]) } : {}),
        timeoutMs,
      });
      break;
    }
    case "core": {
      const num = (v: string | undefined, name: string) => {
        if (v === undefined) return undefined;
        const n = Number(v);
        if (!Number.isInteger(n) || n < 0) throw new Error(`core: --${name} must be a non-negative integer`);
        return n;
      };
      const maxRequests = num(values["max-requests"], "max-requests");
      const minIntervalMs = num(values["interval-ms"], "interval-ms");
      report = await runCoreTarget({
        ...(values.url ? { url: values.url } : {}),
        liveReadonly: values["live-readonly"],
        ...(maxRequests !== undefined ? { maxRequests } : {}),
        ...(minIntervalMs !== undefined ? { minIntervalMs } : {}),
      });
      const k = report.counts;
      process.stderr.write(`tb-conformance core: ${k.pass} pass, ${k.fail} fail, ${k.not_run} not_run, ${k.not_implemented} not_implemented → ${resultLabel(report)}\n`);
      break;
    }
    case "bridge": {
      if (!values.start === !values.cmd) throw new Error("bridge: exactly one of --start <module.ts> and --cmd \"<command>\" (the deployed bridge is started by the suite with its env)");
      const ms = (v: string | undefined, name: string) => {
        if (v === undefined) return undefined;
        const n = Number(v);
        if (!Number.isInteger(n) || n <= 0) throw new Error(`bridge: --${name} must be a positive integer (ms)`);
        return n;
      };
      const timeoutMs = ms(values.timeout, "timeout");
      const pauseLatencyMs = ms(values["pause-latency"], "pause-latency");
      report = await runBridgeTarget({
        ...(values.start ? { start: await loadStart<BridgeStartResult>(values.start), subject: `start(env) module ${values.start} (child process)` } : { cmd: values.cmd as string }),
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
        ...(pauseLatencyMs !== undefined ? { pauseLatencyMs } : {}),
        ...(values.groups ? { groups: values.groups.split(",").map((g) => g.trim()).filter(Boolean) } : {}),
        echoLogs: values["echo-logs"],
      });
      const k = report.counts;
      process.stderr.write(`tb-conformance bridge: ${k.pass} pass, ${k.fail} fail, ${k.not_run} not_run, ${k.not_applicable} not_applicable → ${resultLabel(report)}\n`);
      break;
    }
    case "relay": {
      if (!values.cmd) throw new Error('relay: --cmd "<stdio relay command>" required');
      const timeoutMs = values.timeout ? Number(values.timeout) : undefined;
      report = await runRelayTarget({ cmd: values.cmd, ...(values["login-cmd"] ? { loginCmd: values["login-cmd"] } : {}), ...(timeoutMs ? { timeoutMs } : {}) });
      const k = report.counts;
      process.stderr.write(`tb-conformance relay: ${k.pass} pass, ${k.fail} fail, ${k.not_run} not_run → ${resultLabel(report)}\n`);
      break;
    }
    default:
      process.stderr.write(`unknown target ${target}\n${USAGE}\n`);
      return 2;
  }
  emit(report, values.json, values.report);
  return exitCode(report, { allowNotRun: values["allow-not-run"] === true });
}

const isEntry = (() => {
  try {
    return realpathSync(process.argv[1] ?? "") === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (isEntry) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`tb-conformance: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(2);
    },
  );
}
