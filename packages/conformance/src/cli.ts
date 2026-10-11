#!/usr/bin/env node
// tb-conformance — CONFORMANCE §2 targets:
//   tb-conformance app (--start <module.ts> | --cmd "<command>" [--url <origin>] | --url <origin> --env-out <file>) --manifest <file> [options]
//     --start: the module default-exports `start(env) → Promise<{ url, stop, backupNow? }>` (runApp's harness contract)
//   tb-conformance manifest <file> [--scan <dir>]... [--expect-digest <sha256:…>]
//   tb-conformance bridge|core --url <origin>   |   tb-conformance relay --cmd "<command>"   (not implemented: run fails)
// Output: markdown (default) or JSON (--json); --report <base> also writes <base>.json and <base>.md. Exit code 0 only
// when every check passes (CONFORMANCE §6).
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { request } from "./http.ts";
import { exitCode, type Report, renderMarkdown } from "./report.ts";
import { type AppStartResult, loadManifest, runApp } from "./run-app.ts";
import { runManifestTarget, runPendingTarget } from "./targets.ts";

const USAGE = `usage:
  tb-conformance app (--start <module.ts> | --cmd "<command>" [--url <origin>] | --url <origin> --env-out <file>) --manifest <file>
                     [--inputs <file.json>] [--deploy-template <file.json>] [--timeout <ms>] [--json] [--report <base>]
  tb-conformance manifest <file> [--scan <dir>]... [--expect-digest <sha256:…>] [--json] [--report <base>]
  tb-conformance bridge --url <origin> | core --url <origin> | relay --cmd "<command>"`;

const readJson = (p: string): unknown => JSON.parse(readFileSync(p, "utf8"));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Spawns `cmd` (shell) with the conformance env; ready when `url` answers HTTP. */
function commandHarness(cmd: string, url: string, bootMs: number) {
  return async (env: Record<string, string>): Promise<AppStartResult> => {
    const child: ChildProcess = spawn(cmd, { shell: true, env: { ...process.env, ...env }, stdio: ["ignore", "inherit", "inherit"], detached: true });
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

/** `--start <module>`: default export (or named `start`) = runApp's harness `start(env) → { url, stop, backupNow? }`. */
async function loadStart(path: string): Promise<(env: Record<string, string>) => Promise<AppStartResult>> {
  const mod = (await import(pathToFileURL(resolve(path)).href)) as { default?: unknown; start?: unknown };
  const fn = typeof mod.default === "function" ? mod.default : mod.start;
  if (typeof fn !== "function") throw new Error(`--start ${path}: no default-exported start(env) function`);
  return fn as (env: Record<string, string>) => Promise<AppStartResult>;
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
      json: { type: "boolean", default: false },
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
      const harness = values.start ? await loadStart(values.start) : null;
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
    case "bridge":
    case "core":
    case "relay":
      report = runPendingTarget(target, values.url ?? values.cmd ?? "(none)");
      break;
    default:
      process.stderr.write(`unknown target ${target}\n${USAGE}\n`);
      return 2;
  }
  emit(report, values.json, values.report);
  return exitCode(report);
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
