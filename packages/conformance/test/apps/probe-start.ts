// `--start` harness for the child-process tests: the mini app plus switches read from the INHERITED process env
// (TBTEST_*), so the test also proves the child gets the runner's env and the suite's TB_* names.
//   TBTEST_PIDS=<file>        append {pid, suiteEnvInherited} per start (no env values are written)
//   TBTEST_MODE=sabotage      after boot: chdir away and make every write under TBTEST_REPORT_DIR fail with EACCES
//                             (simulates the SDK's uid drop: the process that runs the app can no longer write there)
//   TBTEST_MODE=throw|exit|hang  start() rejects / the process exits 3 / start() never resolves
import fs, { appendFileSync, readFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { resolve, sep } from "node:path";
import { startMiniApp } from "./mini-app.ts";

const manifest = JSON.parse(readFileSync(new URL("../fixtures/sample.manifest.json", import.meta.url), "utf8"));

const originals = { writeFileSync: fs.writeFileSync, openSync: fs.openSync, appendFileSync: fs.appendFileSync };

/** Patches this process's fs so writes under `dir` throw EACCES (live for named ESM imports too). */
export function sabotage(dir: string): void {
  const root = resolve(dir) + sep;
  const guard = <F extends (...a: never[]) => unknown>(f: F): F =>
    ((...a: Parameters<F>) => {
      const p = a[0] as unknown;
      if (typeof p === "string" && resolve(p).startsWith(root)) throw Object.assign(new Error(`EACCES: permission denied, open '${p}'`), { code: "EACCES" });
      return f(...a);
    }) as F;
  fs.writeFileSync = guard(originals.writeFileSync);
  fs.openSync = guard(originals.openSync);
  fs.appendFileSync = guard(originals.appendFileSync);
  syncBuiltinESMExports();
}

export function unsabotage(): void {
  Object.assign(fs, originals);
  syncBuiltinESMExports();
}

export default async function start(env: Record<string, string>) {
  const mode = process.env.TBTEST_MODE ?? "";
  if (process.env.TBTEST_PIDS) appendFileSync(process.env.TBTEST_PIDS, `${JSON.stringify({ pid: process.pid, suiteEnvInherited: process.env.TB_INSTANCE_ID === env.TB_INSTANCE_ID && process.env.TB_DATA_DIR === env.TB_DATA_DIR })}\n`);
  if (mode === "throw") throw new Error("boom from start");
  if (mode === "exit") process.exit(3);
  if (mode === "hang") return new Promise<never>(() => undefined);
  const app = await startMiniApp(manifest, env);
  if (mode === "sabotage" && process.env.TBTEST_REPORT_DIR) {
    process.chdir(tmpdir());
    sabotage(process.env.TBTEST_REPORT_DIR);
  }
  return app;
}
