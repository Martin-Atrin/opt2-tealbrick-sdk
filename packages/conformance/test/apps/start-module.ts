// `tb-conformance app --start` harness for the mini app: default export start(env) → { url, stop, backupNow }.
import { readFileSync } from "node:fs";
import { startMiniApp } from "./mini-app.ts";

const manifest = JSON.parse(readFileSync(new URL("../fixtures/sample.manifest.json", import.meta.url), "utf8"));

export default function start(env: Record<string, string>) {
  return startMiniApp(manifest, env);
}
