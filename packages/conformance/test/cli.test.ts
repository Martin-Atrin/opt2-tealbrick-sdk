// CLI: manifest target, pending targets, app --cmd against the mini app, usage errors.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { freePort } from "./apps/free-port.ts";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const manifest = fileURLToPath(new URL("./fixtures/sample.manifest.json", import.meta.url));
const serve = fileURLToPath(new URL("./apps/serve-cli.ts", import.meta.url));
const startModule = fileURLToPath(new URL("./apps/start-module.ts", import.meta.url));
const run = (args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 120_000 });

describe("tb-conformance CLI", () => {
  it("manifest <file> prints markdown and exits 0; --json prints the report", () => {
    const md = run(["manifest", manifest]);
    assert.equal(md.status, 0, md.stdout + md.stderr);
    assert.match(md.stdout, /# Conformance report: manifest/);
    const js = run(["manifest", manifest, "--json"]);
    const report = JSON.parse(js.stdout) as { ok: boolean; target: string; checks: unknown[] };
    assert.deepEqual([report.ok, report.target], [true, "manifest"]);
  });

  it("core against nothing exits 1; bridge without --start/--cmd, relay without --cmd, unknown target and missing args exit 2", () => {
    assert.equal(run(["bridge", "--url", "http://127.0.0.1:1", "--json"]).status, 2, "the suite starts the bridge with its own env");
    assert.equal(run(["relay", "--json"]).status, 2);
    assert.equal(run(["core", "--url", "http://127.0.0.1:1"]).status, 1);
    assert.equal(run(["nope"]).status, 2);
    assert.equal(run([]).status, 2);
    assert.equal(run(["app", "--manifest", manifest]).status, 2);
    assert.equal(run(["app", "--manifest", manifest, "--url", "http://127.0.0.1:1"]).status, 2, "--url needs --env-out");
  });

  it("app --start <module> runs every check (restart + backup round-trip included) and exits 0", () => {
    const r = run(["app", "--start", startModule, "--manifest", manifest, "--timeout", "8000", "--json"]);
    const report = JSON.parse(r.stdout) as { ok: boolean; checks: { id: string; status: string }[] };
    const bad = report.checks.filter((c) => c.status !== "pass" && c.status !== "not_applicable").map((c) => `${c.id}:${c.status}`);
    assert.deepEqual(bad, [], r.stderr.slice(-2000));
    assert.equal(r.status, 0);
    assert.equal(run(["app", "--start", manifest, "--manifest", manifest]).status, 2, "a module without start() is a usage error");
  });

  it("app --cmd boots the app with the conformance env, writes --report files and exits by result", async () => {
    const port = await freePort();
    const dir = mkdtempSync(join(tmpdir(), "tbconf-cli-"));
    try {
      const tpl = join(dir, "template.json");
      writeFileSync(tpl, JSON.stringify({ services: [{ name: "app" }] }));
      const base = join(dir, "report");
      const r = run(["app", "--cmd", `"${process.execPath}" "${serve}" ${port}`, "--url", `http://127.0.0.1:${port}`, "--manifest", manifest, "--deploy-template", tpl, "--timeout", "8000", "--report", base]);
      const report = JSON.parse(readFileSync(`${base}.json`, "utf8")) as { ok: boolean; checks: { id: string; status: string }[] };
      const bad = report.checks.filter((c) => c.status !== "pass" && c.status !== "not_applicable").map((c) => `${c.id}:${c.status}`);
      // --cmd has no backupNow hook → the backup round-trip is the one check that cannot run (not_run fails the run)
      assert.deepEqual(bad, ["A7.backup_roundtrip:not_run"], r.stdout.slice(-2000) + r.stderr.slice(-2000));
      assert.equal(r.status, 1);
      assert.match(readFileSync(`${base}.md`, "utf8"), /A7\.backup_roundtrip/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
