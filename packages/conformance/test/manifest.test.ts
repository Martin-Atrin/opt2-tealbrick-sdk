// Manifest target: M1–M5 on the fixture, sensitivity on broken manifests, M4 copy scan, M5 literal scan.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { defaultScanDirs, findProductLiterals, MANIFEST_CHECK_IDS, runManifestChecks, runManifestTarget } from "../src/index.ts";

const path = new URL("./fixtures/sample.manifest.json", import.meta.url).pathname;
const manifest = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
const byId = (r: { id: string; status: string }[], id: string) => r.find((c) => c.id === id)?.status;

describe("manifest checks", () => {
  it("the fixture passes M1–M4; M5 not_run without trees; every manifest id is reported", async () => {
    const { results, manifest: m } = await runManifestChecks(manifest, { manifestPath: path });
    assert.ok(m);
    assert.deepEqual(results.map((r) => r.id), [...MANIFEST_CHECK_IDS]);
    assert.deepEqual(results.filter((r) => r.status === "fail").map((r) => r.id), []);
    assert.equal(byId(results, "M5"), "not_run");
    assert.equal(byId(results, "M2.when_settings"), "not_applicable");
  });

  it("an invalid manifest fails M1 and the checks that need it", async () => {
    const { results, manifest: m } = await runManifestChecks({ ...manifest, conformanceExtra: 1 });
    assert.equal(m, null);
    assert.equal(byId(results, "M1"), "fail");
    assert.equal(byId(results, "M3"), "fail");
  });

  it("a wrong expected digest fails M3", async () => {
    const { results } = await runManifestChecks(manifest, { expectDigest: `sha256:${"1".repeat(64)}` });
    assert.equal(byId(results, "M3"), "fail");
  });

  it("M4 finds hand-written generator outputs beside the manifest", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbconf-m4-"));
    try {
      const p = join(dir, "tealbrick.manifest.json");
      writeFileSync(p, JSON.stringify(manifest));
      assert.equal(byId((await runManifestChecks(manifest, { manifestPath: p })).results, "M4.no_copies"), "pass");
      writeFileSync(join(dir, "openapi.json"), "{}");
      assert.equal(byId((await runManifestChecks(manifest, { manifestPath: p })).results, "M4.no_copies"), "fail");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("M5 finds a product id literal in a source tree and passes on clean trees", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbconf-m5-"));
    try {
      writeFileSync(join(dir, "route.ts"), 'if (product === "conf-sample") doThing();\n');
      writeFileSync(join(dir, "clean.ts"), "// a comment mentioning conf-sample without quotes is fine\n");
      assert.deepEqual(findProductLiterals([dir], ["conf-sample"]).length, 1);
      const r = await runManifestChecks(manifest, { scanDirs: [dir] });
      assert.equal(byId(r.results, "M5"), "fail");
      assert.equal(byId((await runManifestChecks(manifest, { scanDirs: defaultScanDirs() })).results, "M5"), "pass");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("runManifestTarget scans the manifest package and this package by default and passes", async () => {
    const r = await runManifestTarget({ manifestPath: path });
    assert.equal(r.target, "manifest");
    assert.equal(r.ok, true, JSON.stringify(r.checks.filter((c) => c.status !== "pass" && c.status !== "not_applicable")));
  });
});
