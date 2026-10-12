// Manifest target: M1–M5 on the fixture, sensitivity on broken manifests, M4 copy scan, M5 literal scan.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { codeLiterals, literalNamesId } from "../src/code-literals.ts";
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

  it("BSA-10: a product with id `connect` passes M5 when only this package's own files or comments name it", async () => {
    const own = fileURLToPath(new URL("..", import.meta.url));
    // this package's own source names `connect` in comments (src/checks/core.ts) — the default scan must not include it
    assert.ok(!defaultScanDirs().some((d) => d.startsWith(own)));
    const dir = mkdtempSync(join(tmpdir(), "tbconf-m5c-"));
    try {
      const mp = join(dir, "tealbrick.manifest.json");
      writeFileSync(mp, JSON.stringify({ ...manifest, id: "connect" }));
      const src = join(dir, "platform");
      mkdirSync(src);
      writeFileSync(
        join(src, "a.ts"),
        [
          "// the connect product used to be special-cased here",
          '/* if (id === "connect") { … } */',
          "/** @example `connect` */",
          "const net = { connect: () => 1 }; net.connect(); // identifier, not a literal",
          'const url = "https://x.test/a//b"; // "connect" in a comment after a string with //',
          "const re = /\\/\\*/; const t = `x${1 / 2}y`; // regex holding /* and a division in a template",
          'const s = "/* not a comment */"; // connect',
        ].join("\n"),
      );
      writeFileSync(join(src, "b.js"), "export const x = 1; /* 'connect' */\n");
      const t = await runManifestTarget({ manifestPath: mp });
      assert.equal(t.checks.find((c) => c.id === "M5")?.status, "pass", JSON.stringify(t.checks.find((c) => c.id === "M5")));
      // explicitly passing this package's own trees is still a no-op
      const r = await runManifestChecks({ ...manifest, id: "connect" }, { scanDirs: [src, join(own, "src"), own] });
      assert.equal(byId(r.results, "M5"), "pass", JSON.stringify(r.results.find((c) => c.id === "M5")));
      // sensitivity: a real string literal in code still fails, in every literal form
      for (const [name, code] of [
        ["c.ts", 'if (product === "connect") route();\n'],
        ["d.ts", "const p = '/api/connect/items';\n"],
        ["e.js", "const p = `${base}/connect`;\n"],
        ["f.ts", "// connect\nconst a = 1 / 2; const b = ['connect'];\n"],
      ]) {
        const one = join(dir, `one-${name}`);
        mkdirSync(one);
        writeFileSync(join(one, name), code);
        assert.deepEqual(findProductLiterals([one], ["connect"]), [`${join(one, name)}: "connect"`], name);
        assert.equal(byId((await runManifestChecks({ ...manifest, id: "connect" }, { scanDirs: [src, one] })).results, "M5"), "fail", name);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("codeLiterals drops comments and keeps string, template and regex literals", () => {
    const src = [
      "// line comment 'a'",
      "/* block 'b' */ const x = 'c' + \"d\\\"e\";",
      "const t = `f${g(`h${'i'}`)}j`;",
      "const r = x / 2 / 3; const re = /k[/]l/gi; return /m/;",
      'const u = "n//o"; const v = "p/*q*/";',
    ].join("\n");
    assert.deepEqual(codeLiterals(src), ["c", 'd\\"e', "f", "h", "i", "", "j", "k[/]l", "m", "n//o", "p/*q*/"]);
    assert.equal(literalNamesId("connect", "connect"), true);
    assert.equal(literalNamesId("/v1/connect/x", "connect"), true);
    assert.equal(literalNamesId("connector", "connect"), false);
  });

  it("runManifestTarget scans the manifest package by default and passes", async () => {
    const r = await runManifestTarget({ manifestPath: path });
    assert.equal(r.target, "manifest");
    assert.equal(r.ok, true, JSON.stringify(r.checks.filter((c) => c.status !== "pass" && c.status !== "not_applicable")));
  });
});
