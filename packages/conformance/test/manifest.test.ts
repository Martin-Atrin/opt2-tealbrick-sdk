// Manifest target: M1–M6 on the fixture, sensitivity on broken manifests, M4 copy scan, M5 literal scan.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { codeLiterals, literalNamesId } from "../src/code-literals.ts";
import { defaultScanDirs, findProductLiterals, MANIFEST_CHECK_IDS, runManifestChecks, runManifestTarget } from "../src/index.ts";

const path = new URL("./fixtures/sample.manifest.json", import.meta.url).pathname;
const manifest = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
const byId = (r: { id: string; status: string }[], id: string) => r.find((c) => c.id === id)?.status;
const checkOf = (r: { id: string; status: string; asserted: string }[], id: string) => r.find((c) => c.id === id);

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

  it("M2.hook_ops reports own vs foreign hook counts; foreign hooks are left to Core (M-HK-3)", async () => {
    const own = (manifest.hooks as Record<string, unknown>[])[0] as { match: { products: string[] } };
    assert.deepEqual(own.match.products, ["conf-sample"], "the fixture declares one own-product hook");
    const foreign = { id: "audit_peer", title: "Audit a peer", phase: "after", order: 200, match: { products: ["peer-app"] }, timeoutMs: 500 };
    const withBoth = { ...manifest, hooks: [...(manifest.hooks as unknown[]), foreign] };
    const c = checkOf((await runManifestChecks(withBoth)).results, "M2.hook_ops");
    assert.equal(c?.status, "pass", JSON.stringify(c));
    assert.match(c?.asserted ?? "", /own 1 \(ops checked\), foreign 1: checked by Core at chain resolution \(M-HK-3\)/);
    // the fixture alone: own 1, foreign 0
    assert.match(checkOf((await runManifestChecks(manifest)).results, "M2.hook_ops")?.asserted ?? "", /own 1 \(ops checked\), foreign 0: checked by Core/);
  });

  it("M2.hook_ops is not_applicable without an own-product hook (none, or only foreign hooks)", async () => {
    const none = { ...manifest };
    delete none.hooks;
    const a = checkOf((await runManifestChecks(none)).results, "M2.hook_ops");
    assert.equal(a?.status, "not_applicable", JSON.stringify(a));
    assert.match(a?.asserted ?? "", /own 0, foreign 0: checked by Core at chain resolution \(M-HK-3\)/);
    const foreignOnly = { ...manifest, hooks: [{ id: "audit_peer", title: "Audit a peer", phase: "after", order: 200, match: { products: ["peer-app"] }, timeoutMs: 500 }] };
    const b = checkOf((await runManifestChecks(foreignOnly)).results, "M2.hook_ops");
    assert.equal(b?.status, "not_applicable", JSON.stringify(b));
    assert.match(b?.asserted ?? "", /own 0, foreign 1: checked by Core at chain resolution \(M-HK-3\)/);
    // a wildcard hook is foreign too (it is not exactly the own product)
    const wild = { ...manifest, hooks: [{ id: "all_ops", title: "All", phase: "after", order: 200, match: { products: ["*"] }, timeoutMs: 500 }] };
    assert.match(checkOf((await runManifestChecks(wild)).results, "M2.hook_ops")?.asserted ?? "", /own 0, foreign 1/);
  });
});

describe("M6.paths: path bases (MANIFEST §3, v0.1.11 (C70))", () => {
  const skill = (id: string) => `---\nname: ${id}\ndescription: Skill ${id}.\n---\n# ${id}\n`;
  /** Multi-app repo like opt2-tealbrick-samples: <repo>/app/{tealbrick.manifest.json,Dockerfile,skills/}. */
  function repo(files: Record<string, string>, m: Record<string, unknown> = appManifest()) {
    const root = mkdtempSync(join(tmpdir(), "tbconf-m6-"));
    const all: Record<string, string> = { "app/tealbrick.manifest.json": JSON.stringify(m), ...files };
    for (const [rel, text] of Object.entries(all)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    return { root, manifestPath: join(root, "app", "tealbrick.manifest.json"), m };
  }
  function appManifest(): Record<string, unknown> {
    const m = JSON.parse(JSON.stringify(manifest)) as Record<string, any>;
    m.runtime.build = { context: "app", dockerfile: "app/Dockerfile" };
    m.skills = [{ id: "use-conf-sample", title: "How to use the sample", file: "skills/use-conf-sample/SKILL.md" }];
    return m;
  }
  const good = { "app/Dockerfile": "FROM scratch\n", "app/skills/use-conf-sample/SKILL.md": skill("use-conf-sample") };
  const m6 = async (m: Record<string, unknown>, opts: Parameters<typeof runManifestChecks>[1]) => checkOf((await runManifestChecks(m, opts)).results, "M6.paths");

  it("passes: build paths from the repo root, skill files from the manifest dir", async () => {
    const r = repo(good);
    try {
      const c = await m6(r.m, { manifestPath: r.manifestPath, repoDir: r.root });
      assert.equal(c?.status, "pass", JSON.stringify(c));
      assert.match(c?.asserted ?? "", /1 build\(s\) under repo .*; 1 skill file\(s\) under manifest dir .*app/);
    } finally {
      rmSync(r.root, { recursive: true, force: true });
    }
  });

  it("not_applicable without a repo dir", async () => {
    const r = repo(good);
    try {
      const c = await m6(r.m, { manifestPath: r.manifestPath });
      assert.equal(c?.status, "not_applicable");
      assert.match(c?.asserted ?? "", /--repo/);
      assert.equal(byId((await runManifestChecks(manifest)).results, "M6.paths"), "not_applicable");
    } finally {
      rmSync(r.root, { recursive: true, force: true });
    }
  });

  it("fails when a skill exists only at the repo root (skills are manifest-relative)", async () => {
    const r = repo({ "app/Dockerfile": "FROM scratch\n", "skills/use-conf-sample/SKILL.md": skill("use-conf-sample") });
    try {
      const c = await m6(r.m, { manifestPath: r.manifestPath, repoDir: r.root });
      assert.equal(c?.status, "fail", JSON.stringify(c));
      assert.match(c?.asserted ?? "", /skill use-conf-sample: skills\/use-conf-sample\/SKILL\.md: no file under the manifest directory/);
    } finally {
      rmSync(r.root, { recursive: true, force: true });
    }
  });

  it("fails when build paths only exist next to the manifest (build paths are repo-relative)", async () => {
    // repo dir wrongly given as the app dir: app/Dockerfile would be looked up in app/app/
    const r = repo(good);
    try {
      const c = await m6(r.m, { manifestPath: r.manifestPath, repoDir: join(r.root, "app") });
      assert.equal(c?.status, "fail", JSON.stringify(c));
      assert.match(c?.asserted ?? "", /runtime\.build\.context app: no directory under the repo root/);
      assert.match(c?.asserted ?? "", /runtime\.build\.dockerfile app\/Dockerfile: no file under the repo root/);
    } finally {
      rmSync(r.root, { recursive: true, force: true });
    }
  });

  it("fails for a service build whose Dockerfile does not exist under the repo root", async () => {
    const m = appManifest() as Record<string, any>;
    m.runtime.services = [{ id: "worker", port: 9000, resources: { cpu: 0.25, memoryMb: 128 }, health: { kind: "tcp" }, startOrder: 0, build: { context: "app", dockerfile: "app/Dockerfile.worker" } }];
    const r = repo(good, m);
    try {
      const c = await m6(m, { manifestPath: r.manifestPath, repoDir: r.root });
      assert.equal(c?.status, "fail", JSON.stringify(c));
      assert.match(c?.asserted ?? "", /runtime\.services\[worker\]\.build\.dockerfile app\/Dockerfile\.worker: no file/);
    } finally {
      rmSync(r.root, { recursive: true, force: true });
    }
  });

  it("single-app layout: manifest at the repo root, both bases are the same directory; runManifestTarget takes repoDir", async () => {
    const root = mkdtempSync(join(tmpdir(), "tbconf-m6s-"));
    try {
      const mp = join(root, "tealbrick.manifest.json");
      writeFileSync(mp, JSON.stringify(manifest));
      writeFileSync(join(root, "Dockerfile"), "FROM scratch\n");
      assert.equal((await m6(manifest, { manifestPath: mp, repoDir: root }))?.status, "pass");
      const t = await runManifestTarget({ manifestPath: mp, repoDir: root });
      assert.equal(t.checks.find((c) => c.id === "M6.paths")?.status, "pass");
      rmSync(join(root, "Dockerfile"));
      assert.equal(byId((await runManifestTarget({ manifestPath: mp, repoDir: root })).checks, "M6.paths"), "fail");
      assert.equal(byId((await runManifestTarget({ manifestPath: mp })).checks, "M6.paths"), "not_applicable");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
