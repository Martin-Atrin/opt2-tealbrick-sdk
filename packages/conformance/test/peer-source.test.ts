// CONF-MULTIAPP (conformance 0.1.20): the peer config, the signed-index lookup, the source archive and the loader, without
// network (the index bytes, the archive and fetch are injected / stubbed).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { generateKeyPair, manifestDigest, signReleaseIndex } from "@opt2-tealbrick/manifest";
import {
  extractArchive,
  fetchVerifiedIndex,
  githubSource,
  isCheckId,
  loadPeer,
  PeerError,
  parseConformanceConfig,
  type ReleaseRecord,
  selectRecord,
} from "../src/index.ts";
import { PEER, writePeer } from "./apps/peer-fixtures.ts";
import { writeTarGz } from "./apps/tar-write.ts";

const root = mkdtempSync(join(tmpdir(), "tbconf-peer-source-test-"));
after(() => rmSync(root, { recursive: true, force: true }));
const COMMIT = "b".repeat(40);
const REPO = `Tealbrick/opt2-tealbrick-${PEER}`;
const rec = (over: Record<string, unknown> = {}) => ({ kind: "app", product: PEER, version: "1.0.0", channel: "stable", repo: REPO, commit: COMMIT, manifestDigest: null, ...over });

describe("peers in tealbrick-conformance.json", () => {
  const parse = (doc: unknown) => parseConformanceConfig(doc, "test.json");
  it("accepts {product, version, channel?, settings?} (max 3) and contractOps of declared peers", () => {
    const c = parse({ peers: [{ product: "kanban", version: "0.1.13" }, { product: "knowledge", version: "0.1.21", channel: "dev", settings: { engine: "stub" } }], contractOps: { "messages/1": "knowledge.data_pull" } });
    assert.deepEqual(c.peers, [
      { product: "kanban", version: "0.1.13", channel: "stable" },
      { product: "knowledge", version: "0.1.21", channel: "dev", settings: { engine: "stub" } },
    ]);
    assert.deepEqual(c.contractOps, { "messages/1": { peer: "knowledge", op: "data_pull" } });
    assert.deepEqual(parse({}).peers, []);
  });
  it("refuses unknown keys, ranges, duplicates, more than 3, a bad channel and contractOps of a stranger (usage errors)", () => {
    const bad = (doc: unknown, re: RegExp) => assert.throws(() => parse(doc), re);
    bad({ peers: [{ product: "kanban", version: "0.1.13", branch: "main" }] }, /unknown key "branch"/);
    bad({ peers: [{ product: "kanban", version: "^0.1.13" }] }, /exact released version/);
    bad({ peers: [{ product: "kanban", version: "latest" }] }, /exact released version/);
    bad({ peers: [{ product: "kanban", version: "0.1.13" }, { product: "kanban", version: "0.1.12" }] }, /listed twice/);
    bad({ peers: ["a", "b", "c", "d"].map((p) => ({ product: `app-${p}`, version: "1.0.0" })) }, /at most 3 peers/);
    bad({ peers: [{ product: "kanban", version: "0.1.13", channel: "beta" }] }, /channel/);
    bad({ peers: [{ product: "Kanban", version: "0.1.13" }] }, /product id/);
    bad({ peers: [{ product: "kanban", version: "0.1.13", settings: { big: "x".repeat(5000) } }] }, /too large/);
    bad({ peers: "kanban" }, /array/);
    bad({ contractOps: { "messages/1": "knowledge.data_pull" } }, /not a declared peer/);
    bad({ peers: [{ product: "knowledge", version: "0.1.21" }], contractOps: { "nope/1": "knowledge.data_pull" } }, /unknown contract/);
    bad({ peers: [{ product: "knowledge", version: "0.1.21" }], contractOps: { "messages/1": "data_pull" } }, /<peer product>\.<op id>/);
  });
  it("group X row ids are catalogued (waivers may name them); other shapes are not", () => {
    for (const id of ["X1.peer_boot.kanban", "X2.companion_call.kanban.card_get", "X3.companion_refused.kanban.card_get", "X4.contract_schema.fleet.directory_feed", "X5.hold_round_trip.kanban.card_send"]) assert.ok(isCheckId(id), id);
    for (const id of ["X1.peer_boot", "X1.peer_boot.kanban.extra", "X2.companion_call.kanban", "X9.peer_boot.kanban", "X2.nope.kanban.op"]) assert.ok(!isCheckId(id), id);
    assert.ok(parseConformanceConfig({ waivers: [{ id: "X2.companion_call.kanban.card_get", until: "0.2.0", reason: "pending" }] }, "t").waivers.length === 1);
  });
});

describe("signed release index", () => {
  const body = (releases: unknown[]) => ({ schema: "opt2.release-index/v2" as const, generatedAt: "2026-10-17T00:00:00.000Z", releases, offers: [] });
  const serve = (files: Record<string, string>) => async (url: string) => {
    const f = files[url];
    if (f === undefined) throw new PeerError(`HTTP 404 for ${url}`);
    return Buffer.from(f);
  };
  const now = () => Date.parse("2026-10-18T00:00:00Z");

  it("verifies the JWS with the pinned key and returns releases[]", async () => {
    const key = await generateKeyPair();
    const b = body([rec()]);
    const jws = await signReleaseIndex(b, { iat: Math.floor(now() / 1000) - 60 }, key);
    const got = await fetchVerifiedIndex({ bases: ["https://i.test/r"], keys: [key.publicJwk.x], now, get: serve({ "https://i.test/r/index.json": JSON.stringify(b), "https://i.test/r/index.jws": jws }) });
    assert.equal((got[0] as { product: string }).product, PEER);
  });
  it("refuses a signature by another key, a tampered body, an expired envelope and an unexpected schema; tries the next base", async () => {
    const key = await generateKeyPair();
    const other = await generateKeyPair();
    const b = body([rec()]);
    const iat = Math.floor(now() / 1000) - 60;
    const good = await signReleaseIndex(b, { iat }, key);
    const opts = (files: Record<string, string>, keys = [key.publicJwk.x]) => ({ bases: ["https://i.test/r"], keys, now, get: serve(files) });
    await assert.rejects(fetchVerifiedIndex(opts({ "https://i.test/r/index.json": JSON.stringify(b), "https://i.test/r/index.jws": await signReleaseIndex(b, { iat }, other) })), /signature refused/);
    await assert.rejects(fetchVerifiedIndex(opts({ "https://i.test/r/index.json": JSON.stringify(body([rec({ commit: "c".repeat(40) })])), "https://i.test/r/index.jws": good })), /digest mismatch/);
    await assert.rejects(fetchVerifiedIndex(opts({ "https://i.test/r/index.json": JSON.stringify(b), "https://i.test/r/index.jws": await signReleaseIndex(b, { iat: iat - 3 * 86400, exp: iat - 86400 }, key) })), /signature refused/);
    await assert.rejects(fetchVerifiedIndex(opts({ "https://i.test/r/index.json": JSON.stringify({ ...b, schema: "other" }), "https://i.test/r/index.jws": good })), /unexpected release index schema/);
    // first base unreachable, second verifies
    const ok = await fetchVerifiedIndex({ bases: ["https://down.test/r", "https://i.test/r"], keys: [key.publicJwk.x], now, get: serve({ "https://i.test/r/index.json": JSON.stringify(b), "https://i.test/r/index.jws": good }) });
    assert.equal(ok.length, 1);
    // none verifies: every base and its reason is named
    await assert.rejects(fetchVerifiedIndex({ bases: ["https://down.test/r", "https://down2.test/r"], keys: [key.publicJwk.x], now, get: serve({}) }), /no release index host gave a verified index:\n.*down\.test.*\n.*down2\.test/);
  });
  it("pins the platform release key the CLI pins (registry/keys.json)", async () => {
    const { RELEASE_KEYS, INDEX_BASES } = await import("../src/index.ts");
    assert.deepEqual([...RELEASE_KEYS], ["H7nxFrNugQLVOqEXVIB4aOg83Jn19UCosd27fqnoPPI"]);
    assert.ok(INDEX_BASES.every((b) => b.startsWith("https://github.com/Tealbrick/")));
  });
});

describe("record selection", () => {
  const spec = { product: PEER, version: "1.0.0", channel: "stable" as const };
  it("returns repo + commit of the one app record; explains a missing version or channel", () => {
    assert.deepEqual(selectRecord([rec(), { kind: "bridge", product: PEER, version: "1.0.0" }], spec), { ...spec, repo: REPO, commit: COMMIT, manifestDigest: null });
    assert.throws(() => selectRecord([rec({ version: "0.9.0" }), rec({ version: "0.9.1" })], spec), /not in the signed release index; released on stable: 0\.9\.0, 0\.9\.1/);
    assert.throws(() => selectRecord([rec({ channel: "dev" })], spec), /that version exists on channel dev: set "channel"/);
    assert.throws(() => selectRecord([], spec), /has no stable release of conf-peer/);
    assert.throws(() => selectRecord([rec(), rec()], spec), /more than once/);
  });
  it("refuses a repo outside the Teal Brick app repos and a record without a commit", () => {
    assert.throws(() => selectRecord([rec({ repo: "evil/opt2-tealbrick-x" })], spec), /not a Teal Brick app repo/);
    assert.throws(() => selectRecord([rec({ repo: "Tealbrick/other" })], spec), /not a Teal Brick app repo/);
    assert.throws(() => selectRecord([rec({ commit: "main" })], spec), /no source commit/);
    assert.equal(selectRecord([rec({ repo: "Martin-Atrin/opt2-tealbrick-conf-peer" })], spec).repo, "Martin-Atrin/opt2-tealbrick-conf-peer");
  });
});

describe("source archive", () => {
  const top = `opt2-tealbrick-${PEER}-${COMMIT}`;
  const tgz = (entries: Record<string, string>) => writeTarGz(Object.entries(entries).map(([name, data]) => ({ name, data: Buffer.from(data) })));
  it("extracts the files without the top directory when it ends with the signed commit", () => {
    const dir = join(root, "x-good");
    mkdirSync(dir);
    const n = extractArchive(tgz({ [`${top}/package.json`]: "{}", [`${top}/src/a.ts`]: "export {}" }), COMMIT, dir);
    assert.equal(n, 2);
    assert.equal(readFileSync(join(dir, "src/a.ts"), "utf8"), "export {}");
  });
  it("refuses another commit, several top directories, an unsafe path and a non-archive", () => {
    const dir = join(root, "x-bad");
    mkdirSync(dir);
    assert.throws(() => extractArchive(tgz({ [`opt2-tealbrick-${PEER}-${"c".repeat(40)}/a`]: "x" }), COMMIT, dir), /not the commit of the signed index record/);
    assert.throws(() => extractArchive(tgz({ [`${top}/a`]: "x", "other/b": "y" }), COMMIT, dir), /not the commit/);
    assert.throws(() => extractArchive(tgz({ [`${top}/../../escape`]: "x" }), COMMIT, dir), /unsafe path/);
    assert.throws(() => extractArchive(Buffer.from("not a tar"), COMMIT, dir), /not a gzip tar/);
    assert.equal(existsSync(join(root, "escape")), false);
  });
  it("a 404 from codeload says the repo is private (or the commit unpushed); a redirect to another host is refused; nothing is installed", async () => {
    const real = globalThis.fetch;
    const record: ReleaseRecord = { product: PEER, version: "1.0.0", channel: "stable", repo: REPO, commit: COMMIT, manifestDigest: null };
    try {
      globalThis.fetch = (async () => new Response("not found", { status: 404 })) as typeof fetch;
      await assert.rejects(githubSource(record, join(root, "gh-1")), /HTTP 404.*private or the commit is not pushed.*PUBLIC app repos only/s);
      globalThis.fetch = (async () => new Response(null, { status: 302, headers: { location: "https://evil.example/x.tgz" } })) as typeof fetch;
      await assert.rejects(githubSource(record, join(root, "gh-2")), /refusing https:\/\/evil\.example\/x\.tgz/);
    } finally {
      globalThis.fetch = real;
    }
  });
});

describe("install and build from the archive (real pnpm, no dependencies)", () => {
  const havePnpm = spawnSync("pnpm", ["--version"], { encoding: "utf8" }).status === 0;
  const record: ReleaseRecord = { product: PEER, version: "1.0.0", channel: "stable", repo: REPO, commit: COMMIT, manifestDigest: null };
  const top = `opt2-tealbrick-${PEER}-${COMMIT}`;
  const archive = (files: Record<string, string>) => writeTarGz(Object.entries(files).map(([name, data]) => ({ name: `${top}/${name}`, data: Buffer.from(data) })));
  const lock = "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .: {}\n";
  const pkg = JSON.stringify({ name: "fixture", version: "1.0.0", private: true, scripts: { build: "node build.ts" } });
  const withFetch = async (bytes: Buffer, run: () => Promise<void>) => {
    const real = globalThis.fetch;
    globalThis.fetch = (async () => new Response(new Uint8Array(bytes), { status: 200 })) as typeof fetch;
    try {
      await run();
    } finally {
      globalThis.fetch = real;
    }
  };

  it("downloads the commit archive, installs from the lockfile with --ignore-scripts, runs the repo's build script", { skip: !havePnpm && "pnpm not on PATH" }, async () => {
    const dir = join(root, "gh-build");
    mkdirSync(dir);
    // a lifecycle script must NOT run (--ignore-scripts): the postinstall would write the marker
    const scripted = JSON.stringify({ name: "fixture", version: "1.0.0", private: true, scripts: { build: "node build.ts", postinstall: "node -e \"require('fs').writeFileSync('postinstall-ran','x')\"" } });
    await withFetch(archive({ "package.json": scripted, "pnpm-lock.yaml": lock, "build.ts": "import { writeFileSync } from 'node:fs'; writeFileSync('built.txt', 'ok');" }), () => githubSource(record, dir));
    assert.equal(readFileSync(join(dir, "built.txt"), "utf8"), "ok");
    assert.equal(existsSync(join(dir, "postinstall-ran")), false, "install scripts must not run");
  });
  it("refuses a repo without a lockfile (a frozen install is impossible) and names a missing pnpm", async () => {
    const dir = join(root, "gh-nolock");
    mkdirSync(dir);
    await withFetch(archive({ "package.json": pkg }), async () => {
      await assert.rejects(githubSource(record, dir), /no pnpm-lock\.yaml/);
    });
    const dir2 = join(root, "gh-nopnpm");
    mkdirSync(dir2);
    const path = process.env.PATH;
    process.env.PATH = join(root, "empty-bin");
    try {
      await withFetch(archive({ "package.json": pkg, "pnpm-lock.yaml": lock }), async () => {
        await assert.rejects(githubSource(record, dir2), /pnpm is not installed or not on PATH/);
      });
    } finally {
      process.env.PATH = path;
    }
  });
});

describe("loader", () => {
  const src = join(root, "peer-src");
  writePeer(src);
  const manifestOf = () => JSON.parse(readFileSync(join(src, "tealbrick.manifest.json"), "utf8")) as { version: string };
  const spec = { product: PEER, version: "1.0.0", channel: "stable" as const };
  it("fetches once, then reuses the cache of product@version@commit; a half-written directory is rebuilt", async () => {
    let fetched = 0;
    const opts = { index: async () => [rec()], source: async (_r: ReleaseRecord, d: string) => { fetched++; cpSync(src, d, { recursive: true }); }, cacheRoot: join(root, "cache-a"), log: () => undefined };
    const a = await loadPeer(spec, opts);
    assert.equal(a.dir, join(root, "cache-a", `${PEER}@1.0.0@${COMMIT}`));
    assert.equal(a.manifest.id, PEER);
    assert.equal(a.startModule, join(a.dir, "conformance.start.ts"));
    await loadPeer(spec, opts);
    assert.equal(fetched, 1);
    rmSync(join(a.dir, ".tbconf-ready"));
    await loadPeer(spec, opts);
    assert.equal(fetched, 2);
  });
  it("refuses a manifest that is not the released one: other product, other version, other digest", async () => {
    const mk = (mutate: (dir: string) => void, record = rec()) => ({ index: async () => [record], source: async (_r: ReleaseRecord, d: string) => { cpSync(src, d, { recursive: true }); mutate(d); }, cacheRoot: join(root, `cache-${Math.random()}`), log: () => undefined });
    const edit = (d: string, f: (m: Record<string, unknown>) => void) => {
      const p = join(d, "tealbrick.manifest.json");
      const m = JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>;
      f(m);
      writeFileSync(p, JSON.stringify(m));
    };
    await assert.rejects(loadPeer(spec, mk((d) => edit(d, (m) => { m.id = "other-app"; }))), /manifest is for other-app/);
    await assert.rejects(loadPeer(spec, mk((d) => edit(d, (m) => { m.version = "2.0.0"; }))), /manifest is version 2\.0\.0, not the released 1\.0\.0/);
    const digest = manifestDigest(JSON.parse(readFileSync(join(src, "tealbrick.manifest.json"), "utf8")));
    await loadPeer(spec, mk(() => undefined, rec({ manifestDigest: digest })));
    await assert.rejects(loadPeer(spec, mk(() => undefined, rec({ manifestDigest: `sha256:${"0".repeat(64)}` }))), /differs from the signed record/);
    await assert.rejects(loadPeer(spec, mk((d) => rmSync(join(d, "tealbrick.manifest.json")))), /no manifest at tealbrick\.manifest\.json/);
    await assert.rejects(loadPeer(spec, mk((d) => rmSync(join(d, "conformance.start.ts")))), /no conformance\.start\.ts/);
    assert.equal(manifestOf().version, "1.0.0");
  });
  it("a failed source step leaves no cache directory behind", async () => {
    const cacheRoot = join(root, "cache-fail");
    await assert.rejects(loadPeer(spec, { index: async () => [rec()], source: async () => { throw new PeerError("boom"); }, cacheRoot, log: () => undefined }), /boom/);
    assert.equal(existsSync(join(cacheRoot, `${PEER}@1.0.0@${COMMIT}`)), false);
  });
});

describe("CLI --peers", () => {
  const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const manifest = fileURLToPath(new URL("./fixtures/sample.manifest.json", import.meta.url));
  const run = (args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 60_000 });
  it("--peers needs peers in tealbrick-conformance.json (usage error 2); --peers with --no-peers and non-app targets are refused", () => {
    const a = run(["app", "--manifest", manifest, "--cmd", "true", "--peers"]);
    assert.equal(a.status, 2, a.stdout + a.stderr);
    assert.match(a.stderr, /--peers needs "peers" in tealbrick-conformance\.json/);
    assert.equal(run(["app", "--manifest", manifest, "--cmd", "true", "--peers", "--no-peers"]).status, 2);
    assert.equal(run(["manifest", manifest, "--peers"]).status, 2);
    assert.match(run(["--help"]).stderr, /--peers: also boot the REAL peer apps/);
  });
});
