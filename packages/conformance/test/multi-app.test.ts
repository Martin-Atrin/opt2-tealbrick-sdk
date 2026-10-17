// CONF-MULTIAPP (conformance 0.1.20): group X against two tiny REAL SDK apps (workspace source) built inside the test, no
// network (the loader's index and source are injected): quiet on good, fires on a peer that ignores the grant, on a peer
// that finds the caller's product by NAME, on a peer whose output violates the pinned contract, and reports a peer that
// cannot start.
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { forkStart, isCheckId, type PeerSourceOptions, parseConformanceConfig, type Report, runApp } from "../src/index.ts";
import { FEED, PEER, validFeed, writeCaller, writePeer } from "./apps/peer-fixtures.ts";

const root = mkdtempSync(join(tmpdir(), "tbconf-multi-test-"));
after(() => rmSync(root, { recursive: true, force: true }));
let n = 0;

const COMMIT = "a".repeat(40);
/** The loader's injectable index and source: one record for conf-peer@1.0.0, the checkout is a copy of a local fixture directory. */
function localSource(peerDir: string, records: unknown[] = [{ kind: "app", product: PEER, version: "1.0.0", channel: "stable", repo: `Tealbrick/opt2-tealbrick-${PEER}`, commit: COMMIT, manifestDigest: null }]): PeerSourceOptions {
  return {
    index: async () => records,
    source: async (_rec, dir) => cpSync(peerDir, dir, { recursive: true }),
    cacheRoot: join(root, `cache-${n}`),
    log: () => undefined,
  };
}

async function runX(peerDir: string, opts: { config?: Record<string, unknown>; calls?: boolean; source?: PeerSourceOptions } = {}): Promise<Report> {
  n++;
  const caller = writeCaller(join(root, `caller-${n}`), opts.calls === undefined ? {} : { calls: opts.calls });
  const config = parseConformanceConfig({ peers: [{ product: PEER, version: "1.0.0" }], contractOps: { [FEED]: `${PEER}.peer_feed` }, ...(opts.config ?? {}) }, "test");
  return runApp({
    manifest: caller.manifest,
    start: forkStart(caller.startModule, { output: () => undefined }),
    config,
    peers: { source: opts.source ?? localSource(peerDir), cleanup: true },
    timeoutMs: 8000,
  });
}
const rows = (r: Report) => r.checks.filter((c) => /^X\d/.test(c.id));
const byId = (r: Report, id: string) => r.checks.find((c) => c.id === id);
const shown = (r: Report) => rows(r).map((c) => `${c.status} ${c.id}: ${c.asserted}`).join("\n");

describe("group X: real peer apps behind the fake bridge", () => {
  it("two real SDK apps: every X row passes (quiet on good)", async () => {
    const r = await runX(writePeer(join(root, "peer-good")));
    const ids = rows(r).map((c) => c.id).sort();
    assert.deepEqual(
      ids,
      [
        `X1.peer_boot.${PEER}`,
        ...["peer_feed", "peer_get", "peer_send"].flatMap((op) => [`X2.companion_call.${PEER}.${op}`, `X3.companion_refused.${PEER}.${op}`]),
        `X4.contract_schema.${PEER}.peer_feed`,
        `X5.hold_round_trip.${PEER}.peer_send`,
      ].sort(),
      shown(r),
    );
    for (const c of rows(r)) {
      assert.equal(c.status, "pass", shown(r));
      assert.ok(isCheckId(c.id), `${c.id} not catalogued`);
    }
    // the peer's receipt names the verified caller app: type, instance, product (never the decoy)
    assert.match(byId(r, `X2.companion_call.${PEER}.peer_get`)?.asserted ?? "", /"type":"app".*"product":"conf-caller"/);
    assert.match(byId(r, `X2.companion_call.${PEER}.peer_send`)?.asserted ?? "", /answered 202 held/);
    assert.ok(r.notes.some((x) => x.includes(`peer ${PEER}@1.0.0 (stable)`) && x.includes(COMMIT)), r.notes.join("\n"));
  });

  it("fires on a peer that ignores the grant (X3), quiet on its boot (X1)", async () => {
    const r = await runX(writePeer(join(root, "peer-nogrant"), { miniFaults: { skipGrantVerify: true } }));
    assert.equal(byId(r, `X1.peer_boot.${PEER}`)?.status, "pass", shown(r));
    const x3 = byId(r, `X3.companion_refused.${PEER}.peer_get`);
    assert.equal(x3?.status, "fail", shown(r));
    assert.match(x3?.asserted ?? "", /grant for another instance → 200/);
  });

  it("fires on a peer that finds the caller's product by NAME (X2: the decoy of the same name)", async () => {
    const r = await runX(writePeer(join(root, "peer-byname"), { miniFaults: { callerProductFromName: true } }));
    const x2 = byId(r, `X2.companion_call.${PEER}.peer_get`);
    assert.equal(x2?.status, "fail", shown(r));
    assert.match(x2?.asserted ?? "", /from its NAME/);
  });

  it("X4 fires when the peer's real output violates the pinned contract schema", async () => {
    const r = await runX(writePeer(join(root, "peer-badfeed"), { feed: { v: 1, revision: "not a number" } }));
    const x4 = byId(r, `X4.contract_schema.${PEER}.peer_feed`);
    assert.equal(x4?.status, "fail", shown(r));
    assert.match(x4?.asserted ?? "", /violates fleet\.directory_feed\/1/);
    // the rows that do not depend on the contract still pass
    assert.equal(byId(r, `X2.companion_call.${PEER}.peer_get`)?.status, "pass");
    void validFeed;
  });

  it("X4 is not_run when both manifests pair on a contract but contractOps does not name the op", async () => {
    const r = await runX(join(root, "peer-good"), { config: { contractOps: {} } });
    const x4 = byId(r, `X4.contract_schema.${PEER}.unmapped`);
    assert.equal(x4?.status, "not_run", shown(r));
    assert.match(x4?.asserted ?? "", /contractOps/);
  });

  it("a peer that cannot start is an X1 failure with the reason; its ops report the peer is not running", async () => {
    const r = await runX(writePeer(join(root, "peer-throws"), { throws: true }));
    const x1 = byId(r, `X1.peer_boot.${PEER}`);
    assert.equal(x1?.status, "fail", shown(r));
    assert.match(x1?.asserted ?? "", /fixture peer refuses to start/);
    assert.equal(byId(r, `X2.companion_call.${PEER}.peer_get`)?.status, "fail");
    assert.equal(r.ok, false);
  });

  it("a peer that is not in the signed index is an X1 failure naming what the index has", async () => {
    const r = await runX(join(root, "peer-good"), { source: localSource(join(root, "peer-good"), [{ kind: "app", product: PEER, version: "0.9.0", channel: "stable", repo: `Tealbrick/opt2-tealbrick-${PEER}`, commit: COMMIT }]) });
    const x1 = byId(r, `X1.peer_boot.${PEER}`);
    assert.equal(x1?.status, "fail", shown(r));
    assert.match(x1?.asserted ?? "", /not in the signed release index; released on stable: 0\.9\.0/);
  });

  it("X2 is not_run when no operation of the app under test makes the call (no silent pass)", async () => {
    const r = await runX(join(root, "peer-good"), { calls: false });
    const x2 = byId(r, `X2.companion_call.${PEER}.peer_get`);
    assert.equal(x2?.status, "not_run", shown(r));
    assert.match(x2?.asserted ?? "", /no operation of conf-caller made this call/);
    // the suite-driven rows still ran against the real peer
    assert.equal(byId(r, `X3.companion_refused.${PEER}.peer_get`)?.status, "pass", shown(r));
  });
});
