// TrustState slice installation under the key-set statement rule (CREDENTIALS §9.5, SDK-API §9 v0.1.11) and its
// transition rule: legacy path (no portalKeySet) with one warning, pin on first statement, no downgrade after a pin.
import assert from "node:assert/strict";
import { test } from "node:test";
import { type Ed25519KeyPair, generateKeyPair, keySetFrom, signGrant, signKeySetStatement, signSlice, ulid, verifyGrant } from "@opt2-tealbrick/manifest";
import type { BridgeId, InstanceId, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import { openStore } from "../src/server/store.ts";
import { KEYSET_REQUIRED, PORTAL_ROOT_CHANNEL, TrustState } from "../src/server/trust.ts";
import { nowS, tempDir } from "./helpers.ts";

type Status = "pending" | "active" | "retired";
const ins = `ins_${ulid()}` as InstanceId;
const ws = `ws_${ulid()}` as WorkspaceId;
const brg = `brg_${ulid()}` as BridgeId;

async function setup(opts: { roots?: Ed25519KeyPair[]; bootstrap?: Ed25519KeyPair; required?: boolean } = {}) {
  const t = tempDir();
  const db = openStore(t.dir);
  const warnings: string[] = [];
  const mk = () =>
    new TrustState(db, ins, {
      bootstrap: opts.bootstrap ? keySetFrom({ keys: [opts.bootstrap.publicJwk] }, "tb:portal") : null,
      ...(opts.roots ? { roots: opts.roots.map((r) => r.publicJwk) } : {}),
      warn: (msg) => warnings.push(msg),
      ...(opts.required !== undefined ? { required: opts.required } : {}),
    });
  const trust = mk();
  trust.setBridge(brg);
  return { trust, warnings, reopen: mk, cleanup: () => {
      db.close();
      t.cleanup();
    },
  };
}

const bridgeKey = await generateKeyPair();
async function slice(rev: number, key: Ed25519KeyPair, extra: { portalKeySet?: string; portalKeys?: { jwk: Ed25519KeyPair["publicJwk"]; status: Status }[] } = {}): Promise<string> {
  return signSlice(
    {
      v: 1,
      iss: "tb:portal",
      sub: `tb:ins:${ins}`,
      aud: `tb:ins:${ins}`,
      iat: nowS(),
      ws,
      rev,
      ins,
      product: "generic",
      portalKeys: extra.portalKeys ?? [{ jwk: key.publicJwk, status: "active" }],
      bridge: { id: brg, keys: [bridgeKey.publicJwk] },
      pause: { workspace: false, agents: [], instances: [] },
      revoked: { jtis: [] },
      personNbf: 0,
      grants: [],
      agents: [],
      ...(extra.portalKeySet ? { portalKeySet: extra.portalKeySet } : {}),
    } as never,
    key,
  );
}
const kss = (root: Ed25519KeyPair, seq: number, keys: [Ed25519KeyPair, Status][]) =>
  signKeySetStatement({ iss: "tb:portal-root", aud: "tb:portal-keys", seq, iat: nowS(), keys: keys.map(([k, status]) => ({ jwk: k.publicJwk, status })) }, root);
const code = (r: { ok: boolean; code?: string }) => (r.ok ? "ok" : r.code);

test("build pins the dev root channel (cutover release switches to prod)", () => {
  assert.equal(PORTAL_ROOT_CHANNEL, "dev");
});

test("slice with portalKeySet: verified against the statement, pinned (persisted), keys replace the bootstrap set", async () => {
  const [root, a, boot] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair()]);
  const s = await setup({ roots: [root], bootstrap: boot });
  try {
    const k1 = await kss(root, 1, [[a, "active"]]);
    assert.equal(code(s.trust.install(await slice(1, a, { portalKeySet: k1 }), Date.now())), "ok", "signer from the KSS, not from the bootstrap set");
    assert.equal(s.trust.keySetSeq, 1);
    assert.deepEqual(s.warnings, []);
    // persisted with the slice: a restarted TrustState keeps the pin and refuses a slice without a statement
    const again = s.reopen();
    again.setBridge(brg);
    assert.equal(again.keySetSeq, 1);
    assert.equal(code(again.install(await slice(2, a), Date.now())), "keyset_missing");
    // the bootstrap key (TB_PORTAL_KEYS) is no longer trusted for grants
    const ctx = again.context(Date.now());
    assert.ok(ctx);
    assert.equal(ctx.issuers.keys.length, 1);
  } finally {
    s.cleanup();
  }
});

test("negatives: unknown root, lower seq, slice signed by a key outside the statement, retired signer", async () => {
  const [root, other, a, b] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair(), generateKeyPair()]);
  const s = await setup({ roots: [root] });
  try {
    assert.equal(code(s.trust.install(await slice(1, a, { portalKeySet: await kss(other, 1, [[a, "active"]]) }), Date.now())), "keyset_invalid");
    const k2 = await kss(root, 2, [[a, "active"], [b, "pending"]]);
    assert.equal(code(s.trust.install(await slice(1, b, { portalKeySet: await kss(root, 1, [[a, "active"]]) }), Date.now())), "invalid_token", "b is not in seq 1");
    assert.equal(code(s.trust.install(await slice(1, a, { portalKeySet: k2 }), Date.now())), "ok");
    assert.equal(code(s.trust.install(await slice(2, a, { portalKeySet: await kss(root, 1, [[a, "active"]]) }), Date.now())), "keyset_rollback");
    const k3 = await kss(root, 3, [[a, "retired"], [b, "active"]]);
    assert.equal(code(s.trust.install(await slice(2, a, { portalKeySet: k3 }), Date.now())), "invalid_token", "a retired key no longer signs slices");
    assert.equal(code(s.trust.install(await slice(2, b, { portalKeySet: k3 }), Date.now())), "ok");
    assert.equal(s.trust.keySetSeq, 3);
  } finally {
    s.cleanup();
  }
});

test("compromise rotation: the dropped kid's slices and grants are refused at once", async () => {
  const [root, stolen, fresh] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair()]);
  const s = await setup({ roots: [root] });
  try {
    assert.equal(code(s.trust.install(await slice(1, stolen, { portalKeySet: await kss(root, 1, [[stolen, "active"]]) }), Date.now())), "ok");
    const k2 = await kss(root, 2, [[fresh, "active"]]);
    assert.equal(code(s.trust.install(await slice(2, stolen, { portalKeySet: k2 }), Date.now())), "invalid_token");
    assert.equal(code(s.trust.install(await slice(2, fresh, { portalKeySet: k2 }), Date.now())), "ok");
    const ctx = s.trust.context(Date.now());
    assert.ok(ctx);
    const claims = {
      iss: "tb:portal" as const,
      sub: `tb:agt:agt_${ulid()}` as const,
      aud: `tb:ins:${ins}` as const,
      ws,
      cnf: { brg },
      crud: ["read" as const],
      mode: "free" as const,
      held: [],
      caps: {},
      wf: [],
      polrev: 1,
      iat: nowS(),
    };
    assert.equal(code(verifyGrant(await signGrant(claims, stolen), ctx)), "grant_invalid");
    assert.equal(code(verifyGrant(await signGrant(claims, fresh), ctx)), "ok");
    // a statement signed with the stolen K12 cannot re-anchor
    assert.equal(code(s.trust.install(await slice(3, stolen, { portalKeySet: await kss(stolen, 3, [[stolen, "active"]]) }), Date.now())), "keyset_invalid");
  } finally {
    s.cleanup();
  }
});

test("transition: no portalKeySet and nothing pinned → pre-v0.1.11 rule with ONE warning; later statement pins", async () => {
  const [root, a, evil] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair()]);
  const s = await setup({ roots: [root], bootstrap: a });
  try {
    assert.equal(code(s.trust.install(await slice(1, a), Date.now())), "ok");
    assert.equal(code(s.trust.install(await slice(2, a), Date.now())), "ok");
    assert.deepEqual(s.warnings, ["slice_keyset_transition"]);
    assert.equal(s.trust.keySetSeq, null);
    assert.equal(code(s.trust.install(await slice(3, evil), Date.now())), "invalid_token", "legacy path still needs a trusted signer");
    assert.equal(code(s.trust.install(await slice(3, a, { portalKeySet: await kss(root, 1, [[a, "active"]]) }), Date.now())), "ok");
    assert.equal(s.trust.keySetSeq, 1);
    assert.equal(code(s.trust.install(await slice(4, a), Date.now())), "keyset_missing", "no downgrade after the pin");
  } finally {
    s.cleanup();
  }
});

test("transition: a build without pinned roots ignores portalKeySet (legacy path)", async () => {
  const a = await generateKeyPair();
  const s = await setup({ roots: [], bootstrap: a });
  try {
    const someRoot = await generateKeyPair();
    assert.equal(code(s.trust.install(await slice(1, a, { portalKeySet: await kss(someRoot, 1, [[a, "active"]]) }), Date.now())), "ok");
    assert.equal(s.trust.keySetSeq, null);
    assert.deepEqual(s.warnings, ["slice_keyset_transition"]);
  } finally {
    s.cleanup();
  }
});

test("spec 0.1.12 (KEYSET_REQUIRED): a first slice without a statement is refused; 0.1.11 builds keep the fallback", async () => {
  assert.equal(KEYSET_REQUIRED, false, "0.1.11 transition build");
  const [root, a] = await Promise.all([generateKeyPair(), generateKeyPair()]);
  const s = await setup({ roots: [root], bootstrap: a, required: true });
  try {
    assert.equal(code(s.trust.install(await slice(1, a), Date.now())), "keyset_missing");
    assert.equal(code(s.trust.install(await slice(1, a, { portalKeySet: await kss(root, 1, [[a, "active"]]) }), Date.now())), "ok");
  } finally {
    s.cleanup();
  }
});
