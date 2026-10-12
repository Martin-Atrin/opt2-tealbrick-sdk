// keyset.ts: Portal Root Keys, key-set statements (CREDENTIALS §9.5) and BSD-07 app addresses (BRIDGE §5.7).
import assert from "node:assert/strict";
import { test } from "node:test";
import type { WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import type { Ed25519KeyPair, KeySet } from "@opt2-tealbrick/spec/sdk";
import type { Issue } from "../src/jws.ts";
import { generateKeyPair, thumbprint } from "../src/keys.ts";
import {
  isPrivateInternalUrl,
  type KeySetStatementClaims,
  PORTAL_ROOT_KEYS,
  portalRootKeys,
  signKeySetStatement,
  trustedPortalKeys,
  verifyKeySetStatement,
} from "../src/keyset.ts";
import { signConfig, signGrant, verifyConfig, verifyGrant } from "../src/tokens.ts";
import { NOW, payloadOf, rawSign, world } from "./fixtures.ts";

const code = (r: { ok: boolean; code?: string }) => (r.ok ? "ok" : r.code);
type Status = "pending" | "active" | "retired";
const stmt = (seq: number, keys: [Ed25519KeyPair, Status][]): KeySetStatementClaims => ({
  iss: "tb:portal-root",
  aud: "tb:portal-keys",
  seq,
  iat: NOW,
  keys: keys.map(([k, status]) => ({ jwk: k.publicJwk, status })),
});
const kids = (ks: KeySet) => ks.keys.map((k) => thumbprint(k.jwk)).sort();

test("portalRootKeys: dev = the two Platform dev roots (root-a, root-b), prod empty until cutover, returns a copy", () => {
  const dev = portalRootKeys("dev");
  assert.deepEqual(dev.map((k) => k.kid).sort(), ["17Gm_IqxFTy4zBA_VgpcCQYN53_Pfh-gLVidSiyJTKg", "xr8nlOuIDP8GqJOnDvBe6dIc2jwy2T83j2YqlPz6x7A"].sort());
  for (const k of dev) {
    assert.equal(k.kid, thumbprint(k), "kid = RFC 7638 thumbprint");
    assert.deepEqual(Object.keys(k).sort(), ["crv", "kid", "kty", "x"], "public members only");
  }
  assert.deepEqual(portalRootKeys("prod"), []);
  dev[0].x = "tampered";
  assert.notEqual(PORTAL_ROOT_KEYS.dev[0]?.x, "tampered");
  assert.throws(() => portalRootKeys("stable" as never));
});

test("signKeySetStatement: exact tb-keyset+jws format (header, claim order) and refuses malformed claims", async () => {
  const root = await generateKeyPair();
  const a = await generateKeyPair();
  const jws = await signKeySetStatement(stmt(1, [[a, "active"]]), root);
  const [h] = jws.split(".");
  assert.deepEqual(JSON.parse(Buffer.from(h as string, "base64url").toString("utf8")), { alg: "EdDSA", typ: "tb-keyset+jws", kid: root.kid });
  const p = payloadOf(jws);
  assert.deepEqual(Object.keys(p), ["iss", "aud", "seq", "iat", "keys"]);
  assert.deepEqual(p.keys, [{ jwk: a.publicJwk, status: "active" }]);
  await assert.rejects(signKeySetStatement(stmt(0, [[a, "active"]]), root), /seq/);
  await assert.rejects(signKeySetStatement(stmt(1, [[a, "pending"]]), root), /exactly one active/);
  await assert.rejects(signKeySetStatement(stmt(1, [[a, "active"], [a, "retired"]]), root), /duplicate/);
  await assert.rejects(signKeySetStatement({ ...stmt(1, [[a, "active"]]), exp: NOW } as never, root), /claim set/);
  await assert.rejects(signKeySetStatement({ ...stmt(1, [[a, "active"]]), iss: "tb:portal" } as never, root), /iss/);
  // external signer (offline tool holding the key elsewhere) produces a statement that verifies
  const ext = await signKeySetStatement(stmt(2, [[a, "active"]]), {
    kid: root.kid,
    sign: async (input) => Buffer.from(await crypto.subtle.sign({ name: "Ed25519" }, root.privateKey, Buffer.from(input, "ascii"))).toString("base64url"),
  });
  assert.equal(code(verifyKeySetStatement(ext, [root.publicJwk])), "ok");
});

test("verifyKeySetStatement: root-signed, keys + signers, seq ordering, negatives", async () => {
  const [root, backup, other, a, b] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair(), generateKeyPair(), generateKeyPair()]);
  const roots = [root.publicJwk, backup.publicJwk];
  const s1 = await signKeySetStatement(stmt(1, [[a, "active"], [b, "pending"]]), root);
  const v = verifyKeySetStatement(s1, roots);
  assert.ok(v.ok);
  assert.equal(v.ok && v.seq, 1);
  assert.equal(v.ok && v.kss, s1);
  assert.deepEqual(v.ok && kids(v.keys), [a.kid, b.kid].sort());
  assert.deepEqual(v.ok && v.keys.keys.map((k) => k.issuer), ["tb:portal", "tb:portal"]);
  // signed by the backup root: accepted
  assert.equal(code(verifyKeySetStatement(await signKeySetStatement(stmt(2, [[a, "active"]]), backup), roots, { seq: 1, kss: s1 })), "ok");
  // equal seq: byte-identical accepted, any other statement refused
  assert.equal(code(verifyKeySetStatement(s1, roots, { seq: 1, kss: s1 })), "ok");
  assert.equal(code(verifyKeySetStatement(await signKeySetStatement(stmt(1, [[b, "active"]]), root), roots, { seq: 1, kss: s1 })), "keyset_rollback");
  // lower seq refused
  assert.equal(code(verifyKeySetStatement(s1, roots, { seq: 2, kss: "x" })), "keyset_rollback");
  // unknown root
  const foreign = verifyKeySetStatement(await signKeySetStatement(stmt(5, [[a, "active"]]), other), roots);
  assert.equal(code(foreign), "keyset_invalid");
  assert.match(foreign.ok ? "" : foreign.reason, /unknown root/);
  // bad signature: payload swapped under the root's signature
  const [h, , sig] = s1.split(".");
  const evil = Buffer.from(JSON.stringify(stmt(9, [[other, "active"]]))).toString("base64url");
  assert.equal(code(verifyKeySetStatement(`${h}.${evil}.${sig}`, roots)), "keyset_invalid");
  // extra claim / missing claim / wrong typ, signed by a real root
  const hdr = { alg: "EdDSA", typ: "tb-keyset+jws", kid: root.kid };
  assert.equal(code(verifyKeySetStatement(await rawSign(hdr, { ...stmt(3, [[a, "active"]]), exp: NOW + 10 }, root), roots)), "keyset_invalid");
  const { iat: _drop, ...noIat } = stmt(3, [[a, "active"]]);
  assert.equal(code(verifyKeySetStatement(await rawSign(hdr, noIat, root), roots)), "keyset_invalid");
  assert.equal(code(verifyKeySetStatement(await rawSign({ ...hdr, typ: "tb-config+jws" }, stmt(3, [[a, "active"]]), root), roots)), "keyset_invalid");
  // malformed keys: two active, jwk kid ≠ thumbprint, private member, unknown status
  assert.equal(code(verifyKeySetStatement(await rawSign(hdr, stmt(3, [[a, "active"], [b, "active"]]), root), roots)), "keyset_invalid");
  const badKid = { ...stmt(3, [[a, "active"]]), keys: [{ jwk: { ...a.publicJwk, kid: b.kid }, status: "active" }] };
  assert.equal(code(verifyKeySetStatement(await rawSign(hdr, badKid, root), roots)), "keyset_invalid");
  const priv = { ...stmt(3, [[a, "active"]]), keys: [{ jwk: { ...a.publicJwk, d: "x".repeat(43) }, status: "active" }] };
  assert.equal(code(verifyKeySetStatement(await rawSign(hdr, priv, root), roots)), "keyset_invalid");
  const status = { ...stmt(3, [[a, "active"]]), keys: [{ jwk: a.publicJwk, status: "active" }, { jwk: b.publicJwk, status: "revoked" }] };
  assert.equal(code(verifyKeySetStatement(await rawSign(hdr, status, root), roots)), "keyset_invalid");
  // no roots pinned
  assert.equal(code(verifyKeySetStatement(s1, [])), "keyset_invalid");
  assert.equal(code(verifyKeySetStatement("not.a.jws", roots)), "keyset_invalid");
});

test("trustedPortalKeys: KSS rule, no downgrade after a pin, transition (legacy) path", async () => {
  const [root, a, b] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair()]);
  const roots = [root.publicJwk];
  const s1 = await signKeySetStatement(stmt(1, [[a, "active"]]), root);
  const s2 = await signKeySetStatement(stmt(2, [[a, "retired"], [b, "active"]]), root);
  const first = trustedPortalKeys({ portalKeySet: s1 }, null, roots);
  assert.ok(first.ok && !first.legacy && first.changed);
  const same = trustedPortalKeys({ portalKeySet: s1 }, { seq: 1, kss: s1 }, roots);
  assert.ok(same.ok && !same.legacy && !same.changed);
  const next = trustedPortalKeys({ portalKeySet: s2 }, { seq: 1, kss: s1 }, roots);
  assert.ok(next.ok && !next.legacy && next.changed);
  assert.deepEqual(next.ok && !next.legacy && kids(next.signers), [b.kid]);
  assert.equal(code(trustedPortalKeys({ portalKeySet: s1 }, { seq: 2, kss: s2 }, roots)), "keyset_rollback");
  assert.equal(code(trustedPortalKeys({}, { seq: 1, kss: s1 }, roots)), "keyset_missing");
  assert.equal(code(trustedPortalKeys({ portalKeySet: 7 }, null, roots)), "keyset_invalid");
  const legacy = trustedPortalKeys({}, null, roots);
  assert.ok(legacy.ok && legacy.legacy);
  const noRoots = trustedPortalKeys({ portalKeySet: s1 }, null, []);
  assert.ok(noRoots.ok && noRoots.legacy, "a build without pinned roots stays on the transition path");
  assert.equal(code(trustedPortalKeys({ portalKeySet: s2 }, { seq: 1, kss: s1 }, [])), "keyset_invalid", "a pin without roots never passes");
  // spec 0.1.12 (fallback removed): a build with roots refuses a first document without a statement
  assert.equal(code(trustedPortalKeys({}, null, roots, { required: true })), "keyset_missing");
  assert.ok((trustedPortalKeys({}, null, [], { required: true }) as { legacy?: boolean }).legacy, "no roots for the channel: nothing to require");
  assert.equal(code(trustedPortalKeys({ portalKeySet: s1 }, null, roots, { required: true })), "ok");
});

/** Minimal config body signed by `key` (verifyConfig shape). */
async function config(w: Awaited<ReturnType<typeof world>>, key: Ed25519KeyPair, rev: number): Promise<string> {
  const brg = `tb:brg:${w.brg}` as const;
  const body = {
    iss: "tb:portal",
    sub: brg,
    aud: brg,
    ws: w.ws,
    v: 1,
    rev,
    iat: NOW,
    portalKeys: [],
    pause: { workspace: false, agents: [], instances: [] },
    revoked: { jtis: [] },
    connections: [],
    instanceKeys: [],
    grants: [],
    apps: [],
  } as unknown as Issue<WorkspaceConfig>;
  return signConfig(body, key);
}

test("normal rotation (3 statements): pending B announced, B active / A retired, A dropped", async () => {
  const w = await world();
  const [root, b] = await Promise.all([generateKeyPair(), generateKeyPair()]);
  const a = w.portal;
  const roots = [root.publicJwk];
  const brg = `tb:brg:${w.brg}` as const;
  const cfg = (signers: KeySet, jws: string) => code(verifyConfig(jws, { now: NOW, self: brg, issuers: signers }));
  const grantA = await signGrant(w.grantClaims(), a);
  const grantOk = (keys: KeySet) => code(verifyGrant(grantA, { ...w.trust, issuers: keys }));
  let pinned = null as { seq: number; kss: string } | null;
  const step = async (seq: number, keys: [Ed25519KeyPair, Status][]) => {
    const t = trustedPortalKeys({ portalKeySet: await signKeySetStatement(stmt(seq, keys), root) }, pinned, roots);
    assert.ok(t.ok && !t.legacy && t.changed, `seq ${seq} applied`);
    if (!t.ok || t.legacy) throw new Error("unreachable");
    pinned = { seq: t.seq, kss: t.kss };
    return t;
  };
  const t0 = await step(1, [[a, "active"]]);
  assert.equal(cfg(t0.signers, await config(w, a, 1)), "ok");
  const t1 = await step(2, [[a, "active"], [b, "pending"]]);
  assert.equal(cfg(t1.signers, await config(w, a, 2)), "ok");
  assert.equal(cfg(t1.signers, await config(w, b, 2)), "ok", "a pending key may already sign (Core switches after the activating KSS)");
  const t2 = await step(3, [[a, "retired"], [b, "active"]]);
  assert.equal(cfg(t2.signers, await config(w, b, 3)), "ok");
  assert.equal(cfg(t2.signers, await config(w, a, 3)), "invalid_token", "retired key no longer signs configs");
  assert.equal(grantOk(t2.keys), "ok", "tokens signed by the retired key stay verifiable until dropped");
  const t3 = await step(4, [[b, "active"]]);
  assert.equal(grantOk(t3.keys), "grant_invalid", "dropped key refused");
  assert.equal(cfg(t3.signers, await config(w, b, 4)), "ok");
});

test("compromise rotation: one statement drops the stolen kid; its configs and grants are refused at once", async () => {
  const w = await world();
  const [root, fresh] = await Promise.all([generateKeyPair(), generateKeyPair()]);
  const stolen = w.portal;
  const roots = [root.publicJwk];
  const brg = `tb:brg:${w.brg}` as const;
  const s1 = await signKeySetStatement(stmt(1, [[stolen, "active"]]), root);
  const t1 = trustedPortalKeys({ portalKeySet: s1 }, null, roots);
  assert.ok(t1.ok && !t1.legacy);
  const s2 = await signKeySetStatement(stmt(2, [[fresh, "active"]]), root);
  const t2 = trustedPortalKeys({ portalKeySet: s2 }, { seq: 1, kss: s1 }, roots);
  assert.ok(t2.ok && !t2.legacy && t2.changed);
  if (!t2.ok || t2.legacy) return;
  assert.equal(code(verifyConfig(await config(w, stolen, 5), { now: NOW, self: brg, issuers: t2.signers })), "invalid_token");
  assert.equal(code(verifyGrant(await signGrant(w.grantClaims(), stolen), { ...w.trust, issuers: t2.keys })), "grant_invalid");
  assert.equal(code(verifyConfig(await config(w, fresh, 5), { now: NOW, self: brg, issuers: t2.signers })), "ok");
  // the attacker (K12 holder) cannot re-anchor: a statement signed by the stolen K12 is not root-signed
  const forged = await signKeySetStatement(stmt(3, [[stolen, "active"]]), stolen);
  assert.equal(code(trustedPortalKeys({ portalKeySet: forged }, { seq: 2, kss: s2 }, roots)), "keyset_invalid");
  // replaying the old statement is a rollback
  assert.equal(code(trustedPortalKeys({ portalKeySet: s1 }, { seq: 2, kss: s2 }, roots)), "keyset_rollback");
});

test("isPrivateInternalUrl: railway.internal form; own-infra only with ownInfra + allow-list", () => {
  assert.equal(isPrivateInternalUrl("http://notes.railway.internal:8080"), true);
  assert.equal(isPrivateInternalUrl("http://a-b.c.railway.internal:1"), true);
  for (const bad of [
    "https://notes.railway.internal:8080",
    "http://notes.railway.internal",
    "http://notes.railway.internal:0",
    "http://notes.railway.internal:70000",
    "http://notes.railway.internal:8080/x",
    "http://Notes.railway.internal:8080",
    "http://railway.internal:8080",
    "http://notes.railway.internal.evil.com:8080",
    "https://attacker.example",
    "http://10.0.0.5:8080",
  ]) {
    assert.equal(isPrivateInternalUrl(bad), false, bad);
  }
  const allowList = ["http://10.0.0.5:8080", " https://apps.example.org "];
  assert.equal(isPrivateInternalUrl("http://10.0.0.5:8080", { ownInfra: true, allowList }), true);
  assert.equal(isPrivateInternalUrl("https://apps.example.org", { ownInfra: true, allowList }), true);
  assert.equal(isPrivateInternalUrl("https://apps.example.org:443", { ownInfra: true, allowList }), true, "default port normalised");
  assert.equal(isPrivateInternalUrl("http://10.0.0.5:8080", { ownInfra: false, allowList }), false, "allow-list needs ownInfra");
  assert.equal(isPrivateInternalUrl("http://10.0.0.5:8080", { ownInfra: true }), false, "ownInfra needs the allow-list");
  assert.equal(isPrivateInternalUrl("http://10.0.0.6:8080", { ownInfra: true, allowList }), false);
  assert.equal(isPrivateInternalUrl("http://10.0.0.5:8080/path", { ownInfra: true, allowList }), false);
  assert.equal(isPrivateInternalUrl("http://user@10.0.0.5:8080", { ownInfra: true, allowList }), false);
  assert.equal(isPrivateInternalUrl("ftp://10.0.0.5:8080", { ownInfra: true, allowList: ["ftp://10.0.0.5:8080"] }), false);
});
