// random.ts, keys.ts, jws.ts (V0 + assertions), seal.ts.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { type AgentId, type ConnectionId, type InstanceId, LEEWAY_S, type PersonId, TYP } from "@opt2-tealbrick/spec/credentials";
import { sha256Bytes } from "../src/jcs.ts";
import { memoryReplayGuard, signAssertion, signInstanceAssertion, signJws, verifyAssertion, verifyJws } from "../src/jws.ts";
import { exportPrivateKey, generateKeyPair, importKeyPair, keySetAnnounce, keySetFrom, keySetFromPortalKeys, thumbprint } from "../src/keys.ts";
import { digestEqual, opaqueDigest, opaqueValue, ULID_RE, ulid } from "../src/random.ts";
import { kekFromEnv, needsReseal, seal, sealAad, unseal } from "../src/seal.ts";
import { NOW, rawSign, world } from "./fixtures.ts";

// ── random ──
test("ulid: 26-char Crockford, time prefix, monotonic within one millisecond", () => {
  const ids = Array.from({ length: 500 }, () => ulid(1_700_000_000_000));
  for (const id of ids) assert.match(id, ULID_RE);
  assert.deepEqual([...ids].sort(), ids);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ulid(1_700_000_000_001) > ids[ids.length - 1]);
  const last = ulid(1_700_000_000_001);
  assert.ok(ulid(1_600_000_000_000) > last, "clock moved back: still monotonic");
  assert.throws(() => ulid(-1));
});

test("opaqueValue / opaqueDigest / digestEqual", () => {
  const v = opaqueValue("tbr_");
  assert.match(v, /^tbr_[A-Za-z0-9_-]{43}$/);
  assert.notEqual(opaqueValue("tbr_"), v);
  const d = opaqueDigest(v);
  assert.equal(d, sha256Bytes(new TextEncoder().encode(v)));
  assert.ok(digestEqual(d, opaqueDigest(v)));
  assert.ok(!digestEqual(d, opaqueDigest(`${v}x`)));
  assert.ok(!digestEqual(d, d.slice(0, -1)));
});

// ── keys ──
test("thumbprint: RFC 8037 A.3 vector", () => {
  assert.equal(thumbprint({ kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  assert.throws(() => thumbprint({ kty: "OKP", crv: "X25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" } as never));
});

test("generateKeyPair: non-extractable by default; export/import round trip when extractable", async () => {
  const k = await generateKeyPair();
  assert.equal(k.kid, thumbprint(k.publicJwk));
  assert.deepEqual(Object.keys(k.publicJwk).sort(), ["crv", "kty", "x"]);
  assert.equal(k.privateKey.extractable, false);
  await assert.rejects(exportPrivateKey(k), /not extractable/);

  const e = await generateKeyPair({ extractable: true });
  const pkcs8 = await exportPrivateKey(e);
  const back = await importKeyPair(pkcs8);
  assert.equal(back.kid, e.kid);
  assert.equal(back.privateKey.extractable, false);
  const keys = keySetFrom({ keys: [e.publicJwk] }, "tb:portal");
  const t = await signJws(TYP.pairingCode, { iss: "tb:portal", sub: `tb:agt:agt_${ulid()}`, aud: `tb:brg:brg_${ulid()}`, ws: `ws_${ulid()}`, iat: NOW, exp: NOW + 60, jti: ulid() }, back);
  assert.equal(verifyJws(t, keys, { typ: TYP.pairingCode, aud: (JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()) as { aud: string }).aud, iss: ["tb:portal"], now: NOW, maxLifetimeS: 600 }).ok, true);
  await assert.rejects(importKeyPair(new Uint8Array([1, 2, 3])));
});

test("keySetFrom rejects non-Ed25519 / private JWKs", async () => {
  const k = await generateKeyPair();
  assert.throws(() => keySetFrom({ keys: [{ ...k.publicJwk, d: "secret" } as never] }, "tb:portal"));
  assert.throws(() => keySetFrom({ keys: [{ kty: "EC", crv: "P-256", x: k.publicJwk.x } as never] }, "tb:portal"));
  assert.equal(keySetFrom({ keys: [k.publicJwk] }, "tb:portal").keys[0].status, "active");
});

test("keySetAnnounce: only a trusted signer's document replaces the set (adds, retires, removes)", async () => {
  const a = await generateKeyPair();
  const b = await generateKeyPair();
  const evil = await generateKeyPair();
  const trusted = keySetFrom({ keys: [a.publicJwk] }, "tb:portal");
  // T0: A-signed document announces B pending
  const t0 = keySetAnnounce(trusted, keySetFromPortalKeys([{ jwk: a.publicJwk, status: "active" }, { jwk: b.publicJwk, status: "pending" }]), { kid: a.kid });
  assert.deepEqual(t0.keys.map((k) => [k.jwk.x, k.status]), [[a.publicJwk.x, "active"], [b.publicJwk.x, "pending"]]);
  // T0+24h: B (pending at the verifier) signs the document that makes it active and retires A
  const t1 = keySetAnnounce(t0, keySetFromPortalKeys([{ jwk: a.publicJwk, status: "retired" }, { jwk: b.publicJwk, status: "active" }]), { kid: b.kid });
  assert.equal(t1.keys.find((k) => k.jwk.x === a.publicJwk.x)?.status, "retired");
  // A removed later
  const t2 = keySetAnnounce(t1, keySetFromPortalKeys([{ jwk: b.publicJwk, status: "active" }]), { kid: b.kid });
  assert.equal(t2.keys.length, 1);
  // a document signed by an unknown key changes nothing
  const t3 = keySetAnnounce(t2, keySetFromPortalKeys([{ jwk: evil.publicJwk, status: "active" }]), { kid: evil.kid });
  assert.equal(t3, t2);
  // retired-and-removed A cannot re-announce
  assert.equal(keySetAnnounce(t2, keySetFrom({ keys: [a.publicJwk] }, "tb:portal"), { kid: a.kid }), t2);
});

// ── JWS V0 ──
test("verifyJws: positive and every V0 refusal", async () => {
  const w = await world();
  const keys = w.trust.issuers;
  const base = { iss: "tb:portal", sub: `tb:agt:${w.agt}`, aud: `tb:brg:${w.brg}`, ws: w.ws, iat: NOW, exp: NOW + 600, jti: ulid() };
  const expect = { typ: TYP.pairingCode, aud: `tb:brg:${w.brg}`, iss: ["tb:portal"], now: NOW, maxLifetimeS: 600 } as const;
  const good = await signJws(TYP.pairingCode, base, w.portal);
  const ok = verifyJws<typeof base>(good, keys, expect);
  assert.ok(ok.ok);
  assert.equal(ok.ok && ok.claims.jti, base.jti);
  assert.equal(ok.ok && ok.header.kid, w.portal.kid);

  const hdr = { alg: "EdDSA", typ: TYP.pairingCode, kid: w.portal.kid };
  const cases: [string, string][] = [
    ["wrong typ", await signJws(TYP.agentSession, { iss: `tb:brg:${w.brg}`, sub: `tb:agt:${w.agt}`, aud: `tb:brg:${w.brg}`, ws: w.ws, con: `con_${ulid()}`, gen: 1, iat: NOW, exp: NOW + 60, jti: ulid() }, w.portal)],
    ["alg none", await rawSign({ ...hdr, alg: "none" }, base, w.portal)],
    ["extra header jku", await rawSign({ ...hdr, jku: "https://x" }, base, w.portal)],
    ["extra header member", await rawSign({ ...hdr, cty: "x" }, base, w.portal)],
    ["unannounced kid", await signJws(TYP.pairingCode, base, w.stranger)],
    ["kid swapped", await rawSign({ ...hdr }, base, w.stranger)],
    ["aud array", await rawSign(hdr, { ...base, aud: [`tb:brg:${w.brg}`] }, w.portal)],
    ["aud missing", await rawSign(hdr, { ...base, aud: undefined }, w.portal)],
    ["foreign aud", await signJws(TYP.pairingCode, { ...base, aud: `tb:brg:brg_${ulid()}` }, w.portal)],
    ["unknown claim nbf", await rawSign(hdr, { ...base, nbf: NOW }, w.portal)],
    ["jti not a ulid", await rawSign(hdr, { ...base, jti: "abc" }, w.portal)],
    ["expired", await signJws(TYP.pairingCode, { ...base, iat: NOW - 700, exp: NOW - LEEWAY_S }, w.portal)],
    ["iat in future", await signJws(TYP.pairingCode, { ...base, iat: NOW + LEEWAY_S + 1, exp: NOW + 600 }, w.portal)],
    ["lifetime too long", await rawSign(hdr, { ...base, exp: NOW + 601 }, w.portal)],
    ["tampered signature", `${good.slice(0, -4)}AAAA`],
    ["two parts", good.split(".").slice(0, 2).join(".")],
    ["oversize", `${good}${"A".repeat(9000)}`],
    ["clerk-like person JWT", `${Buffer.from('{"alg":"RS256","typ":"JWT","kid":"ins_1"}').toString("base64url")}.${Buffer.from('{"sub":"user_1","azp":"https://portal"}').toString("base64url")}.c2ln`],
    ["owner CLI opaque", opaqueValue("tbo_")],
  ];
  for (const [name, token] of cases) {
    const r = verifyJws(token, keys, expect);
    assert.equal(r.ok, false, name);
    assert.equal(!r.ok && r.code, "invalid_token", name);
  }
  // within leeway still accepted
  const edge = await signJws(TYP.pairingCode, { ...base, iat: NOW - 600, exp: NOW - LEEWAY_S + 1 }, w.portal);
  assert.ok(verifyJws(edge, keys, expect).ok);
  // iss not allowed by the endpoint
  assert.equal(verifyJws(good, keys, { ...expect, iss: [`tb:brg:${w.brg}`] }).ok, false);
  // key trusted for another issuer cannot sign as Portal
  assert.equal(verifyJws(good, keySetFrom({ keys: [w.portal.publicJwk] }, `tb:brg:${w.brg}`), expect).ok, false);
});

test("signJws refuses claim sets outside the closed set", async () => {
  const w = await world();
  await assert.rejects(signJws(TYP.pairingCode, { iss: "tb:portal", sub: `tb:agt:${w.agt}`, aud: [`tb:brg:${w.brg}`], ws: w.ws, iat: NOW, exp: NOW + 60, jti: ulid() }, w.portal));
  await assert.rejects(signJws(TYP.pairingCode, { iss: "tb:portal", sub: `tb:agt:${w.agt}`, aud: `tb:brg:${w.brg}`, ws: w.ws, extra: 1, iat: NOW, exp: NOW + 60, jti: ulid() }, w.portal));
  await assert.rejects(signJws("JWT" as never, {}, w.portal));
});

// ── assertions ──
test("instance assertion: htm/htu/bd binding, replay, wrong signer", async () => {
  const w = await world();
  const keys = keySetFrom({ keys: [w.insKey.publicJwk] }, `tb:ins:${w.ins}`);
  const body = new TextEncoder().encode('{"x":1}');
  const t = await signInstanceAssertion({ key: w.insKey, ins: w.ins, svc: "db", bridge: w.brg, method: "post", pathAndQuery: "/tb/v1/status?a=1", body, now: NOW });
  const expect = { typ: TYP.instanceAssertion, aud: `tb:brg:${w.brg}`, now: NOW, method: "POST", pathAndQuery: "/tb/v1/status?a=1", body } as const;
  const ok = verifyAssertion(t, keys, expect);
  assert.ok(ok.ok);
  assert.equal(ok.ok && ok.claims.svc, "db");
  assert.equal(ok.ok && ok.claims.bd, sha256Bytes(body));
  const no = (r: { ok: boolean }) => assert.equal(r.ok, false);
  no(verifyAssertion(t, keys, { ...expect, method: "GET" }));
  no(verifyAssertion(t, keys, { ...expect, pathAndQuery: "/tb/v1/status" }));
  no(verifyAssertion(t, keys, { ...expect, body: new TextEncoder().encode('{"x":2}') }));
  no(verifyAssertion(t, keys, { ...expect, body: undefined }));
  no(verifyAssertion(t, keys, { ...expect, method: undefined }));
  no(verifyAssertion(t, keys, { ...expect, aud: `tb:brg:brg_${ulid()}` }));
  no(verifyAssertion(t, keys, { ...expect, typ: TYP.bridgeAssertion }));
  no(verifyAssertion(t, keys, { ...expect, now: NOW + 61 + LEEWAY_S }));
  no(verifyAssertion(t, keySetFrom({ keys: [w.stranger.publicJwk] }, `tb:ins:${w.ins}`), expect));
  // body-less request: bd absent, any bd present refused
  const g = await signInstanceAssertion({ key: w.insKey, ins: w.ins, bridge: w.brg, method: "GET", pathAndQuery: "/tb/v1/keys/a", now: NOW });
  assert.ok(verifyAssertion(g, keys, { ...expect, method: "GET", pathAndQuery: "/tb/v1/keys/a", body: undefined }).ok);
  no(verifyAssertion(g, keys, { ...expect, method: "GET", pathAndQuery: "/tb/v1/keys/a", body: new Uint8Array([1]) }));
  // replay hook
  const replay = memoryReplayGuard();
  assert.ok(verifyAssertion(t, keys, { ...expect, replay }).ok);
  const again = verifyAssertion(t, keys, { ...expect, replay });
  assert.equal(!again.ok && again.reason, "step 10: jti replay");
});

test("agent, owner and pair-state assertions; binding misuse throws", async () => {
  const w = await world();
  const agentKey = await generateKeyPair();
  const con = `con_${ulid()}` as ConnectionId;
  const agtRef = `tb:agt:${w.agt as AgentId}` as const;
  const a = await signAssertion(TYP.agentAssertion, { iss: agtRef, sub: agtRef, aud: `tb:brg:${w.brg}`, con, iat: NOW }, agentKey);
  const agentKeys = keySetFrom({ keys: [agentKey.publicJwk] }, agtRef);
  const va = verifyAssertion(a, agentKeys, { typ: TYP.agentAssertion, aud: `tb:brg:${w.brg}`, now: NOW });
  assert.equal(va.ok && va.claims.con, con);
  // iss != sub refused
  const forged = await rawSign({ alg: "EdDSA", typ: TYP.agentAssertion, kid: agentKey.kid }, { iss: agtRef, sub: `tb:agt:agt_${ulid()}`, aud: `tb:brg:${w.brg}`, con, iat: NOW, exp: NOW + 60, jti: ulid() }, agentKey);
  assert.equal(verifyAssertion(forged, agentKeys, { typ: TYP.agentAssertion, aud: `tb:brg:${w.brg}`, now: NOW }).ok, false);

  const ownerKey = await generateKeyPair();
  const perRef = `tb:per:${w.per as PersonId}` as const;
  const o = await signAssertion(TYP.ownerAssertion, { iss: perRef, sub: perRef, aud: `tb:brg:${w.brg}`, iat: NOW }, ownerKey, { method: "POST", pathAndQuery: "/admin/v1/pause", body: new Uint8Array([123, 125]) });
  const ownerKeys = keySetFrom({ keys: [ownerKey.publicJwk] }, perRef);
  assert.ok(verifyAssertion(o, ownerKeys, { typ: TYP.ownerAssertion, aud: `tb:brg:${w.brg}`, now: NOW, method: "POST", pathAndQuery: "/admin/v1/pause", body: new Uint8Array([123, 125]) }).ok);
  // owner assertion is never an agent assertion (typ confusion)
  assert.equal(verifyAssertion(o, ownerKeys, { typ: TYP.agentAssertion, aud: `tb:brg:${w.brg}`, now: NOW }).ok, false);

  const brgRef = `tb:brg:${w.brg}` as const;
  const ps = await signAssertion(TYP.pairState, { iss: brgRef, sub: brgRef, aud: "tb:portal", rid: "r1", ret: "https://b.example/oauth/pair/callback", rh: "claude.ai", cn: "Client", iat: NOW, exp: NOW + 600 }, w.bridgeKey);
  assert.ok(verifyAssertion(ps, w.trust.bridgeKeys, { typ: TYP.pairState, aud: "tb:portal", now: NOW + 500 }).ok);
  await assert.rejects(signAssertion(TYP.pairState, { iss: brgRef, sub: brgRef, aud: "tb:portal", rid: "r1", ret: "http://b.example/cb", rh: "h", cn: "c", iat: NOW }, w.bridgeKey));

  await assert.rejects(signAssertion(TYP.bridgeAssertion, { iss: brgRef, sub: brgRef, aud: "tb:portal", iat: NOW }, w.bridgeKey), /request binding/);
  await assert.rejects(signAssertion(TYP.agentAssertion, { iss: agtRef, sub: agtRef, aud: brgRef, con, iat: NOW }, agentKey, { method: "GET", pathAndQuery: "/" }));
  await assert.rejects(signAssertion(TYP.grant as never, {} as never, agentKey));
  await assert.rejects(signAssertion(TYP.agentAssertion, { iss: agtRef, sub: agtRef, aud: brgRef, con, iat: NOW, exp: NOW + 61 }, agentKey), /lifetime/);
  assert.equal(verifyAssertion(a, agentKeys, { typ: TYP.grant as never, aud: brgRef, now: NOW }).ok, false);
  void (w.ins as InstanceId);
});

// ── seal ──
test("seal / unseal: round trip, AAD binding, tamper, previous KEK, unknown KEK", () => {
  const cur = { id: "k2", key: new Uint8Array(randomBytes(32)) };
  const prev = { id: "k1", key: new Uint8Array(randomBytes(32)) };
  const aad = sealAad("portal-key", "kid123");
  assert.equal(aad, "tb:seal:portal-key:kid123");
  const pt = new TextEncoder().encode("private key bytes");
  const blob = seal(pt, cur, aad);
  assert.deepEqual(Object.keys(blob).sort(), ["alg", "ct", "iv", "kek", "tag", "v"]);
  assert.equal(blob.v, 1);
  assert.equal(blob.alg, "A256GCM");
  assert.equal(Buffer.from(blob.iv, "base64url").length, 12);
  assert.deepEqual(unseal(blob, { current: cur }, aad), pt);
  assert.notEqual(seal(pt, cur, aad).iv, blob.iv);

  assert.throws(() => unseal(blob, { current: cur }, sealAad("portal-key", "other")), /unseal_failed/);
  const flip = (s: string) => (s[0] === "A" ? "B" : "A") + s.slice(1);
  assert.throws(() => unseal({ ...blob, ct: flip(blob.ct) }, { current: cur }, aad), /unseal_failed/);
  assert.throws(() => unseal({ ...blob, tag: flip(blob.tag) }, { current: cur }, aad), /unseal_failed/);
  assert.throws(() => unseal({ ...blob, iv: "short" }, { current: cur }, aad), /unseal_failed/);
  assert.throws(() => unseal({ ...blob, v: 2 } as never, { current: cur }, aad), /unseal_failed/);

  const old = seal(pt, prev, aad);
  assert.ok(needsReseal(old, cur));
  assert.ok(!needsReseal(blob, cur));
  assert.deepEqual(unseal(old, { current: cur, previous: prev }, aad), pt);
  assert.throws(() => unseal(old, { current: cur }, aad), /unseal_failed/);
  assert.throws(() => unseal(blob, { current: { id: "k2", key: prev.key } }, aad), /unseal_failed/);
  assert.throws(() => seal(pt, { id: "x", key: new Uint8Array(16) }, aad));
  assert.deepEqual(unseal(seal(new Uint8Array(0), cur, aad), { current: cur }, aad), new Uint8Array(0));
});

test("kekFromEnv: base64url or hex 32 bytes only; stable non-secret id", () => {
  const raw = randomBytes(32);
  const a = kekFromEnv(raw.toString("base64url"));
  const b = kekFromEnv(raw.toString("hex"));
  assert.deepEqual(a.key, new Uint8Array(raw));
  assert.deepEqual(b.key, a.key);
  assert.equal(a.id, b.id);
  assert.match(a.id, /^kek_[0-9a-f]{16}$/);
  assert.throws(() => kekFromEnv("x".repeat(40))); // C35: exactly 32 bytes, no hashed fallback
  assert.equal(kekFromEnv(raw.toString("hex"), "core-1").id, "core-1");
  assert.throws(() => kekFromEnv("short"));
});
