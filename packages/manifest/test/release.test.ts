import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { test } from "node:test";
import { generateKeyPair, keySetFrom, signJwsWithSigner, signReleaseIndex, verifyJws, verifyReleaseIndex } from "../src/index.ts";

const body = { schema: "opt2.release-index/v2" as const, releases: [{ a: 1 }, { b: 2 }], offers: [{ o: 1 }] };

test("release index: sign + verify, digest and counts bound", async () => {
  const k = await generateKeyPair();
  const keys = keySetFrom({ keys: [k.publicJwk] }, "tb:releases");
  const now = 1_800_000_000;
  const jws = await signReleaseIndex(body, { iat: now }, k);
  const ok = verifyReleaseIndex(jws, body, { now: now + 10, keys });
  assert.equal(ok.ok, true);
  const tampered = verifyReleaseIndex(jws, { ...body, releases: [{ a: 1 }, { b: 3 }] }, { now, keys });
  assert.equal(tampered.ok, false);
  const wrongIssuer = verifyReleaseIndex(jws, body, { now, keys: keySetFrom({ keys: [k.publicJwk] }, "tb:portal") });
  assert.equal(wrongIssuer.ok, false);
  const expired = verifyReleaseIndex(jws, body, { now: now + 15552000 + 100, keys });
  assert.equal(expired.ok, false);
  await assert.rejects(signReleaseIndex(body, { iat: now, exp: now + 15552001 }, k));
});

test("signJwsWithSigner produces a JWS verifiable like signJws; bad signature refused", async () => {
  const k = await generateKeyPair();
  const signer = {
    kid: k.kid,
    sign: async (input: string) =>
      Buffer.from(await webcrypto.subtle.sign({ name: "Ed25519" }, k.privateKey as webcrypto.CryptoKey, Buffer.from(input, "ascii"))).toString("base64url"),
  };
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: `tb:agt:agt_01JAAAAAAAAAAAAAAAAAAAAAAA`, sub: `tb:agt:agt_01JAAAAAAAAAAAAAAAAAAAAAAA`, aud: `tb:brg:brg_01JAAAAAAAAAAAAAAAAAAAAAAA`, iat: now, exp: now + 60, jti: "01JAAAAAAAAAAAAAAAAAAAAAAB", con: "con_01JAAAAAAAAAAAAAAAAAAAAAAA" };
  const jws = await signJwsWithSigner("tb-agent-assert+jwt", claims, signer);
  const keys = keySetFrom({ keys: [k.publicJwk] }, claims.iss as never);
  const r = verifyJws(jws, keys, { typ: "tb-agent-assert+jwt", aud: claims.aud, iss: [claims.iss], now, maxLifetimeS: 60 });
  assert.equal(r.ok, true, JSON.stringify(r));
  await assert.rejects(signJwsWithSigner("tb-agent-assert+jwt", claims, { kid: k.kid, sign: () => "short" }));
  await assert.rejects(signJwsWithSigner("tb-agent-assert+jwt", { ...claims, extra: 1 }, signer));
});
