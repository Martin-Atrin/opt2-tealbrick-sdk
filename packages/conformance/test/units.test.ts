// Small units: sample input generator, tar reader, payload scan, tamper helper, token helpers.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { generateKeyPair } from "@opt2-tealbrick/manifest";
import { Mint, peek, rawSign, readTar, sampleInput, scanPayloads, tamperValue } from "../src/index.ts";
import { writeTarGz } from "./apps/tar-write.ts";

describe("units", () => {
  it("sampleInput fills required properties by type and constraint", () => {
    const v = sampleInput(
      {
        type: "object",
        required: ["s", "n", "e", "b", "a", "o", "mail", "r"],
        properties: {
          s: { type: "string", maxLength: 3 },
          n: { type: "integer", minimum: 5 },
          e: { enum: ["x", "y"] },
          b: { type: "boolean" },
          a: { type: "array", minItems: 2, items: { type: "string" } },
          o: { type: "object", required: ["k"], properties: { k: { type: "string" } } },
          mail: { type: "string", format: "email" },
          r: { $ref: "#/$defs/d" },
          opt: { type: "string" },
        },
        $defs: { d: { const: 7 } },
      },
      "fill-value",
    );
    assert.deepEqual(v, { s: "fil", n: 5, e: "x", b: false, a: ["fill-value", "fill-value"], o: { k: "fill-value" }, mail: "conformance@example.org", r: 7 });
    assert.deepEqual(sampleInput(undefined, "x"), {});
  });

  it("tamperValue changes one value and keeps the shape", () => {
    assert.deepEqual(tamperValue({ b: "x", a: 1 }), { b: "x-tampered", a: 1 });
    assert.deepEqual(tamperValue({ n: 1 }), { n: 2 });
    assert.deepEqual(tamperValue({}), { tb_conformance_tamper: true });
    assert.deepEqual(tamperValue("s"), { tampered: "s" });
  });

  it("readTar reads gzip ustar archives and rejects garbage", () => {
    const tgz = writeTarGz([{ name: "meta.json", data: Buffer.from('{"a":1}') }, { name: "dir/b.txt", data: Buffer.alloc(700, 65) }]);
    const e = readTar(new Uint8Array(tgz));
    assert.deepEqual(e.map((x) => [x.name, x.data.length]), [["meta.json", 7], ["dir/b.txt", 700]]);
    assert.throws(() => readTar(new Uint8Array([0x1f, 0x8b, 1, 2, 3])));
  });

  it("scanPayloads reports labels (never values) for secrets and person tickets", async () => {
    const key = await generateKeyPair();
    const ticket = await rawSign({ alg: "EdDSA", typ: "tb-ticket+jwt", kid: key.kid }, { sub: "tb:per:x", pad: "y".repeat(20) }, key);
    const payloads = [
      { dir: "bridge-in" as const, method: "POST", path: "/tb/v1/status", headers: {}, body: `{"leak":"${ticket}"}`, at: 0 },
      { dir: "app-in" as const, method: "POST", path: "/tb/v1/ops/x", headers: {}, body: "secret-value-123", at: 0 },
      { dir: "app-in" as const, method: "POST", path: "/a/p/tb/launch", headers: {}, body: "secret-value-123", at: 0 },
    ];
    const r = scanPayloads(payloads, [{ label: "key value", values: ["secret-value-123"] }], {
      select: (p) => (p.dir === "bridge-in" ? `bridge ${p.path}` : p.path.startsWith("/tb/v1/") ? `answer ${p.path}` : null),
    });
    assert.equal(r.payloads, 2);
    assert.deepEqual(r.findings, ["answer /tb/v1/ops/x: key value", "bridge /tb/v1/status: person ticket (tb-ticket+jwt)"]);
    assert.ok(!r.findings.join().includes("secret-value-123"));
  });

  it("Mint helpers produce person-shaped values that are never tb tokens", () => {
    assert.match(Mint.ownerCliLike(), /^tbo_[A-Za-z0-9_-]{43}$/);
    const clerk = Mint.clerkLikeJwt();
    assert.equal(clerk.split(".").length, 3);
    assert.equal(peek(clerk)?.sub, "user_conformance");
    assert.equal(peek("not-a-jws"), null);
  });
});
