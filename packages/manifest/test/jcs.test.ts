// RFC 8785 vectors: number serialization (Appendix B), the §3.2.2 example and §3.2.3 key sorting.
import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalize, digest, sha256Bytes } from "../src/jcs.ts";

const fromHex = (hex: string) => {
  const dv = new DataView(new ArrayBuffer(8));
  dv.setBigUint64(0, BigInt(`0x${hex}`));
  return dv.getFloat64(0);
};

test("RFC 8785 Appendix B number vectors", () => {
  const vectors: [string, string][] = [
    ["0000000000000000", "0"],
    ["8000000000000000", "0"],
    ["0000000000000001", "5e-324"],
    ["8000000000000001", "-5e-324"],
    ["7fefffffffffffff", "1.7976931348623157e+308"],
    ["ffefffffffffffff", "-1.7976931348623157e+308"],
    ["4340000000000000", "9007199254740992"],
    ["c340000000000000", "-9007199254740992"],
    ["4430000000000000", "295147905179352830000"],
    ["44b52d02c7e14af5", "9.999999999999997e+22"],
    ["44b52d02c7e14af6", "1e+23"],
    ["44b52d02c7e14af7", "1.0000000000000001e+23"],
    ["444b1ae4d6e2ef4e", "999999999999999700000"],
    ["444b1ae4d6e2ef4f", "999999999999999900000"],
    ["444b1ae4d6e2ef50", "1e+21"],
    ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
    ["3eb0c6f7a0b5ed8d", "0.000001"],
    ["41b3de4355555553", "333333333.3333332"],
    ["41b3de4355555554", "333333333.33333325"],
    ["41b3de4355555555", "333333333.3333333"],
    ["41b3de4355555556", "333333333.3333334"],
    ["41b3de4355555557", "333333333.33333343"],
    ["becbf647612f3696", "-0.0000033333333333333333"],
    ["43143ff3c1cb0959", "1424953923781206.2"],
  ];
  for (const [hex, want] of vectors) assert.equal(canonicalize(fromHex(hex)), want, hex);
});

test("non-finite numbers and non-JSON values are rejected", () => {
  assert.throws(() => canonicalize(Number.NaN));
  assert.throws(() => canonicalize(Number.POSITIVE_INFINITY));
  assert.throws(() => canonicalize({ a: undefined } as never));
  assert.throws(() => canonicalize(new Date() as never));
  assert.throws(() => canonicalize(1n as never));
});

test("RFC 8785 §3.2.2 example (numbers, string escaping, literals)", () => {
  const input = JSON.parse(
    '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", "literals": [null, true, false]}',
  );
  const want = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
  assert.equal(canonicalize(input), want);
});

test("RFC 8785 §3.2.3 key sorting by UTF-16 code units", () => {
  const input = {
    "\u20ac": "Euro Sign",
    "\r": "Carriage Return",
    "\ufb33": "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "\ud83d\ude00": "Emoji: Grinning Face",
    "\u0080": "Control",
    "\u00f6": "Latin Small Letter O With Diaeresis",
  };
  const want =
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis",' +
    '"\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}';
  assert.equal(canonicalize(input), want);
});

test("digest is sha256 of the JCS bytes", () => {
  assert.equal(digest({ b: 1, a: [true] }), sha256Bytes(new TextEncoder().encode('{"a":[true],"b":1}')));
  assert.match(digest(null), /^sha256:[0-9a-f]{64}$/);
});

test("canonicalize rejects lone surrogates (I-JSON, RFC 8785)", () => {
  assert.throws(() => canonicalize("a\uD800b"));
  assert.throws(() => canonicalize({ "\uDC00": 1 }));
  assert.equal(canonicalize("😀"), '"😀"');
});
