import assert from "node:assert/strict";
import { test } from "node:test";
import { compareSemver, requiredBridgeVersion, sdkMajorOf, sdkMajorServed } from "../src/index.ts";

test("sdkMajorOf: 0.x counts as major 1 (C35/C44)", () => {
  assert.equal(sdkMajorOf("0.1.2"), 1);
  assert.equal(sdkMajorOf("0.9.0-rc.1"), 1);
  assert.equal(sdkMajorOf("1.0.0"), 1);
  assert.equal(sdkMajorOf("2.3.4"), 2);
  assert.throws(() => sdkMajorOf("1.0"));
  assert.throws(() => sdkMajorOf("v1.0.0"));
});

test("sdkMajorServed: current major and the one before", () => {
  assert.equal(sdkMajorServed("0.1.2", 1), true);
  assert.equal(sdkMajorServed("1.4.0", 2), true);
  assert.equal(sdkMajorServed("0.1.0", 3), false);
  assert.equal(sdkMajorServed("3.0.0", 2), false);
});

test("compareSemver and requiredBridgeVersion (C104): feature table + declared, highest wins", () => {
  assert.equal(compareSemver("0.1.16", "0.1.9"), 1);
  assert.equal(compareSemver("0.1.9", "0.1.9"), 0);
  assert.equal(compareSemver("1.0.0-rc.1", "1.0.0"), -1);
  assert.throws(() => compareSemver("1.0", "1.0.0"));
  assert.deepEqual(requiredBridgeVersion({ operations: [{}], companions: [] }), { bridge: null, reasons: [] });
  assert.equal(requiredBridgeVersion({ operations: [{ dynamic: { mode: "search" } }] }).bridge, "0.1.15");
  const wild = requiredBridgeVersion({ operations: [{ dynamic: {} }], companions: [{ product: "*", operations: ["tb.holds_pending"] }] });
  assert.equal(wild.bridge, "0.1.16");
  assert.equal(wild.reasons.length, 3);
  assert.equal(requiredBridgeVersion({ companions: [{ product: "*", operations: ["tb.holds_pending"] }], requires: { bridge: "0.1.17" } }).bridge, "0.1.17");
  assert.equal(requiredBridgeVersion({ operations: [{ dynamic: {} }], requires: { bridge: "0.1.2" } }).bridge, "0.1.15");
});
