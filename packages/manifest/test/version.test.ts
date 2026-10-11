import assert from "node:assert/strict";
import { test } from "node:test";
import { sdkMajorOf, sdkMajorServed } from "../src/index.ts";

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
