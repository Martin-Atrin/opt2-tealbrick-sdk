import assert from "node:assert/strict";
import { test } from "node:test";
import { channelSenderId, deriveIdempotencyKey, holdVerdictClaim, hookResponseProblem, isValidLaunchPath, onBehalfOfFromMeta, parseChannelSender, reduceBeforeChain } from "../src/index.ts";

test("hookResponseProblem: before (allow/refuse/hold), context (namespace, reserved tb.), after", () => {
  assert.equal(hookResponseProblem("before", { allow: true }, "rules"), null);
  assert.equal(hookResponseProblem("before", { allow: false, reason: "no" }, "rules"), null);
  assert.equal(hookResponseProblem("before", { allow: false, hold: { family: "policy", reason: "review" } }, "rules"), null);
  assert.match(hookResponseProblem("before", { allow: true, hold: { family: "policy", reason: "x" } }, "rules") ?? "", /allow true/);
  assert.match(hookResponseProblem("before", { allow: false, hold: { family: "caps", reason: "x" } }, "rules") ?? "", /family/);
  assert.match(hookResponseProblem("before", { allow: false, hold: { family: "money", reason: "" } }, "rules") ?? "", /reason/);
  assert.match(hookResponseProblem("before", { allow: false, hold: { family: "money", reason: "x".repeat(281) } }, "rules") ?? "", /reason/);
  assert.match(hookResponseProblem("before", { allow: false, extra: 1 }, "rules") ?? "", /unknown keys/);
  assert.match(hookResponseProblem("before", { allow: "yes" }, "rules") ?? "", /boolean/);
  assert.equal(hookResponseProblem("context", { add: { "rules.narrowing": { v: 1 } } }, "rules"), null);
  assert.match(hookResponseProblem("context", { add: { "tb.onBehalfOf": {} } }, "rules") ?? "", /reserved/);
  assert.match(hookResponseProblem("context", { add: { "knowledge.x": 1 } }, "rules") ?? "", /outside/);
  assert.equal(hookResponseProblem("after", { redactions: ["/items/0/body", ""] }, "rules"), null);
  assert.match(hookResponseProblem("after", { redactions: ["items"] }, "rules") ?? "", /pointers/);
});

test("reduceBeforeChain: refuse wins at once; else the FIRST hold; a later refuse beats an earlier hold", () => {
  const allow = { allow: true };
  const hold = (reason: string) => ({ allow: false, hold: { family: "policy" as const, reason } });
  const refuse = { allow: false, reason: "blocked" };
  assert.deepEqual(reduceBeforeChain([]), { kind: "allow" });
  assert.deepEqual(reduceBeforeChain([{ by: "a/h", answer: allow }]), { kind: "allow" });
  const h = reduceBeforeChain([
    { by: "a/h", answer: allow },
    { by: "b/h", answer: hold("first") },
    { by: "c/h", answer: hold("second") },
  ]);
  assert.deepEqual(h, { kind: "hold", by: "b/h", verdict: { family: "policy", reason: "first" } });
  assert.deepEqual(holdVerdictClaim(h as Extract<typeof h, { kind: "hold" }>), { f: "policy", r: "first", by: "b/h" });
  assert.deepEqual(reduceBeforeChain([{ by: "b/h", answer: hold("x") }, { by: "c/h", answer: refuse }]), { kind: "refuse", by: "c/h", reason: "blocked" });
  assert.deepEqual(reduceBeforeChain([{ by: "c/h", answer: { allow: false } }]), { kind: "refuse", by: "c/h", reason: null });
});

test("onBehalfOfFromMeta: shape, channel_sender format, 1 KB cap; unverified", () => {
  assert.deepEqual(onBehalfOfFromMeta({ kind: "channel_sender", id: "buzz:npub1abc", display: "Ann" }), { claim: { kind: "channel_sender", id: "buzz:npub1abc", display: "Ann" }, verified: false, via: "mcp_meta" });
  assert.deepEqual(onBehalfOfFromMeta({ kind: "person", id: "per_1" })?.claim, { kind: "person", id: "per_1" });
  for (const bad of [null, "x", [], { kind: "boss", id: "x" }, { kind: "person", id: "" }, { kind: "person", id: "x", extra: 1 }, { kind: "channel_sender", id: "npub1abc" }, { kind: "person", id: "x".repeat(257) }, { kind: "person", id: "x", display: "d".repeat(129) }]) {
    assert.equal(onBehalfOfFromMeta(bad), null, JSON.stringify(bad)?.slice(0, 60));
  }
  assert.equal(onBehalfOfFromMeta({ kind: "agent", id: "a".repeat(256), display: "d".repeat(128) })?.verified, false);
});

test("channel_sender ids: build, parse, bare npub reads as buzz", () => {
  assert.equal(channelSenderId("slack", "U123"), "slack:U123");
  assert.throws(() => channelSenderId("Slack", "U1"));
  assert.throws(() => channelSenderId("slack", ""));
  assert.deepEqual(parseChannelSender("telegram:4242"), { channel: "telegram", value: "4242" });
  assert.deepEqual(parseChannelSender("npub1xyz"), { channel: "buzz", value: "npub1xyz" });
  assert.equal(parseChannelSender("no-colon"), null);
});

test("isValidLaunchPath (C86): app-relative only", () => {
  for (const ok of ["/", "/holds/hld_01", "/items?id=3#top", "/a/b%20c"]) assert.ok(isValidLaunchPath(ok), ok);
  for (const no of ["", "holds", "//evil.example/x", "/a//b", "https://evil.example", "/a/../b", "/a/%2e%2e/b", "/a\\b", "/a%5Cb", "/%2F%2Fevil", "/a\nb", `/${"x".repeat(512)}`, "/%E0%A4%A"]) {
    assert.equal(isValidLaunchPath(no), false, JSON.stringify(no).slice(0, 40));
  }
});

test("deriveIdempotencyKey (C98): stable within the 10-min bucket, differs by session, op, input, connection, bucket", () => {
  const base = { connection: "con_1", session: "s1", op: "note_write", input: { text: "a", n: 1 }, now: 1_000_000 * 600_000 + 5 };
  const k = deriveIdempotencyKey(base);
  assert.match(k, /^drv_[0-9a-f]{64}$/);
  assert.equal(deriveIdempotencyKey({ ...base, input: { n: 1, text: "a" }, now: base.now + 1000 }), k, "key order and time inside the bucket do not matter");
  for (const other of [{ session: "s2" }, { op: "x" }, { input: { text: "b", n: 1 } }, { connection: "con_2" }, { now: base.now + 600_000 }]) {
    assert.notEqual(deriveIdempotencyKey({ ...base, ...other }), k, JSON.stringify(other));
  }
});

test("normalizeTag / tagsMatch (G5): trim + lower case on both sides; anyOf at least one, noneOf none", async () => {
  const { normalizeTag, tagsMatch } = await import("../src/index.ts");
  assert.equal(normalizeTag("  Work "), "work");
  assert.equal(tagsMatch(undefined, []), true);
  assert.equal(tagsMatch({ anyOf: ["Work"] }, ["work", "x"]), true);
  assert.equal(tagsMatch({ anyOf: ["work"] }, [" WORK "]), true);
  assert.equal(tagsMatch({ anyOf: ["work"] }, ["home"]), false);
  assert.equal(tagsMatch({ anyOf: ["work"] }, []), false);
  // C115: an EMPTY anyOf passes nothing (Rules' disjoint merge); absent anyOf is no constraint
  assert.equal(tagsMatch({ anyOf: [] }, ["home"]), false, "empty anyOf passes nothing");
  assert.equal(tagsMatch({ anyOf: [] }, []), false);
  assert.equal(tagsMatch({ anyOf: [], noneOf: ["x"] }, ["home"]), false, "empty anyOf + noneOf still passes nothing");
  assert.equal(tagsMatch({ noneOf: ["x"] }, ["home"]), true, "absent anyOf = no anyOf constraint");
  assert.equal(tagsMatch({}, ["home"]), true, "no lists = no constraint");
  assert.equal(tagsMatch({ noneOf: ["Secret"] }, ["secret"]), false);
  assert.equal(tagsMatch({ noneOf: ["secret"] }, []), true);
  assert.equal(tagsMatch({ anyOf: ["work"], noneOf: ["secret"] }, ["work", "Secret"]), false);
});
