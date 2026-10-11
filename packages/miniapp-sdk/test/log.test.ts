// Logger redaction (SDK-API §3.1): secret-looking field names and fetched key values never reach a log line.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createLogger, SecretRegistry } from "../src/server/log.ts";

test("logger redacts secret field names and registered key values, honours the level", () => {
  const lines: string[] = [];
  const secrets = new SecretRegistry();
  secrets.add("sk-live-value-123");
  const log = createLogger("info", secrets, { product: "jotter" }, { write: (_l, line) => lines.push(line) });
  log.info("call", { authorization: "Bearer abc", nested: { apiKey: "x", note: "sk-live-value-123", ok: "fine" }, list: ["sk-live-value-123"] });
  log.debug("hidden");
  assert.equal(lines.length, 1);
  const rec = JSON.parse(lines[0] as string);
  assert.equal(rec.authorization, "[redacted]");
  assert.equal(rec.nested.apiKey, "[redacted]");
  assert.equal(rec.nested.note, "[redacted]");
  assert.equal(rec.nested.ok, "fine");
  assert.deepEqual(rec.list, ["[redacted]"]);
  assert.equal(rec.product, "jotter");
  assert.equal(lines[0]?.includes("sk-live-value-123"), false);
});
