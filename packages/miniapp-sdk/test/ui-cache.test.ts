import assert from "node:assert/strict";
import { test } from "node:test";
import { uiCacheControl } from "../src/server/server.ts";

test("C61: UI cache headers — HTML / un-hashed files revalidate, content-hashed assets are immutable", () => {
  assert.equal(uiCacheControl("index.html"), "no-cache");
  assert.equal(uiCacheControl(""), "no-cache");
  assert.equal(uiCacheControl("main.js"), "no-cache", "an un-hashed file is never cached for minutes");
  assert.equal(uiCacheControl("assets-0123456789ab/main.js"), "private, max-age=31536000, immutable");
  assert.equal(uiCacheControl("/assets-0123456789abcdef/vendor/x.css"), "private, max-age=31536000, immutable");
  assert.equal(uiCacheControl("assets-short/main.js"), "no-cache");
  assert.equal(uiCacheControl("x/assets-0123456789ab/main.js"), "no-cache", "only the top-level hashed directory");
});
