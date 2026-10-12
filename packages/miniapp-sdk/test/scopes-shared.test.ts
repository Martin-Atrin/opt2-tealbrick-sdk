// v0.1.13 (Kanban QA S2): an instance that becomes shared reaches callers seen before; owner edits win.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { PersonPrincipal } from "@opt2-tealbrick/spec/sdk";
import { createAuditLog } from "../src/server/audit.ts";
import { createScopeStore } from "../src/server/scopes.ts";
import { openStore } from "../src/server/store.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "tb-scopes-"));
  const db = openStore(dir);
  const m = fixtureManifest(1) as Manifest;
  const sc = m.scopes?.[0];
  if (!sc) throw new Error("fixture has no scope");
  sc.defaultGrants = [
    { kind: "own", access: "read_write" },
    { kind: "shared", access: "read" },
  ];
  let changes = 0;
  const store = createScopeStore(db, m, createAuditLog(db, []), () => {
    changes += 1;
  });
  return { store, changes: () => changes, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
const owner = { type: "person", id: "per_owner" } as unknown as PersonPrincipal;

test("an instance created shared AFTER agents were seen reaches every seen agent (shared default)", async () => {
  const { store, changes, cleanup } = setup();
  try {
    store.applyDefaultsFor("agt_a", "A");
    store.applyDefaultsFor("agt_b", "B");
    const before = changes();
    await store.instances.create("notebook", "team", "Team", { shared: true });
    assert.ok(changes() > before, "scopes rev bumped");
    assert.equal((await store.access("agt_a" as never, "notebook", "team"))?.access, "read");
    assert.equal((await store.access("agt_b" as never, "notebook", "team"))?.access, "read");
    // an agent seen later still gets it on first sight
    store.applyDefaultsFor("agt_c", "C");
    assert.equal((await store.access("agt_c" as never, "notebook", "team"))?.access, "read");
  } finally {
    cleanup();
  }
});

test("switching an instance to shared applies the default once; owner edits win; re-upserting does not re-grant", async () => {
  const { store, cleanup } = setup();
  try {
    store.applyDefaultsFor("agt_a", "A");
    store.applyDefaultsFor("agt_b", "B");
    await store.instances.create("notebook", "proj", "Project");
    assert.equal(await store.access("agt_a" as never, "notebook", "proj"), null, "not shared: no grant");
    // owner gives A write before the share
    await store.set(owner, "agt_a" as never, "notebook", "proj", "read_write");
    await store.instances.create("notebook", "proj", "Project", { shared: true });
    assert.equal((await store.access("agt_a" as never, "notebook", "proj"))?.access, "read_write", "owner edit wins");
    assert.equal((await store.access("agt_b" as never, "notebook", "proj"))?.access, "read");
    // owner removes B; the app re-upserts the (still shared) instance: no re-grant
    await store.set(owner, "agt_b" as never, "notebook", "proj", null);
    await store.instances.create("notebook", "proj", "Project renamed", { shared: true });
    assert.equal(await store.access("agt_b" as never, "notebook", "proj"), null, "owner removal wins");
  } finally {
    cleanup();
  }
});
