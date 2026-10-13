// The ONE store (SDK-API §7.1): node:sqlite at TB_DATA_DIR/app.db, WAL, one process; the ONE migration runner
// (SDK set first, then the app's forward-only NNNN_<name>.sql|.ts files). App code gets a `Db` handle that the
// SQLite authorizer keeps away from SDK-reserved `tb_*` tables.
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { constants, DatabaseSync, type SQLInputValue } from "node:sqlite";
import { pathToFileURL } from "node:url";
import type { Db } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";

export type RawDb = DatabaseSync;
export type Row = Record<string, unknown>;

/** SDK-internal migrations (scope "sdk"), applied before any app migration. Forward-only; never edit an entry. */
export const SDK_MIGRATIONS: readonly { version: number; name: string; sql: string }[] = [
  {
    version: 1,
    name: "sdk_baseline",
    sql: `
CREATE TABLE tb_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE tb_receipts (
  id TEXT PRIMARY KEY, call_id TEXT, caller_type TEXT NOT NULL, caller_id TEXT NOT NULL, caller_name TEXT NOT NULL,
  op TEXT NOT NULL, effect TEXT NOT NULL, hold_family TEXT, status TEXT NOT NULL, input_digest TEXT NOT NULL,
  summary TEXT NOT NULL, meta TEXT NOT NULL, idempotency_key TEXT, view TEXT,
  created_at INTEGER NOT NULL, decided_at INTEGER, expires_at INTEGER, decided_by TEXT, consumed INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX tb_receipts_match ON tb_receipts (caller_id, op, input_digest, status);
CREATE INDEX tb_receipts_status ON tb_receipts (status, expires_at);
CREATE INDEX tb_receipts_usage ON tb_receipts (caller_id, effect, created_at);
CREATE INDEX tb_receipts_order ON tb_receipts (created_at, id);
CREATE INDEX tb_receipts_call ON tb_receipts (call_id);
CREATE TABLE tb_idempotency (
  caller_id TEXT NOT NULL, op TEXT NOT NULL, key TEXT NOT NULL, input_digest TEXT NOT NULL,
  kind TEXT NOT NULL, output TEXT, hold_id TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY (caller_id, op, key)
) STRICT;
CREATE TABLE tb_scope_instances (
  type TEXT NOT NULL, id TEXT NOT NULL, label TEXT NOT NULL, shared INTEGER NOT NULL DEFAULT 0, owner_agent TEXT,
  created_at INTEGER NOT NULL, PRIMARY KEY (type, id)
) STRICT;
CREATE TABLE tb_scopes (agent TEXT NOT NULL, type TEXT NOT NULL, instance_id TEXT NOT NULL, access TEXT NOT NULL,
  PRIMARY KEY (agent, type, instance_id)) STRICT;
CREATE TABLE tb_scope_defaults (agent TEXT NOT NULL, type TEXT NOT NULL, applied_at INTEGER NOT NULL,
  PRIMARY KEY (agent, type)) STRICT;
CREATE TABLE tb_agents (agent TEXT PRIMARY KEY, name TEXT NOT NULL, first_seen INTEGER NOT NULL, in_slice INTEGER NOT NULL) STRICT;
CREATE TABLE tb_sessions (digest TEXT PRIMARY KEY, person TEXT NOT NULL, ws TEXT NOT NULL, instance TEXT NOT NULL,
  iss TEXT NOT NULL, csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
CREATE TABLE tb_used_jti (jti TEXT PRIMARY KEY, exp INTEGER NOT NULL) STRICT;
CREATE TABLE tb_keys (name TEXT PRIMARY KEY, sealed TEXT NOT NULL, updated_at INTEGER NOT NULL) STRICT;
CREATE TABLE tb_audit (id TEXT PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT, detail TEXT NOT NULL) STRICT;
CREATE INDEX tb_audit_order ON tb_audit (at, id);
`,
  },
  {
    version: 2,
    name: "sdk_app_secrets",
    sql: "CREATE TABLE tb_secrets (name TEXT PRIMARY KEY, sealed TEXT NOT NULL, updated_at INTEGER NOT NULL) STRICT;",
  },
  {
    // v0.1.13 (G1): `held_by` = Receipt.heldBy (`<product>/<hookId>` of the before hook whose verdict held the call);
    // `hold_reason` = the hook verdict reason or the SDK hold reason code (tb.hold_status / tb.holds_pending). Old rows: null.
    version: 3,
    name: "sdk_receipt_held_by",
    sql: "ALTER TABLE tb_receipts ADD COLUMN held_by TEXT;\nALTER TABLE tb_receipts ADD COLUMN hold_reason TEXT;",
  },
];

function sha256(text: string | Uint8Array): string {
  return createHash("sha256").update(text).digest("hex");
}

/** Opens TB_DATA_DIR/app.db (WAL, foreign keys, busy timeout) and applies the SDK migration set. */
export function openStore(dataDir: string): RawDb {
  mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(join(dataDir, "app.db"));
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;");
  db.exec(
    "CREATE TABLE IF NOT EXISTS tb_migrations (scope TEXT NOT NULL, version INTEGER NOT NULL, name TEXT NOT NULL, sha256 TEXT NOT NULL, applied_at INTEGER NOT NULL, PRIMARY KEY (scope, version)) STRICT",
  );
  const applied = new Map(
    (db.prepare("SELECT version, sha256 FROM tb_migrations WHERE scope = 'sdk'").all() as Row[]).map((r) => [Number(r.version), String(r.sha256)]),
  );
  for (const m of SDK_MIGRATIONS) {
    const sum = sha256(m.sql);
    const have = applied.get(m.version);
    if (have !== undefined) {
      if (have !== sum) throw new TbError("migration_invalid", `SDK migration ${m.version} changed after it was applied`, 500);
      continue;
    }
    tx(db, () => {
      db.exec(m.sql);
      db.prepare("INSERT INTO tb_migrations (scope, version, name, sha256, applied_at) VALUES ('sdk', ?, ?, ?, ?)").run(m.version, m.name, sum, Date.now());
    });
  }
  return db;
}

// ── transactions (one runner; nested calls become savepoints) ──
const depth = new WeakMap<RawDb, number>();

export function tx<T>(db: RawDb, fn: () => T): T {
  const d = depth.get(db) ?? 0;
  const sp = `tbsp${d}`;
  db.exec(d === 0 ? "BEGIN IMMEDIATE" : `SAVEPOINT ${sp}`);
  depth.set(db, d + 1);
  try {
    const out = fn();
    if (out instanceof Promise) throw new TbError("db_transaction_async", "transaction callbacks must be synchronous", 500);
    db.exec(d === 0 ? "COMMIT" : `RELEASE ${sp}`);
    return out;
  } catch (e) {
    db.exec(d === 0 ? "ROLLBACK" : `ROLLBACK TO ${sp}; RELEASE ${sp}`);
    throw e;
  } finally {
    depth.set(db, d);
  }
}

// ── tb_meta key/value ──
export function metaGet<T>(db: RawDb, key: string): T | null {
  const row = db.prepare("SELECT value FROM tb_meta WHERE key = ?").get(key) as Row | undefined;
  return row ? (JSON.parse(String(row.value)) as T) : null;
}
export function metaSet(db: RawDb, key: string, value: unknown): void {
  db.prepare("INSERT INTO tb_meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").run(key, JSON.stringify(value));
}
export function metaDelete(db: RawDb, key: string): void {
  db.prepare("DELETE FROM tb_meta WHERE key = ?").run(key);
}

// ── App handle: SQLite authorizer denies every access to `tb_*` objects while app SQL compiles or runs ──
const RESERVED = /^tb_/i;
type Authorizer = (action: number, a1: string | null, a2: string | null, dbName: string | null, trigger: string | null) => number;
type AuthorizerDb = RawDb & { setAuthorizer?: (cb: Authorizer | null) => void };

const appAuthorizer: Authorizer = (action, a1, a2) => {
  if (action === constants.SQLITE_FUNCTION || action === constants.SQLITE_SAVEPOINT || action === constants.SQLITE_TRANSACTION) return constants.SQLITE_OK;
  return RESERVED.test(a1 ?? "") || RESERVED.test(a2 ?? "") ? constants.SQLITE_DENY : constants.SQLITE_OK;
};

function guarded<T>(db: RawDb, fn: () => T): T {
  const adb = db as AuthorizerDb;
  if (typeof adb.setAuthorizer !== "function") return fn();
  adb.setAuthorizer(appAuthorizer);
  try {
    return fn();
  } catch (e) {
    const msg = e instanceof Error ? e.message : "";
    if (/prohibited|not authorized/i.test(msg)) throw new TbError("db_reserved", "tb_* tables are reserved for the SDK", 500);
    throw e;
  } finally {
    adb.setAuthorizer(null);
  }
}

/**
 * Fallback for runtimes without `setAuthorizer`: reject SQL naming any `tb_*` identifier. KEPT on purpose (C133 audit V-19):
 * `setAuthorizer` exists from Node 24.10.0, `engines` says `>=24`, so Node 24.0–24.9 still run this SDK and would
 * otherwise let app SQL touch the SDK's reserved tables. It is a security guard, not an old-format reader.
 */
function legacyGuard(sql: string): void {
  if (/(^|[^a-z0-9_])tb_[a-z0-9_]*/i.test(sql)) throw new TbError("db_reserved", "tb_* tables are reserved for the SDK", 500);
}

/** The app's SQLite handle (OpContext.db): app tables only. */
export function appDb(db: RawDb): Db {
  const hasAuthorizer = typeof (db as AuthorizerDb).setAuthorizer === "function";
  const check = (sql: string) => {
    if (!hasAuthorizer) legacyGuard(sql);
  };
  return {
    exec(sql) {
      check(sql);
      guarded(db, () => db.exec(sql));
    },
    prepare(sql) {
      check(sql);
      const stmt = guarded(db, () => db.prepare(sql));
      const params = (p: unknown[]) => p as SQLInputValue[];
      return {
        run: (...p) => {
          const r = guarded(db, () => stmt.run(...params(p)));
          return { changes: Number(r.changes), lastInsertRowid: r.lastInsertRowid };
        },
        get: (...p) => guarded(db, () => stmt.get(...params(p))) as Row | undefined,
        all: (...p) => guarded(db, () => stmt.all(...params(p))) as Row[],
      };
    },
    transaction: (fn) => tx(db, fn),
  };
}

// ── App migrations (forward-only, gap-free from 0001, one transaction each) ──
const FILE_RE = /^(\d{4})_([a-z0-9][a-z0-9_-]*)\.(sql|ts)$/;

export interface AppliedMigration {
  version: number;
  name: string;
}

/** Applies the app's migration directory; any changed, missing, misnamed or down migration → `migration_invalid`. */
export async function runAppMigrations(db: RawDb, dir: string): Promise<AppliedMigration[]> {
  const abs = resolve(dir);
  let names: string[];
  try {
    names = readdirSync(abs);
  } catch {
    throw new TbError("migration_invalid", `migrations directory not found: ${dir}`, 500);
  }
  const files: { version: number; name: string; file: string; kind: "sql" | "ts"; sum: string; body: Buffer }[] = [];
  for (const f of names.sort()) {
    if (!/\.(sql|ts)$/.test(f)) continue;
    const m = FILE_RE.exec(f);
    if (!m || /(^|_)down(_|$)/.test(m[2])) throw new TbError("migration_invalid", `invalid migration file name: ${f}`, 500);
    const body = readFileSync(join(abs, f));
    files.push({ version: Number(m[1]), name: m[2], file: f, kind: m[3] as "sql" | "ts", sum: sha256(body), body });
  }
  files.forEach((f, i) => {
    if (f.version !== i + 1) throw new TbError("migration_invalid", `migrations must be gap-free from 0001 (at ${f.file})`, 500);
  });
  const applied = db.prepare("SELECT version, name, sha256 FROM tb_migrations WHERE scope = 'app' ORDER BY version").all() as Row[];
  for (const a of applied) {
    const f = files[Number(a.version) - 1];
    if (!f) throw new TbError("migration_invalid", `applied migration ${a.version} is missing`, 500);
    if (f.sum !== a.sha256) throw new TbError("migration_invalid", `applied migration ${f.file} changed`, 500);
  }
  const handle = appDb(db);
  const done: AppliedMigration[] = [];
  for (const f of files.slice(applied.length)) {
    let up: ((d: Db) => unknown) | null = null;
    if (f.kind === "ts") {
      const mod = (await import(pathToFileURL(join(abs, f.file)).href)) as { up?: unknown };
      if (typeof mod.up !== "function") throw new TbError("migration_invalid", `${f.file} must export function up(db)`, 500);
      up = mod.up as (d: Db) => unknown;
    }
    tx(db, () => {
      if (up) {
        if (up(handle) instanceof Promise) throw new TbError("migration_invalid", `${f.file}: up(db) must be synchronous`, 500);
      } else handle.exec(f.body.toString("utf8"));
      db.prepare("INSERT INTO tb_migrations (scope, version, name, sha256, applied_at) VALUES ('app', ?, ?, ?, ?)").run(f.version, f.name, f.sum, Date.now());
    });
    done.push({ version: f.version, name: f.name });
  }
  return done;
}
