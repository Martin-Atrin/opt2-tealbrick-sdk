// v0.1.25 (E2: UPGRADE-SAFETY M1–M3, C207 (2), C209): the data phase of a boot made upgrade-safe.
// - ONE migration lock per database (`tb_migration_lock`, holder + lease): two containers on one volume never migrate
//   together; a crashed holder is taken over after its lease.
// - a pre-update snapshot (backup.ts `writePreUpdateSnapshot`) before any pending migration or version change.
// - explicit refusals when the data is newer than the code (`app_schema_newer`, `sdk_schema_newer`).
// - the boot-failure model the failed-mode server reports (`BootFailure`): phase + code + migration file, never SQL or data.
// - `tb_meta` keys written in ONE transaction after a successful data phase (L31): app_version, schema, min_compatible_*.
import { hostname } from "node:os";
import { ulid } from "@opt2-tealbrick/manifest";
import { TbError } from "./errors.ts";
import { metaDelete, metaGet, metaSet, type RawDb, type Row, type SchemaVersion, tx } from "./store.ts";

/** Lease of the migration lock; a holder that stopped (crash, SIGKILL) is taken over after it (UPGRADE-SAFETY M2). */
export const MIGRATION_LOCK_LEASE_MS = 120_000;
/** How long a second instance waits for the holder before it gives up (failed mode `migration_locked`). */
export const MIGRATION_LOCK_WAIT_MS = 150_000;
const LOCK_POLL_MS = 1000;

export interface Clock {
  now(): number;
  sleep(ms: number): Promise<void>;
}
export const realClock: Clock = {
  now: () => Date.now(),
  sleep: (ms) =>
    new Promise((r) => {
      const t = setTimeout(r, ms);
      t.unref?.();
    }),
};

/**
 * The migration lock (one row, id = 1). `acquire` waits while another holder's lease is live and takes the row over
 * when the lease has run out; `heartbeat` extends the lease between migration files; `release` deletes the row only
 * when this process still holds it.
 */
export class MigrationLock {
  readonly holder: string;
  readonly #db: RawDb;
  readonly #clock: Clock;
  readonly #leaseMs: number;
  readonly #waitMs: number;
  #held = false;
  /** the holder this process took the lock over from (crashed instance), for the log */
  takenOverFrom: string | null = null;

  constructor(db: RawDb, opts: { clock?: Clock; leaseMs?: number; waitMs?: number; holder?: string } = {}) {
    this.#db = db;
    this.#clock = opts.clock ?? realClock;
    this.#leaseMs = opts.leaseMs ?? MIGRATION_LOCK_LEASE_MS;
    this.#waitMs = opts.waitMs ?? MIGRATION_LOCK_WAIT_MS;
    this.holder = opts.holder ?? `${hostname().slice(0, 40)}/${process.pid}/${ulid()}`;
  }

  get held(): boolean {
    return this.#held;
  }

  /** One attempt: true when this process holds the lock afterwards. */
  tryAcquire(): boolean {
    const now = this.#clock.now();
    return tx(this.#db, () => {
      const row = this.#db.prepare("SELECT holder, until FROM tb_migration_lock WHERE id = 1").get() as Row | undefined;
      if (row && String(row.holder) !== this.holder && Number(row.until) > now) return false;
      if (row && String(row.holder) !== this.holder) this.takenOverFrom = String(row.holder);
      this.#db
        .prepare("INSERT INTO tb_migration_lock (id, holder, until) VALUES (1, ?, ?) ON CONFLICT (id) DO UPDATE SET holder = excluded.holder, until = excluded.until")
        .run(this.holder, now + this.#leaseMs);
      this.#held = true;
      return true;
    });
  }

  async acquire(): Promise<void> {
    const start = this.#clock.now();
    for (;;) {
      if (this.tryAcquire()) return;
      if (this.#clock.now() - start >= this.#waitMs) {
        const row = this.#db.prepare("SELECT holder, until FROM tb_migration_lock WHERE id = 1").get() as Row | undefined;
        throw new TbError("migration_locked", "another instance holds the migration lock of this database", 503, { holder: row ? String(row.holder) : null });
      }
      await this.#clock.sleep(LOCK_POLL_MS);
    }
  }

  /** Extends the lease; `migration_lock_lost` when another instance took the lock over (this process must stop migrating). */
  heartbeat(): void {
    if (!this.#held) return;
    const r = this.#db.prepare("UPDATE tb_migration_lock SET until = ? WHERE id = 1 AND holder = ?").run(this.#clock.now() + this.#leaseMs, this.holder);
    if (Number(r.changes) !== 1) {
      this.#held = false;
      throw new TbError("migration_lock_lost", "another instance took over the migration lock", 503);
    }
  }

  release(): void {
    if (!this.#held) return;
    this.#held = false;
    try {
      this.#db.prepare("DELETE FROM tb_migration_lock WHERE id = 1 AND holder = ?").run(this.holder);
    } catch {
      // a closed or broken database: the lease runs out by itself
    }
  }
}

/** `tb_meta` keys (E2). */
export const META = {
  appVersion: "app_version",
  schema: "schema",
  minCompatibleCode: "min_compatible_code",
  minCompatibleSdk: "min_compatible_sdk",
  /** set after the snapshot, before the first pending migration; deleted with the success write (crash → snapshot reused) */
  upgrade: "upgrade_in_progress",
  /** the newest pre-update snapshot written for this database */
  lastPreUpdate: "last_preupdate",
} as const;

export interface PreUpdateSnapshot {
  file: string;
  sha256: string;
  bytes: number;
  createdAt: string;
  /** the app version that wrote the data (null: a database from before SDK 0.1.25 records no version) */
  from: string | null;
  to: string;
  schema: SchemaVersion;
}

export interface UpgradeInProgress {
  from: string | null;
  to: string;
  snapshot: PreUpdateSnapshot;
  startedAt: number;
}

export function readUpgradeMeta(db: RawDb): {
  appVersion: string | null;
  minCompatibleCode: string | null;
  minCompatibleSdk: string | null;
  upgrade: UpgradeInProgress | null;
  lastPreUpdate: PreUpdateSnapshot | null;
} {
  const has = !!db.prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'tb_meta'").get();
  if (!has) return { appVersion: null, minCompatibleCode: null, minCompatibleSdk: null, upgrade: null, lastPreUpdate: null };
  return {
    appVersion: metaGet<string>(db, META.appVersion),
    minCompatibleCode: metaGet<string>(db, META.minCompatibleCode),
    minCompatibleSdk: metaGet<string>(db, META.minCompatibleSdk),
    upgrade: metaGet<UpgradeInProgress>(db, META.upgrade),
    lastPreUpdate: metaGet<PreUpdateSnapshot>(db, META.lastPreUpdate),
  };
}

/** The success write of the data phase: ONE transaction (L31). */
export function recordBoot(
  db: RawDb,
  opts: { version: string; sdkVersion: string; schema: SchemaVersion; appMigrated: boolean; sdkMigrated: boolean; prev: { minCompatibleCode: string | null; minCompatibleSdk: string | null }; snapshot: PreUpdateSnapshot | null },
): { minCompatibleCode: string | null; minCompatibleSdk: string | null } {
  // the oldest code that can open this data = the version that applied its newest migration. A database from before
  // 0.1.25 that this boot did not migrate has no record: unknown (null), never a guess.
  const minCompatibleCode = opts.appMigrated ? opts.version : opts.prev.minCompatibleCode;
  const minCompatibleSdk = opts.sdkMigrated ? opts.sdkVersion : opts.prev.minCompatibleSdk;
  tx(db, () => {
    metaSet(db, META.appVersion, opts.version);
    metaSet(db, META.schema, opts.schema);
    if (minCompatibleCode) metaSet(db, META.minCompatibleCode, minCompatibleCode);
    if (minCompatibleSdk) metaSet(db, META.minCompatibleSdk, minCompatibleSdk);
    if (opts.snapshot) metaSet(db, META.lastPreUpdate, opts.snapshot);
    metaDelete(db, META.upgrade);
  });
  return { minCompatibleCode, minCompatibleSdk };
}

// ── boot failures (failed mode, M2) ──
export type BootPhase = "restore" | "open" | "schema" | "lock" | "snapshot" | "sdk_migrations" | "app_migrations";

/** Machine-readable reason of a failed boot (health `failure`, status push). Never SQL, data or a secret. */
export interface BootFailure {
  phase: BootPhase;
  /** the SDK error code (e.g. migration_invalid, app_schema_newer, restore_failed) */
  code: string;
  /** a narrower reason where the code has several (restore: product_mismatch | version_newer | schema_newer | …) */
  reason?: string;
  /** the app migration file that failed */
  file?: string;
  at: string;
}

/**
 * Attention code + owner text per failed phase. Wire: AppStatus.attention (readiness `degraded`) — the ONE field the
 * bridge copies into its Portal report today (bridge 0.1.29 portal.ts), so Core sees a failed boot within seconds.
 */
export function failureAttention(f: BootFailure): { code: string; reason: string } {
  if (f.code === "app_schema_newer" || f.code === "sdk_schema_newer")
    return { code: "schema_newer", reason: "A newer version of this app wrote its data. Run that version again, or restore the copy taken before that update." };
  if (f.phase === "restore") return { code: "restore_failed", reason: "The app could not restore its data from the copy it was given. The current data was not changed." };
  if (f.phase === "lock") return { code: "migration_locked", reason: "Another copy of this app is changing the data right now. It did not finish in time." };
  if (f.phase === "snapshot")
    return f.code === "preupdate_snapshot_no_space"
      ? { code: "preupdate_snapshot_no_space", reason: "The update needs free space for a copy of the data first. The data volume is too full, so nothing was changed." }
      : { code: "preupdate_snapshot_failed", reason: "The app could not save a copy of its data before the update, so it changed nothing." };
  return {
    code: "migration_failed",
    reason: `The update could not change the stored data${f.file ? ` (${f.file})` : ""}. A copy from before the update is saved; go back to the previous version.`.slice(0, 200),
  };
}

export function bootFailure(phase: BootPhase, e: unknown, now: number): BootFailure {
  const code = e instanceof TbError ? e.code : "boot_failed";
  const d = e instanceof TbError ? e.details : undefined;
  const reason = typeof d?.reason === "string" ? d.reason : undefined;
  const file = typeof d?.file === "string" ? d.file : undefined;
  return { phase, code, ...(reason ? { reason } : {}), ...(file ? { file } : {}), at: new Date(now).toISOString() };
}

// ── semver (x.y.z[-pre]; enough for app versions) ──
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/.exec(v);
    if (!m) throw new TbError("version_invalid", `not a semver version: ${v}`, 500);
    return { n: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? null };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) if ((x.n[i] as number) !== (y.n[i] as number)) return (x.n[i] as number) < (y.n[i] as number) ? -1 : 1;
  if (x.pre === y.pre) return 0;
  if (x.pre === null) return 1;
  if (y.pre === null) return -1;
  const xs = x.pre.split(".");
  const ys = y.pre.split(".");
  for (let i = 0; i < Math.max(xs.length, ys.length); i++) {
    const p = xs[i];
    const q = ys[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn && Number(p) !== Number(q)) return Number(p) < Number(q) ? -1 : 1;
    if (pn !== qn) return pn ? -1 : 1;
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}
