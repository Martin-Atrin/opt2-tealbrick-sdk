// Receipts and holds — ONE table `tb_receipts` (SDK-API §4); idempotency results in `tb_idempotency` (§4.4).
import { ulid } from "@opt2-tealbrick/manifest";
import type { FreeCaps, Sha256Digest } from "@opt2-tealbrick/spec/credentials";
import type { Effect, HoldFamily } from "@opt2-tealbrick/spec/manifest";
import type { Json, Receipt, ReceiptQuery, ReceiptStatus, ReceiptStore } from "@opt2-tealbrick/spec/sdk";
import { clampLimit, decodeCursor, encodeCursor } from "./audit.ts";
import type { RawDb, Row } from "./store.ts";

export const HOLD_TTL_MS = 15 * 60_000;
/** After approval the agent repeats the same call within 15 min (§4.3). */
export const APPROVAL_WINDOW_MS = 15 * 60_000;
export const IDEMPOTENCY_TTL_MS = 24 * 3600_000;
export const RECEIPT_RETENTION_MS = 90 * 86400_000;
const CAP_WINDOW_MS = { hour: 3600_000, day: 86400_000 } as const;

export interface NewReceipt {
  kind: "hld" | "rcp";
  callId: Receipt["callId"];
  caller: Receipt["caller"];
  op: string;
  effect: Effect;
  holdFamily: HoldFamily | "caps" | null;
  status: ReceiptStatus;
  inputDigest: Sha256Digest;
  summary: string;
  meta: Json;
  idempotencyKey: string | null;
  view?: string | null;
  expiresAt?: number | null;
}

export type IdempotencyRow =
  | { kind: "result"; inputDigest: string; output: string }
  | { kind: "held"; inputDigest: string; holdId: string };

function toReceipt(r: Row, withView: boolean): Receipt {
  const rec: Receipt = {
    id: String(r.id) as Receipt["id"],
    callId: (r.call_id as Receipt["callId"]) ?? null,
    caller: { type: String(r.caller_type) as "agent" | "app", id: String(r.caller_id) as Receipt["caller"]["id"], name: String(r.caller_name) },
    op: String(r.op),
    effect: String(r.effect) as Effect,
    holdFamily: (r.hold_family as Receipt["holdFamily"]) ?? null,
    status: String(r.status) as ReceiptStatus,
    inputDigest: String(r.input_digest) as Sha256Digest,
    summary: String(r.summary),
    meta: JSON.parse(String(r.meta)) as Json,
    idempotencyKey: (r.idempotency_key as string | null) ?? null,
    createdAt: Number(r.created_at),
    decidedAt: r.decided_at === null ? null : Number(r.decided_at),
    expiresAt: r.expires_at === null ? null : Number(r.expires_at),
    decidedBy: (r.decided_by as Receipt["decidedBy"]) ?? null,
  };
  if (withView && typeof r.view === "string") rec.view = r.view;
  return rec;
}

export class Receipts implements ReceiptStore {
  readonly #db: RawDb;
  constructor(db: RawDb) {
    this.#db = db;
  }

  async get(id: Receipt["id"]): Promise<Receipt | null> {
    return this.getSync(id);
  }
  getSync(id: string): Receipt | null {
    const r = this.#db.prepare("SELECT * FROM tb_receipts WHERE id = ?").get(id) as Row | undefined;
    return r ? toReceipt(r, true) : null;
  }

  async list(q: ReceiptQuery): Promise<{ items: Receipt[]; nextCursor: string | null }> {
    const limit = clampLimit(q.limit);
    const cur = decodeCursor(q.cursor);
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (q.caller) {
      where.push("caller_id = ?");
      args.push(q.caller);
    }
    if (q.op) {
      where.push("op = ?");
      args.push(q.op);
    }
    const statuses = q.status === undefined ? [] : Array.isArray(q.status) ? q.status : [q.status];
    if (statuses.length) {
      where.push(`status IN (${statuses.map(() => "?").join(",")})`);
      args.push(...statuses);
    }
    if (cur) {
      where.push("(created_at < ? OR (created_at = ? AND id < ?))");
      args.push(cur.at, cur.at, cur.id);
    }
    const rows = this.#db
      .prepare(`SELECT * FROM tb_receipts ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY created_at DESC, id DESC LIMIT ?`)
      .all(...args, limit + 1) as Row[];
    const items = rows.slice(0, limit).map((r) => toReceipt(r, true));
    const last = items.at(-1);
    return { items, nextCursor: rows.length > limit && last ? encodeCursor(last.createdAt, last.id) : null };
  }

  async usage(caller: string, caps: FreeCaps, now: number): Promise<Partial<Record<Effect, number>>> {
    const out: Partial<Record<Effect, number>> = {};
    const stmt = this.#db.prepare(
      "SELECT COUNT(*) AS n FROM tb_receipts WHERE caller_id = ? AND effect = ? AND status IN ('run', 'approved') AND created_at >= ?",
    );
    for (const [effect, cap] of Object.entries(caps) as [Effect, { max: number; per: "hour" | "day" } | undefined][]) {
      if (!cap) continue;
      out[effect] = Number((stmt.get(caller, effect, now - CAP_WINDOW_MS[cap.per]) as Row).n);
    }
    return out;
  }

  async holdStatus(caller: string, holdId: string): Promise<{ status: ReceiptStatus; decidedAt: number | null; expiresAt: number | null } | null> {
    const r = this.#db
      .prepare("SELECT status, decided_at, expires_at FROM tb_receipts WHERE id = ? AND caller_id = ? AND id LIKE 'hld\\_%' ESCAPE '\\'")
      .get(holdId, caller) as Row | undefined;
    if (!r) return null;
    return {
      status: String(r.status) as ReceiptStatus,
      decidedAt: r.decided_at === null ? null : Number(r.decided_at),
      expiresAt: r.expires_at === null ? null : Number(r.expires_at),
    };
  }

  // ── internal (SDK only) ──
  insert(n: NewReceipt, now = Date.now()): Receipt {
    const id = `${n.kind}_${ulid(now)}`;
    this.#db
      .prepare(
        `INSERT INTO tb_receipts (id, call_id, caller_type, caller_id, caller_name, op, effect, hold_family, status, input_digest,
          summary, meta, idempotency_key, view, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        n.callId,
        n.caller.type,
        n.caller.id,
        n.caller.name,
        n.op,
        n.effect,
        n.holdFamily,
        n.status,
        n.inputDigest,
        n.summary,
        JSON.stringify(n.meta ?? null),
        n.idempotencyKey,
        n.view ?? null,
        now,
        n.expiresAt ?? null,
      );
    return this.getSync(id) as Receipt;
  }

  /** Terminal statuses drop the hold view (§4.1). */
  finish(id: string, status: ReceiptStatus, patch: { summary?: string; meta?: Json; consumed?: boolean } = {}): void {
    const keepView = status === "held" || status === "approved";
    this.#db
      .prepare(
        `UPDATE tb_receipts SET status = ?, summary = COALESCE(?, summary), meta = COALESCE(?, meta),
          consumed = CASE WHEN ? THEN 1 ELSE consumed END, view = CASE WHEN ? THEN view ELSE NULL END WHERE id = ?`,
      )
      .run(status, patch.summary ?? null, patch.meta === undefined ? null : JSON.stringify(patch.meta), patch.consumed ? 1 : 0, keepView ? 1 : 0, id);
  }

  decide(id: string, status: "approved" | "denied", by: Receipt["decidedBy"], now: number): void {
    this.#db
      .prepare(
        `UPDATE tb_receipts SET status = ?, decided_at = ?, decided_by = ?, expires_at = ?,
          view = CASE WHEN ? = 'approved' THEN view ELSE NULL END WHERE id = ? AND status = 'held'`,
      )
      .run(status, now, by, status === "approved" ? now + APPROVAL_WINDOW_MS : null, status, id);
  }

  /** The approved, unconsumed hold for this exact call (§4.3), if still inside its retry window. */
  findApproved(callerId: string, op: string, inputDigest: string, now: number): Receipt | null {
    const r = this.#db
      .prepare(
        "SELECT * FROM tb_receipts WHERE caller_id = ? AND op = ? AND input_digest = ? AND status = 'approved' AND consumed = 0 AND expires_at > ? ORDER BY decided_at DESC LIMIT 1",
      )
      .get(callerId, op, inputDigest, now) as Row | undefined;
    return r ? toReceipt(r, false) : null;
  }

  /** Atomically claims an approved row for execution; false if someone else consumed it first. */
  consume(id: string): boolean {
    return Number(this.#db.prepare("UPDATE tb_receipts SET consumed = 1 WHERE id = ? AND status = 'approved' AND consumed = 0").run(id).changes) === 1;
  }

  byCall(callId: string): Receipt | null {
    const r = this.#db.prepare("SELECT * FROM tb_receipts WHERE call_id = ? ORDER BY created_at DESC LIMIT 1").get(callId) as Row | undefined;
    return r ? toReceipt(r, false) : null;
  }

  pendingCount(): number {
    return Number((this.#db.prepare("SELECT COUNT(*) AS n FROM tb_receipts WHERE status = 'held'").get() as Row).n);
  }

  /** Expires pending holds (→ denied by "expiry"), drops views of lapsed approvals, purges old rows and keys. */
  sweep(now: number): { expired: number } {
    const expired = Number(
      this.#db
        .prepare("UPDATE tb_receipts SET status = 'denied', decided_by = 'expiry', decided_at = ?, view = NULL WHERE status = 'held' AND expires_at <= ?")
        .run(now, now).changes,
    );
    this.#db.prepare("UPDATE tb_receipts SET view = NULL WHERE status = 'approved' AND view IS NOT NULL AND expires_at <= ?").run(now);
    this.#db.prepare("DELETE FROM tb_receipts WHERE created_at < ?").run(now - RECEIPT_RETENTION_MS);
    this.#db.prepare("DELETE FROM tb_idempotency WHERE expires_at <= ?").run(now);
    return { expired };
  }

  // ── idempotency (§4.4): key scope = (caller id, op, key) ──
  idemGet(callerId: string, op: string, key: string, now: number): IdempotencyRow | null {
    const r = this.#db
      .prepare("SELECT kind, input_digest, output, hold_id FROM tb_idempotency WHERE caller_id = ? AND op = ? AND key = ? AND expires_at > ?")
      .get(callerId, op, key, now) as Row | undefined;
    if (!r) return null;
    return r.kind === "held"
      ? { kind: "held", inputDigest: String(r.input_digest), holdId: String(r.hold_id) }
      : { kind: "result", inputDigest: String(r.input_digest), output: String(r.output) };
  }
  idemPut(callerId: string, op: string, key: string, inputDigest: string, v: { output: string } | { holdId: string }, now: number): void {
    this.#db
      .prepare(
        `INSERT INTO tb_idempotency (caller_id, op, key, input_digest, kind, output, hold_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (caller_id, op, key) DO UPDATE SET kind = excluded.kind, output = excluded.output, hold_id = excluded.hold_id`,
      )
      .run(
        callerId,
        op,
        key,
        inputDigest,
        "output" in v ? "result" : "held",
        "output" in v ? v.output : null,
        "holdId" in v ? v.holdId : null,
        now,
        now + IDEMPOTENCY_TTL_MS,
      );
  }
}
