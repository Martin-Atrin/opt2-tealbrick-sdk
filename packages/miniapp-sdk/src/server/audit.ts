// Audit log `tb_audit` (SDK-API §7.4): person and system actions only; agent calls are receipts.
import { SDK_AUDIT_ACTIONS, ulid } from "@opt2-tealbrick/manifest";
import type { AuditEntry, AuditLog, Json } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";
import type { RawDb, Row } from "./store.ts";

/** Keyset cursor over (created/at, id), newest first. */
export function encodeCursor(at: number, id: string): string {
  return Buffer.from(`${at}:${id}`, "utf8").toString("base64url");
}
export function decodeCursor(cursor: string | undefined): { at: number; id: string } | null {
  if (!cursor) return null;
  const raw = Buffer.from(cursor, "base64url").toString("utf8");
  const i = raw.indexOf(":");
  const at = Number(raw.slice(0, i));
  if (i < 1 || !Number.isSafeInteger(at)) throw new TbError("cursor_invalid", "cursor is not valid", 400);
  return { at, id: raw.slice(i + 1) };
}
export function clampLimit(limit: number | undefined, max = 200): number {
  return Math.max(1, Math.min(max, Math.trunc(limit ?? 50)));
}

export function createAuditLog(db: RawDb, appActions: readonly string[]): AuditLog {
  const allowed = new Set<string>([...SDK_AUDIT_ACTIONS, ...appActions]);
  return {
    async record(entry) {
      if (!allowed.has(entry.action)) throw new TbError("audit_action_unknown", `audit action not declared: ${entry.action}`, 500);
      db.prepare("INSERT INTO tb_audit (id, at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)").run(
        `aud_${ulid()}`,
        Date.now(),
        entry.actor,
        entry.action,
        entry.target,
        JSON.stringify(entry.detail ?? null),
      );
    },
    async list(q) {
      const limit = clampLimit(q.limit);
      const cur = decodeCursor(q.cursor);
      const where: string[] = [];
      const args: (string | number)[] = [];
      if (q.action) {
        where.push("action = ?");
        args.push(q.action);
      }
      if (cur) {
        where.push("(at < ? OR (at = ? AND id < ?))");
        args.push(cur.at, cur.at, cur.id);
      }
      const rows = db
        .prepare(`SELECT * FROM tb_audit ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY at DESC, id DESC LIMIT ?`)
        .all(...args, limit + 1) as Row[];
      const items: AuditEntry[] = rows.slice(0, limit).map((r) => ({
        id: String(r.id) as AuditEntry["id"],
        at: Number(r.at),
        actor: String(r.actor) as AuditEntry["actor"],
        action: String(r.action),
        target: r.target === null ? null : String(r.target),
        detail: JSON.parse(String(r.detail)) as Json,
      }));
      const last = items.at(-1);
      return { items, nextCursor: rows.length > limit && last ? encodeCursor(last.at, last.id) : null };
    },
  };
}
