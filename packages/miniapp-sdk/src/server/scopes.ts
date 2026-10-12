// Scope store (SDK-API §7.2): the app is the authority for scope assignments (CORE §6). Types and access levels
// come from manifest `scopes[]`; `defaultGrants` (C1) are applied once per (caller, type) on first sight, and (v0.1.13)
// the `shared` default also when an instance becomes shared later, for every caller seen before.
import type { AgentId } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, Manifest, Scope } from "@opt2-tealbrick/spec/manifest";
import type { AuditLog, PersonPrincipal, ScopeAccessView, ScopeGrantRow, ScopeInstance, ScopeStore, SliceAgent } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";
import { metaGet, metaSet, type RawDb, type Row, tx } from "./store.ts";

const SUMMARY_MAX = 80;

function toRow(r: Row): ScopeGrantRow {
  return { agent: String(r.agent) as AgentId, type: String(r.type), instanceId: String(r.instance_id), access: String(r.access) };
}
function toInstance(r: Row): ScopeInstance {
  return { type: String(r.type), id: String(r.id), label: String(r.label), shared: Number(r.shared) === 1 };
}

export interface ScopeStoreInternals extends ScopeStore {
  /** CRUD set of an access level (manifest `access[].crud`); [] for unknown levels. */
  crudOf(type: string, level: string): CrudAction[];
  /** Monotonic counter reported as `AppStatus.scopesRev`. */
  rev(): number;
  /** Resolved access for a call: the targeted instance, or the best access when the op spans instances. */
  resolve(caller: string, type: string, instanceId: string | null): { level: string; crud: CrudAction[]; id: string | null } | null;
  /** ScopeAccessView for an agent/app caller (person callers see everything). */
  view(caller: string | null, access: ScopeAccessView["access"]): ScopeAccessView;
  /** Applies defaults for a caller that has no slice entry (companion app callers). */
  applyDefaultsFor(caller: string, name: string): void;
}

export function createScopeStore(db: RawDb, manifest: Manifest, audit: AuditLog, onChange: () => void): ScopeStoreInternals {
  const scopes = new Map<string, Scope>((manifest.scopes ?? []).map((s) => [s.type, s]));
  const scopeOf = (type: string): Scope => {
    const s = scopes.get(type);
    if (!s) throw new TbError("scope_type_unknown", `scope type not declared: ${type}`, 400);
    return s;
  };
  const crudOf = (type: string, level: string): CrudAction[] => [...(scopes.get(type)?.access.find((a) => a.id === level)?.crud ?? [])];
  const bump = () => {
    metaSet(db, "scopes_rev", (metaGet<number>(db, "scopes_rev") ?? 0) + 1);
    onChange();
  };
  const rank = (type: string, level: string): number => {
    const s = scopes.get(type);
    const i = s?.access.findIndex((a) => a.id === level) ?? -1;
    return crudOf(type, level).length * 1000 + i;
  };
  const rowsOf = (caller: string, type: string): ScopeGrantRow[] =>
    (db.prepare("SELECT * FROM tb_scopes WHERE agent = ? AND type = ?").all(caller, type) as Row[]).map(toRow);
  const bestOf = (caller: string, type: string): ScopeGrantRow | null =>
    rowsOf(caller, type).reduce<ScopeGrantRow | null>((b, r) => (b === null || rank(type, r.access) > rank(type, b.access) ? r : b), null);
  const accessOf = (caller: string, type: string, id: string): ScopeGrantRow | null => {
    const r = db.prepare("SELECT * FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").get(caller, type, id) as Row | undefined;
    return r ? toRow(r) : null;
  };

  /**
   * v0.1.13 (Kanban QA S2): an instance that BECOMES shared (created shared, or switched from not shared) gets the
   * `shared` default grant for every caller whose defaults were already applied (the directory seen so far); callers
   * seen later get it on first sight as before. INSERT OR IGNORE: an existing row (an owner edit) always wins.
   */
  const shareWithSeen = (s: Scope, id: string): boolean => {
    const g = s.defaultGrants.find((x) => x.kind === "shared");
    if (!g) return false;
    const seen = (db.prepare("SELECT agent FROM tb_scope_defaults WHERE type = ?").all(s.type) as Row[]).map((r) => String(r.agent));
    let n = 0;
    const grant = db.prepare("INSERT OR IGNORE INTO tb_scopes (agent, type, instance_id, access) VALUES (?, ?, ?, ?)");
    for (const agent of seen) n += Number(grant.run(agent, s.type, id, g.access).changes ?? 0);
    return n > 0;
  };

  const createInstance = (type: string, id: string, label: string, opts: { shared?: boolean; ownerAgent?: string } = {}): ScopeInstance => {
    const s = scopeOf(type);
    if (!id || id.length > 128) throw new TbError("scope_instance_invalid", "scope instance id must be 1..128 chars", 400);
    const before = db.prepare("SELECT shared FROM tb_scope_instances WHERE type = ? AND id = ?").get(type, id) as Row | undefined;
    const becomesShared = opts.shared === true && (before === undefined || Number(before.shared) !== 1);
    db.prepare(
      `INSERT INTO tb_scope_instances (type, id, label, shared, owner_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (type, id) DO UPDATE SET label = excluded.label, shared = excluded.shared, owner_agent = COALESCE(excluded.owner_agent, owner_agent)`,
    ).run(type, id, label, opts.shared ? 1 : 0, opts.ownerAgent ?? null, Date.now());
    if (becomesShared && shareWithSeen(s, id)) bump();
    return toInstance(db.prepare("SELECT * FROM tb_scope_instances WHERE type = ? AND id = ?").get(type, id) as Row);
  };

  const applyDefaultsFor = (caller: string, name: string): void => {
    let changed = false;
    tx(db, () => {
      for (const s of scopes.values()) {
        if (db.prepare("SELECT 1 FROM tb_scope_defaults WHERE agent = ? AND type = ?").get(caller, s.type)) continue;
        const grant = db.prepare("INSERT OR IGNORE INTO tb_scopes (agent, type, instance_id, access) VALUES (?, ?, ?, ?)");
        for (const g of s.defaultGrants) {
          let ids: string[];
          if (g.kind === "own") {
            ids = (db.prepare("SELECT id FROM tb_scope_instances WHERE type = ? AND owner_agent = ?").all(s.type, caller) as Row[]).map((r) => String(r.id));
            // MANIFEST §6: `own` = the caller's own instance, created if the app has not created one.
            if (ids.length === 0) ids = [createInstance(s.type, caller, name, { ownerAgent: caller }).id];
          } else if (g.kind === "shared") {
            ids = (db.prepare("SELECT id FROM tb_scope_instances WHERE type = ? AND shared = 1").all(s.type) as Row[]).map((r) => String(r.id));
          } else {
            ids = (db.prepare("SELECT id FROM tb_scope_instances WHERE type = ?").all(s.type) as Row[]).map((r) => String(r.id));
          }
          for (const id of ids) grant.run(caller, s.type, id, g.access);
        }
        db.prepare("INSERT INTO tb_scope_defaults (agent, type, applied_at) VALUES (?, ?, ?)").run(caller, s.type, Date.now());
        changed = true;
      }
    });
    if (changed) bump();
  };

  const store: ScopeStoreInternals = {
    instances: {
      async create(type, id, label, opts) {
        return createInstance(type, id, label, opts);
      },
      async list(type) {
        scopeOf(type);
        return (db.prepare("SELECT * FROM tb_scope_instances WHERE type = ? ORDER BY created_at, id").all(type) as Row[]).map(toInstance);
      },
    },
    async access(agent, type, instanceId) {
      return accessOf(agent, type, instanceId);
    },
    async best(agent, type) {
      return bestOf(agent, type);
    },
    async list(agent) {
      return (db.prepare("SELECT * FROM tb_scopes WHERE agent = ? ORDER BY type, instance_id").all(agent) as Row[]).map(toRow);
    },
    async set(principal: PersonPrincipal, agent, type, instanceId, access) {
      if (principal?.type !== "person") throw new TbError("session_required", "only the owner can set scope access", 403);
      const s = scopeOf(type);
      if (access !== null && !s.access.some((a) => a.id === access)) throw new TbError("access_level_unknown", `access level not declared: ${access}`, 400);
      if (!db.prepare("SELECT 1 FROM tb_scope_instances WHERE type = ? AND id = ?").get(type, instanceId))
        throw new TbError("scope_instance_unknown", "scope instance does not exist", 404);
      if (access === null) db.prepare("DELETE FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").run(agent, type, instanceId);
      else
        db.prepare(
          "INSERT INTO tb_scopes (agent, type, instance_id, access) VALUES (?, ?, ?, ?) ON CONFLICT (agent, type, instance_id) DO UPDATE SET access = excluded.access",
        ).run(agent, type, instanceId, access);
      await audit.record({ actor: principal.id, action: "scope.set", target: agent, detail: { type, instance: instanceId, access } });
      bump();
    },
    async applyDefaults(agent: SliceAgent) {
      applyDefaultsFor(agent.id, agent.name);
    },
    async summary(agent) {
      const parts: string[] = [];
      for (const s of scopes.values()) {
        const rows = rowsOf(agent, s.type);
        if (rows.length === 0) continue;
        const text = s.summaryTemplate.replace(/\{(count|label|labelPlural|access\.([a-z0-9_]+))\}/g, (_m, v: string, level?: string) => {
          if (v === "count") return String(rows.length);
          if (v === "label") return s.label;
          if (v === "labelPlural") return s.labelPlural;
          return String(rows.filter((r) => r.access === level).length);
        });
        parts.push(text);
      }
      const out = parts.join(" · ");
      return out.length <= SUMMARY_MAX ? out : `${out.slice(0, SUMMARY_MAX - 1)}…`;
    },
    crudOf,
    rev: () => metaGet<number>(db, "scopes_rev") ?? 0,
    resolve(caller, type, instanceId) {
      const row = instanceId === null ? bestOf(caller, type) : accessOf(caller, type, instanceId);
      return row ? { level: row.access, crud: crudOf(type, row.access), id: instanceId } : null;
    },
    view(caller, access) {
      const ids = async (type: string, want: (c: CrudAction[]) => boolean): Promise<string[]> => {
        scopeOf(type);
        if (caller === null) return (await store.instances.list(type)).map((i) => i.id);
        return rowsOf(caller, type)
          .filter((r) => want(crudOf(type, r.access)))
          .map((r) => r.instanceId);
      };
      return {
        access,
        readable: (type) => ids(type, (c) => c.includes("read")),
        writable: (type) => ids(type, (c) => c.some((a) => a !== "read")),
        async can(type, id, crud) {
          scopeOf(type);
          if (caller === null) return true;
          const row = accessOf(caller, type, id);
          return row !== null && crudOf(type, row.access).includes(crud);
        },
      };
    },
    applyDefaultsFor,
  };
  return store;
}
