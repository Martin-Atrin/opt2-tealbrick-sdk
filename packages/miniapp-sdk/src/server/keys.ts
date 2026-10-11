// Keys (SDK-API §8, CORE §10, C2): app-own value (tb_keys, sealed under TB_KEK) wins over the workspace default
// fetched from the bridge (`GET /tb/v1/keys/<name>` with TB-Assert). Defaults are cached in memory until `keysRev`
// changes or the slice shows a pause. Values are never logged, returned to persons, or compared in clear.
import { BRIDGE_INTERNAL_PATHS, type KeyFetchResponse } from "@opt2-tealbrick/spec/bridge";
import type { Condition, KeyRequirement, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { AuditLog, KeyApi, KeyStatus, Logger, PersonPrincipal } from "@opt2-tealbrick/spec/sdk";
import type { BridgeClient } from "./bridge-client.ts";
import { errorFrom } from "./bridge-client.ts";
import { TbError } from "./errors.ts";
import type { SecretRegistry } from "./log.ts";
import type { Sealer } from "./secrets.ts";
import type { RawDb, Row } from "./store.ts";

const KEY_PURPOSE = "app-key";
const MAX_KEY_BYTES = 16 * 1024;

/**
 * `when` on a key: settings reach the app only as env (`runtime.env[].setting`, C16 S6), so a condition is evaluated
 * against the env var that carries the setting. SPEC-GAP: a setting no env entry carries cannot be evaluated by the
 * app; the condition then counts as true (the key is treated as needed).
 */
export function conditionHolds(when: Condition | undefined, manifest: Manifest, env: Record<string, string | undefined>): boolean {
  if (!when) return true;
  for (const [setting, expected] of Object.entries(when)) {
    const entry = manifest.runtime.env?.find((e) => "setting" in e && e.setting === setting);
    if (!entry) continue;
    const raw = env[entry.name];
    if (raw === undefined) continue;
    const ok = (Array.isArray(expected) ? expected : [expected]).some((v) => String(v) === raw);
    if (!ok) return false;
  }
  return true;
}

export interface KeysInternals extends KeyApi {
  set(principal: PersonPrincipal, name: string, value: string): Promise<void>;
  remove(principal: PersonPrincipal, name: string): Promise<void>;
  /** status long-poll returned a new keysRev */
  onKeysRev(rev: number): Promise<void>;
  /** slice shows a pause: drop cached default values */
  dropCache(): void;
  /** prefetch workspace defaults so health/readiness know presence */
  refresh(): Promise<void>;
  needsKeys(): boolean;
  keysRev(): number;
}

export function createKeys(opts: {
  db: RawDb;
  manifest: Manifest;
  env: Record<string, string | undefined>;
  sealer: Sealer;
  secrets: SecretRegistry;
  audit: AuditLog;
  log: Logger;
  bridge: () => BridgeClient | null;
  emit: (names: string[]) => Promise<void>;
}): KeysInternals {
  const { db, manifest, sealer, secrets } = opts;
  const declared = new Map<string, KeyRequirement>((manifest.settings?.keys ?? []).filter((k) => k.usedBy.includes("app")).map((k) => [k.name, k]));
  const cache = new Map<string, string | null>();
  const listeners = new Set<(names: string[]) => void>();
  let rev = 0;

  const req = (name: string): KeyRequirement => {
    const k = declared.get(name);
    if (!k) throw new TbError("key_undeclared", `key not declared in settings.keys with usedBy "app": ${name}`, 500);
    return k;
  };
  const appOwn = (name: string): string | null => {
    const row = db.prepare("SELECT sealed FROM tb_keys WHERE name = ?").get(name) as Row | undefined;
    if (!row) return null;
    try {
      return sealer.unsealText(KEY_PURPOSE, name, String(row.sealed));
    } catch {
      // §7.3: a restore into a deployment with another KEK drops app-own keys (status needs_keys)
      return null;
    }
  };
  const fetchDefault = async (name: string): Promise<string | null> => {
    if (cache.has(name)) return cache.get(name) ?? null;
    const client = opts.bridge();
    if (!client) return null;
    const r = await client.request("GET", BRIDGE_INTERNAL_PATHS.keys.replace("{name}", encodeURIComponent(name)));
    if (r.status === 404) {
      cache.set(name, null);
      return null;
    }
    if (r.status !== 200) throw errorFrom(r, "key_unavailable");
    const body = r.body as KeyFetchResponse;
    if (typeof body?.value !== "string") throw new TbError("key_unavailable", "bridge key answer malformed", 502);
    secrets.add(body.value);
    cache.set(name, body.value);
    return body.value;
  };
  const notify = async (names: string[]) => {
    for (const cb of listeners) {
      try {
        cb(names);
      } catch (e) {
        opts.log.warn("onKeysChanged listener failed", { error: e instanceof Error ? e.message : "unknown" });
      }
    }
    await opts.emit(names);
  };
  const present = (k: KeyRequirement): { present: boolean; source: KeyStatus["source"] } => {
    if (db.prepare("SELECT 1 FROM tb_keys WHERE name = ?").get(k.name)) return { present: true, source: "app_own" };
    if (k.source === "account_default" && typeof cache.get(k.name) === "string") return { present: true, source: "account_default" };
    return { present: false, source: null };
  };

  return {
    async getKey(name) {
      const k = req(name);
      const own = appOwn(name);
      if (own !== null) {
        secrets.add(own);
        return own;
      }
      return k.source === "account_default" ? fetchDefault(name) : null;
    },
    onKeysChanged(cb) {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    async status() {
      return [...declared.values()].map((k) => ({ name: k.name, required: k.required && conditionHolds(k.when, manifest, opts.env), ...present(k) }));
    },
    async set(principal, name, value) {
      if (principal?.type !== "person") throw new TbError("session_required", "only the owner can set keys", 403);
      req(name);
      if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > MAX_KEY_BYTES) throw new TbError("key_invalid", "key value must be 1..16384 bytes", 400);
      db.prepare("INSERT INTO tb_keys (name, sealed, updated_at) VALUES (?, ?, ?) ON CONFLICT (name) DO UPDATE SET sealed = excluded.sealed, updated_at = excluded.updated_at").run(
        name,
        sealer.sealText(KEY_PURPOSE, name, value),
        Date.now(),
      );
      secrets.add(value);
      await opts.audit.record({ actor: principal.id, action: "key.set", target: name, detail: { name } });
      await notify([name]);
    },
    async remove(principal, name) {
      if (principal?.type !== "person") throw new TbError("session_required", "only the owner can delete keys", 403);
      req(name);
      db.prepare("DELETE FROM tb_keys WHERE name = ?").run(name);
      await opts.audit.record({ actor: principal.id, action: "key.delete", target: name, detail: { name } });
      await notify([name]);
    },
    async onKeysRev(next) {
      if (next === rev) return;
      rev = next;
      cache.clear();
      await this.refresh();
      await notify([...declared.values()].filter((k) => k.source === "account_default").map((k) => k.name));
    },
    dropCache() {
      cache.clear();
    },
    async refresh() {
      for (const k of declared.values()) {
        if (k.source !== "account_default") continue;
        try {
          await fetchDefault(k.name);
        } catch (e) {
          opts.log.debug("key prefetch failed", { name: k.name, code: e instanceof TbError ? e.code : "error" });
        }
      }
    },
    needsKeys() {
      return [...declared.values()].some((k) => k.required && conditionHolds(k.when, manifest, opts.env) && !present(k).present);
    },
    keysRev: () => rev,
  };
}
