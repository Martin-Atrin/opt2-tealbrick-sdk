// App secrets `ctx.secrets` (Coordinator C31): THE app-secret mechanism. Values are sealed under TB_KEK with the
// manifest package seal/unseal (AAD `tb:seal:app-secret:<name>`), stored in `tb_secrets`, excluded from export and
// included (still sealed) in backups. Never logged; values read back are added to the logger's redaction set.
import { TbError } from "./errors.ts";
import type { SecretRegistry } from "./log.ts";
import type { Sealer } from "./secrets.ts";
import type { RawDb, Row } from "./store.ts";

export interface AppSecrets {
  put(name: string, value: string): Promise<void>;
  /** null when absent or not openable with this deployment's KEK (e.g. restored into another deployment) */
  get(name: string): Promise<string | null>;
  delete(name: string): Promise<void>;
}

const PURPOSE = "app-secret";
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const MAX_VALUE_BYTES = 64 * 1024;

export function createAppSecrets(db: RawDb, sealer: Sealer, registry: SecretRegistry): AppSecrets & { reseal(): void } {
  const check = (name: string) => {
    if (typeof name !== "string" || !NAME_RE.test(name)) throw new TbError("secret_name_invalid", "secret name must be 1..128 chars of [A-Za-z0-9._:/-]", 500);
  };
  return {
    async put(name, value) {
      check(name);
      if (typeof value !== "string" || Buffer.byteLength(value) > MAX_VALUE_BYTES) throw new TbError("secret_value_invalid", "secret value must be a string ≤ 64 KB", 500);
      db.prepare("INSERT INTO tb_secrets (name, sealed, updated_at) VALUES (?, ?, ?) ON CONFLICT (name) DO UPDATE SET sealed = excluded.sealed, updated_at = excluded.updated_at").run(
        name,
        sealer.sealText(PURPOSE, name, value),
        Date.now(),
      );
      registry.add(value);
    },
    async get(name) {
      check(name);
      const r = db.prepare("SELECT sealed FROM tb_secrets WHERE name = ?").get(name) as Row | undefined;
      if (!r) return null;
      try {
        const v = sealer.unsealText(PURPOSE, name, String(r.sealed));
        registry.add(v);
        return v;
      } catch {
        return null;
      }
    },
    async delete(name) {
      check(name);
      db.prepare("DELETE FROM tb_secrets WHERE name = ?").run(name);
    },
    /** KEK rotation (CREDENTIALS §9.1): reseal blobs sealed under TB_KEK_PREVIOUS. */
    reseal() {
      for (const r of db.prepare("SELECT name, sealed FROM tb_secrets").all() as Row[]) {
        if (!sealer.stale(String(r.sealed))) continue;
        const name = String(r.name);
        db.prepare("UPDATE tb_secrets SET sealed = ? WHERE name = ?").run(sealer.sealText(PURPOSE, name, sealer.unsealText(PURPOSE, name, String(r.sealed))), name);
      }
    },
  };
}
