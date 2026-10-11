// Secrets at rest for the instance (CREDENTIALS §9.1, SDK-API §9, I3): the KEK (env TB_KEK, else a generated file
// TB_DATA_DIR/tb/kek excluded from backups), the sealed instance key K8 and a text sealer. Sealing and key handling are
// `@opt2-tealbrick/manifest`; this module only decides where blobs live.
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type Ed25519KeyPair, exportPrivateKey, generateKeyPair, importKeyPair, type Kek, kekFromEnv, needsReseal, type SealedBlob, seal, sealAad, unseal } from "@opt2-tealbrick/manifest";
import { TbError } from "./errors.ts";

export interface Sealer {
  sealText(purpose: string, id: string, text: string): string;
  /** throws TbError `unseal_failed` (e.g. after a restore into a deployment with another KEK) */
  unsealText(purpose: string, id: string, blob: string): string;
  /** a blob sealed under TB_KEK_PREVIOUS (to reseal at boot) */
  stale(blob: string): boolean;
}

function writeSecretFile(path: string, data: string): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, data, { mode: 0o600 });
  renameSync(tmp, path);
}

/** TB_KEK, or (I3) a 32-byte KEK created on first boot in TB_DATA_DIR/tb/kek. */
export function resolveKeks(dataDir: string, kekEnv: string | null, previousEnv: string | null): { current: Kek; previous?: Kek } {
  let current: Kek;
  try {
    if (kekEnv !== null) current = kekFromEnv(kekEnv);
    else {
      const dir = join(dataDir, "tb");
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const file = join(dir, "kek");
      if (!existsSync(file)) writeSecretFile(file, randomBytes(32).toString("base64url"));
      current = kekFromEnv(readFileSync(file, "utf8").trim());
    }
  } catch (e) {
    if (e instanceof TbError) throw e;
    throw new TbError("env_invalid", "TB_KEK is not a usable 32-byte key", 500);
  }
  if (previousEnv === null) return { current };
  try {
    return { current, previous: kekFromEnv(previousEnv) };
  } catch {
    throw new TbError("env_invalid", "TB_KEK_PREVIOUS is not a usable 32-byte key", 500);
  }
}

export function createSealer(keks: { current: Kek; previous?: Kek }): Sealer {
  return {
    sealText(purpose, id, text) {
      return JSON.stringify(seal(new TextEncoder().encode(text), keks.current, sealAad(purpose, id)));
    },
    unsealText(purpose, id, blob) {
      try {
        return new TextDecoder().decode(unseal(JSON.parse(blob) as SealedBlob, keks, sealAad(purpose, id)));
      } catch {
        throw new TbError("unseal_failed", "sealed value cannot be opened with this deployment's KEK", 500);
      }
    },
    stale(blob) {
      try {
        return needsReseal(JSON.parse(blob) as SealedBlob, keks.current);
      } catch {
        return false;
      }
    },
  };
}

const INSTANCE_KEY_PURPOSE = "instance-key";

/** The instance key K8: generated at first boot, sealed in TB_DATA_DIR/tb/instance-key, never leaves the instance. */
export async function loadInstanceKey(dataDir: string, sealer: Sealer): Promise<Ed25519KeyPair> {
  const dir = join(dataDir, "tb");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = join(dir, "instance-key");
  if (existsSync(file)) {
    const blob = readFileSync(file, "utf8");
    const pkcs8 = Buffer.from(sealer.unsealText(INSTANCE_KEY_PURPOSE, "self", blob), "base64url");
    if (sealer.stale(blob)) writeSecretFile(file, sealer.sealText(INSTANCE_KEY_PURPOSE, "self", pkcs8.toString("base64url")));
    return importKeyPair(pkcs8);
  }
  const pair = await generateKeyPair({ extractable: true });
  const pkcs8 = Buffer.from(await exportPrivateKey(pair)).toString("base64url");
  writeSecretFile(file, sealer.sealText(INSTANCE_KEY_PURPOSE, "self", pkcs8));
  return importKeyPair(Buffer.from(pkcs8, "base64url"));
}
