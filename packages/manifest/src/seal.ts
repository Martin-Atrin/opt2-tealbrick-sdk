// Sealing at rest (CREDENTIALS §9.1): AES-256-GCM under a KEK from the service env; one format for Core, bridge, apps.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import type { SealedBlob } from "@opt2-tealbrick/spec/credentials";

export type { SealedBlob };
/** A key-encryption key: 32 bytes + its id (recorded in each blob's `kek`). */
export interface Kek {
  id: string;
  key: Uint8Array;
}

const B64URL = /^[A-Za-z0-9_-]+$/;

/** AAD for a sealed record (CREDENTIALS §9.1): `tb:seal:<purpose>:<record id>`. */
export function sealAad(purpose: string, recordId: string): string {
  return `tb:seal:${purpose}:${recordId}`;
}

function checkKek(kek: Kek): void {
  if (typeof kek.id !== "string" || kek.id.length === 0 || kek.key.length !== 32) throw new TypeError("seal: KEK must be 32 bytes with an id");
}

/** Seals `plaintext` under `kek`, bound to `aad` (a blob cannot be moved to another record). */
export function seal(plaintext: Uint8Array, kek: Kek, aad: string): SealedBlob {
  checkKek(kek);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", kek.key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { v: 1, alg: "A256GCM", kek: kek.id, iv: iv.toString("base64url"), ct: ct.toString("base64url"), tag: cipher.getAuthTag().toString("base64url") };
}

/**
 * Opens a blob with the KEK its `kek` id names: `current`, or `previous` during KEK rotation (`TB_KEK_PREVIOUS`; the
 * service reseals every blob on start). Throws `Error("unseal_failed")` on unknown KEK, malformed blob, wrong AAD or tampering.
 */
export function unseal(blob: SealedBlob, keks: { current: Kek; previous?: Kek }, aad: string): Uint8Array {
  const fail = () => new Error("unseal_failed");
  const b = blob as unknown as Record<string, unknown> | null;
  const b64 = (v: unknown, empty: boolean) => typeof v === "string" && ((empty && v === "") || B64URL.test(v));
  if (b?.v !== 1 || b.alg !== "A256GCM" || typeof b.kek !== "string" || !b64(b.iv, false) || !b64(b.tag, false) || !b64(b.ct, true)) throw fail();
  const kek = keks.current.id === blob.kek ? keks.current : keks.previous?.id === blob.kek ? keks.previous : undefined;
  if (!kek) throw fail();
  checkKek(kek);
  const iv = Buffer.from(blob.iv, "base64url");
  const tag = Buffer.from(blob.tag, "base64url");
  if (iv.length !== 12 || tag.length !== 16) throw fail();
  try {
    const d = createDecipheriv("aes-256-gcm", kek.key, iv, { authTagLength: 16 });
    d.setAAD(Buffer.from(aad, "utf8"));
    d.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([d.update(Buffer.from(blob.ct, "base64url")), d.final()]));
  } catch {
    throw fail();
  }
}

/** True when `blob` is sealed under a KEK other than `current` (reseal it on start, CREDENTIALS §9.1). */
export function needsReseal(blob: SealedBlob, current: Kek): boolean {
  return blob.kek !== current.id;
}

/**
 * KEK from an env value (`TB_KEK`, `TB_KEK_PREVIOUS`). Accepts 32 bytes as base64url (43 chars) or hex (64 chars);
 * any other value of ≥ 32 characters (e.g. a provider-generated random string) is reduced with SHA-256.
 * `id` defaults to a non-secret fingerprint of the key (Core passes `TB_KEK_ID`).
 * SPEC-GAP: CREDENTIALS §9.1 fixes "32 random bytes" but not the env encoding nor a KEK id for bridge/apps.
 */
export function kekFromEnv(value: string, id?: string): Kek {
  let key: Buffer;
  if (/^[A-Za-z0-9_-]{43}$/.test(value)) key = Buffer.from(value, "base64url");
  else if (/^[0-9a-fA-F]{64}$/.test(value)) key = Buffer.from(value, "hex");
  else if (value.length >= 32) key = createHash("sha256").update(value, "utf8").digest();
  else throw new TypeError("kekFromEnv: KEK too short");
  const fp = createHash("sha256").update("tb:kek-id:").update(key).digest("hex").slice(0, 16);
  return { id: id ?? `kek_${fp}`, key: new Uint8Array(key) };
}
