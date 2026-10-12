// Ed25519 keys, RFC 7638 thumbprints and trusted key sets (CORE §3–§4, CREDENTIALS §9.2–§9.3).
import { createHash, createPrivateKey, createPublicKey, type KeyObject, webcrypto } from "node:crypto";
import type { AgentRef, BridgeRef, Ed25519PublicJwk, InstanceRef, PersonRef, PortalKeyEntry, PortalRef, ReleasesRef } from "@opt2-tealbrick/spec/credentials";
import type { Ed25519KeyPair, KeySet } from "@opt2-tealbrick/spec/sdk";

export type { Ed25519KeyPair, KeySet };

type KeyEntry = KeySet["keys"][number];
type KeyStatus = KeyEntry["status"];

const subtle = webcrypto.subtle;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/;

/** Throws unless `jwk` is an Ed25519 public JWK (`kty OKP`, `crv Ed25519`, 32-byte `x`, no private `d`). */
export function assertPublicJwk(jwk: unknown): asserts jwk is Ed25519PublicJwk {
  const j = jwk as Record<string, unknown> | null;
  if (!j || typeof j !== "object" || j.kty !== "OKP" || j.crv !== "Ed25519" || typeof j.x !== "string" || !B64URL_32.test(j.x) || "d" in j) {
    throw new TypeError("not an Ed25519 public JWK");
  }
}

/** RFC 7638 SHA-256 thumbprint of `{crv,kty,x}`, base64url (43 chars) = `kid`. */
export function thumbprint(jwk: Ed25519PublicJwk): string {
  assertPublicJwk(jwk);
  // RFC 7638: required members only, lexicographic order, no whitespace
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`;
  return createHash("sha256").update(canonical).digest("base64url");
}

function publicPart(jwk: { x?: string }): Ed25519PublicJwk {
  const pub = { kty: "OKP", crv: "Ed25519", x: jwk.x } as Ed25519PublicJwk;
  assertPublicJwk(pub);
  return pub;
}

/**
 * New Ed25519 key pair. The private key is a WebCrypto `CryptoKey`, non-extractable by default;
 * pass `extractable: true` only when the holder must persist it sealed (`exportPrivateKey`).
 */
export async function generateKeyPair(opts: { extractable?: boolean } = {}): Promise<Ed25519KeyPair> {
  const pair = (await subtle.generateKey({ name: "Ed25519" }, opts.extractable === true, ["sign", "verify"])) as unknown as webcrypto.CryptoKeyPair;
  const publicJwk = publicPart(await subtle.exportKey("jwk", pair.publicKey));
  return { publicJwk, privateKey: pair.privateKey as CryptoKey, kid: thumbprint(publicJwk) };
}

/** PKCS#8 DER of an extractable private key, for sealing (`seal`) at rest. Throws for non-extractable keys. */
export async function exportPrivateKey(pair: Ed25519KeyPair): Promise<Uint8Array> {
  if (!pair.privateKey.extractable) throw new TypeError("exportPrivateKey: key is not extractable");
  return new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey as webcrypto.CryptoKey));
}

/** Rebuilds a key pair from PKCS#8 DER (e.g. after `unseal`). The imported key is non-extractable by default. */
export async function importKeyPair(pkcs8: Uint8Array, opts: { extractable?: boolean } = {}): Promise<Ed25519KeyPair> {
  const der = Buffer.from(pkcs8);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  if (priv.asymmetricKeyType !== "ed25519") throw new TypeError("importKeyPair: not an Ed25519 key");
  const publicJwk = publicPart(createPublicKey(priv).export({ format: "jwk" }));
  const privateKey = await subtle.importKey("pkcs8", der, { name: "Ed25519" }, opts.extractable === true, ["sign"]);
  return { publicJwk, privateKey: privateKey as CryptoKey, kid: thumbprint(publicJwk) };
}

// SPEC-GAP: types/sdk.ts types KeySet `issuer` as Portal | Bridge | Instance only; agent assertions (connection
// `publicKey`) and standalone owner assertions (`ownerKeys`) need agent / person issuers, so the helpers accept them.
export type KeyIssuer = PortalRef | BridgeRef | InstanceRef | AgentRef | PersonRef | ReleasesRef;

function entry(jwk: Ed25519PublicJwk, status: KeyStatus, issuer: KeyIssuer): KeyEntry {
  assertPublicJwk(jwk);
  return { jwk: publicPart(jwk), status, issuer: issuer as KeyEntry["issuer"] };
}

/** Key set from a JWKS (bootstrap `TB_PORTAL_KEYS`, slice `bridge.keys`, connection key, own key); every key `active`. */
export function keySetFrom(jwks: { keys: Ed25519PublicJwk[] }, issuer: KeyIssuer): KeySet {
  return { keys: jwks.keys.map((k) => entry(k, "active", issuer)) };
}

/** Key set from a config/slice `portalKeys` list, keeping each key's status (CREDENTIALS §5.1). */
export function keySetFromPortalKeys(entries: readonly PortalKeyEntry[], issuer: PortalRef | BridgeRef = "tb:portal"): KeySet {
  return { keys: entries.map((e) => entry(e.jwk, e.status, issuer)) };
}

/**
 * @deprecated v0.1.11 (C62/C63): NOT a trust path any more — the trusted Portal key set comes only from a root-signed
 * key-set statement (`trustedPortalKeys`, keyset.ts). Kept exported for one minor solely for the transition rule (c) of
 * CREDENTIALS §9.5 (a verifier that has pinned no statement and receives documents without `portalKeySet`; used by
 * miniapp-sdk's TrustState legacy path). Removed in v0.2.
 *
 * Pre-v0.1.11 CORE §4 trust rule. `announced` is the full key list of a document (config / slice `portalKeys`) whose signature was
 * verified with key `announcedBy.kid`. Only when that key is already in `trusted` does the document's list take effect,
 * and it then REPLACES the trusted set: new keys are added, keys the document dropped (rotation end, compromise,
 * standalone `portalKeys: []`) are no longer trusted, retired keys stay verifiable while the document still lists them.
 * Otherwise `trusted` is returned unchanged. Any status may verify: a `pending` key at the verifier is the normal state
 * at the moment Portal switches it to `active` (CREDENTIALS §9.2).
 */
export function keySetAnnounce(trusted: KeySet, announced: KeySet, announcedBy: { kid: string }): KeySet {
  if (!findKey(trusted, announcedBy.kid)) return trusted;
  return { keys: announced.keys.map((k) => entry(k.jwk, k.status, k.issuer)) };
}

/** Key set entry whose thumbprint equals `kid`, or undefined. */
export function findKey(keys: KeySet, kid: string): KeyEntry | undefined {
  return keys.keys.find((k) => kidOf(k.jwk) === kid);
}

const kidCache = new WeakMap<object, string>();
function kidOf(jwk: Ed25519PublicJwk): string {
  let kid = kidCache.get(jwk);
  if (kid === undefined) {
    kid = thumbprint(jwk);
    kidCache.set(jwk, kid);
  }
  return kid;
}

const keyObjectCache = new Map<string, KeyObject>();
/** node:crypto public KeyObject for synchronous verification (cache bounded by trusted keys only). */
export function publicKeyObject(jwk: Ed25519PublicJwk): KeyObject {
  let ko = keyObjectCache.get(jwk.x);
  if (!ko) {
    ko = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
    if (keyObjectCache.size > 1024) keyObjectCache.clear();
    keyObjectCache.set(jwk.x, ko);
  }
  return ko;
}
