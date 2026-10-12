// v0.1.11 (C62/C63, BSD-08): offline Portal Root Keys and root-signed key-set statements (CORE §4, CREDENTIALS §9.5).
// The ONE implementation of the trust rule the bridge and the SDK apply to every config / slice: the trusted Portal
// key set comes only from the newest root-signed statement; a K12 holder can sign documents but cannot change the set.


import type { KeySetStatementClaims, PortalKeysAudience, PortalRootChannel, PortalRootRef } from "@opt2-tealbrick/spec/credentials";
import { type Ed25519PublicJwk, KEYSET_REFUSAL, MAX_JWS_BYTES, PORTAL_ROOT_KEYS, type PortalKeyEntry } from "@opt2-tealbrick/spec/credentials";
import type { Ed25519KeyPair, KeySet, PinnedKeySet, Refusal, VerifiedKeySet } from "@opt2-tealbrick/spec/sdk";
import { type ExternalSigner, KEYSET_TYP, signCompact, verifySignedCompact } from "./jws.ts";
import { assertPublicJwk, keySetFrom, keySetFromPortalKeys, thumbprint } from "./keys.ts";

export type { KeySetStatementClaims, PinnedKeySet, PortalKeysAudience, PortalRootChannel, PortalRootRef, VerifiedKeySet };
export { KEYSET_REFUSAL, PORTAL_ROOT_KEYS };

export const KEYSET_ISSUER: PortalRootRef = "tb:portal-root";
export const KEYSET_AUDIENCE: PortalKeysAudience = "tb:portal-keys";
const MAX_KEYS = 8;
const CLAIMS = ["iss", "aud", "seq", "iat", "keys"];
const JWK_MEMBERS = new Set(["kty", "crv", "x", "kid", "alg", "use"]);
const STATUSES = new Set(["pending", "active", "retired"]);

/** Build-pinned root PUBLIC keys of `channel` (a copy of PORTAL_ROOT_KEYS[channel]). The channel is a build constant, never env. */
export function portalRootKeys(channel: PortalRootChannel): Ed25519PublicJwk[] {
  const keys = PORTAL_ROOT_KEYS[channel];
  if (!keys) throw new TypeError(`portalRootKeys: unknown channel ${String(channel)}`);
  return keys.map((k) => ({ ...k }));
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** Closed claim set + well-formed keys (CREDENTIALS §9.5); returns the failure reason or null. */
function claimsProblem(c: unknown): string | null {
  if (!isObj(c)) return "claims not an object";
  const extra = Object.keys(c).filter((k) => !CLAIMS.includes(k));
  if (extra.length || CLAIMS.some((k) => !Object.hasOwn(c, k))) return "claim set";
  if (c.iss !== KEYSET_ISSUER || c.aud !== KEYSET_AUDIENCE) return "iss/aud";
  if (!Number.isSafeInteger(c.seq) || (c.seq as number) < 1) return "seq";
  if (!Number.isSafeInteger(c.iat) || (c.iat as number) < 0) return "iat";
  const keys = c.keys;
  if (!Array.isArray(keys) || keys.length < 1 || keys.length > MAX_KEYS) return "keys count";
  const kids = new Set<string>();
  let active = 0;
  for (const e of keys) {
    if (!isObj(e) || Object.keys(e).length !== 2 || !STATUSES.has(e.status as string) || !isObj(e.jwk)) return "key entry";
    const jwk = e.jwk;
    if (Object.keys(jwk).some((k) => !JWK_MEMBERS.has(k))) return "jwk members";
    try {
      assertPublicJwk(jwk);
    } catch {
      return "jwk";
    }
    if ((jwk.alg !== undefined && jwk.alg !== "EdDSA") || (jwk.use !== undefined && jwk.use !== "sig")) return "jwk alg/use";
    const kid = thumbprint(jwk);
    if (jwk.kid !== undefined && jwk.kid !== kid) return "jwk kid";
    if (kids.has(kid)) return "duplicate key";
    kids.add(kid);
    if (e.status === "active") active++;
  }
  return active === 1 ? null : "exactly one active key";
}

const refuse = (code: string, reason: string): Refusal => ({ ok: false, code, reason });

/**
 * Offline ceremony tool only (CREDENTIALS §9.5): checks the closed claim set and signs a `tb-keyset+jws` with a root
 * key (key pair or external signer). Header `{alg: EdDSA, typ: tb-keyset+jws, kid}`, `kid` = the root's thumbprint.
 */
export async function signKeySetStatement(claims: KeySetStatementClaims, rootKey: Ed25519KeyPair | ExternalSigner): Promise<string> {
  const p = claimsProblem(claims);
  if (p) throw new TypeError(`signKeySetStatement: ${p}`);
  const ordered = { iss: claims.iss, aud: claims.aud, seq: claims.seq, iat: claims.iat, keys: claims.keys.map((e) => ({ jwk: e.jwk, status: e.status })) };
  return signCompact(KEYSET_TYP, ordered, rootKey, MAX_JWS_BYTES);
}

/**
 * Verifies a key-set statement: signed by one of `roots` (header kid = root thumbprint), closed claims, well-formed keys
 * (1–8, distinct, exactly one active), and newer than `pinned` (`seq` > pinned.seq; equal `seq` only when byte-identical).
 * Refusals: `keyset_invalid`, `keyset_rollback`.
 */
export function verifyKeySetStatement(jws: string, roots: readonly Ed25519PublicJwk[], pinned?: PinnedKeySet | null): VerifiedKeySet | Refusal {
  if (!Array.isArray(roots) || roots.length === 0) return refuse(KEYSET_REFUSAL.invalid, "no pinned roots");
  let rootSet: KeySet;
  try {
    rootSet = keySetFrom({ keys: [...roots] }, "tb:portal");
  } catch {
    return refuse(KEYSET_REFUSAL.invalid, "pinned roots malformed");
  }
  const sv = verifySignedCompact(jws, rootSet, KEYSET_TYP, MAX_JWS_BYTES);
  if (!sv.ok) return refuse(KEYSET_REFUSAL.invalid, `step ${sv.step}: ${sv.step === 3 ? "unknown root" : sv.reason}`);
  const problem = claimsProblem(sv.payload);
  if (problem) return refuse(KEYSET_REFUSAL.invalid, `claims: ${problem}`);
  const c = sv.payload as KeySetStatementClaims;
  if (pinned) {
    if (c.seq < pinned.seq) return refuse(KEYSET_REFUSAL.rollback, `seq ${c.seq} below pinned ${pinned.seq}`);
    if (c.seq === pinned.seq && jws !== pinned.kss) return refuse(KEYSET_REFUSAL.rollback, `seq ${c.seq} equals pinned with a different statement`);
  }
  const keys = keySetFromPortalKeys(c.keys);
  return { ok: true, keys, signers: { keys: keys.keys.filter((k) => k.status !== "retired") }, seq: c.seq, kss: jws };
}

/**
 * The ONE trust rule for a config / slice / enrolment-response body (CREDENTIALS §9.5, transition rule included):
 * - body carries `portalKeySet` → verifyKeySetStatement against `roots` and `pinned` (`changed` = newer than pinned);
 * - no `portalKeySet` and a statement is pinned → `keyset_missing` (no downgrade; also a bridge's re-enrolment);
 * - no pin and no `portalKeySet`, or no pin and no roots pinned for the build → `{ legacy: true }`: the caller keeps
 *   its pre-v0.1.11 key set (`portalKeys` / `TB_PORTAL_KEYS`) and logs a warning. Spec 0.1.11 only.
 * `opts.required` (spec 0.1.12, the fallback removed): a build that pins roots refuses a body without a statement even
 * when nothing is pinned yet (first enrolment, first slice) → `keyset_missing`.
 */
export function trustedPortalKeys(
  body: { portalKeySet?: unknown },
  pinned: PinnedKeySet | null,
  roots: readonly Ed25519PublicJwk[],
  opts: { required?: boolean } = {},
): (VerifiedKeySet & { legacy: false; changed: boolean }) | { ok: true; legacy: true; reason: string } | Refusal {
  const kss = isObj(body) ? body.portalKeySet : undefined;
  if (kss === undefined) {
    if (pinned) return refuse(KEYSET_REFUSAL.missing, `document without portalKeySet after seq ${pinned.seq} was pinned`);
    if (opts.required && roots.length > 0) return refuse(KEYSET_REFUSAL.missing, "document without portalKeySet (statement required, spec 0.1.12)");
    return { ok: true, legacy: true, reason: "document carries no portalKeySet (transition rule c)" };
  }
  if (typeof kss !== "string") return refuse(KEYSET_REFUSAL.invalid, "portalKeySet not a string");
  if (!pinned && roots.length === 0) return { ok: true, legacy: true, reason: "build pins no roots for its channel (transition rule c)" };
  const v = verifyKeySetStatement(kss, roots, pinned);
  if (!v.ok) return v;
  return { ...v, legacy: false, changed: !pinned || v.seq > pinned.seq };
}

// ── BSD-07: app addresses (BRIDGE §5.7) ──────────────────────────────────────
const RAILWAY_INTERNAL = /^http:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)*\.railway\.internal:[0-9]{1,5}$/;

/** Normalised origin of a bare http(s) origin string (no userinfo, path, query or fragment), or null. */
function bareOrigin(raw: string): string | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) return null;
  if (raw.endsWith("/") || /[?#@]/.test(raw)) return null;
  return u.origin;
}

/**
 * BSD-07: true iff `url` is `http://<name>.railway.internal:<port>` (port 1–65535), or — only when `ownInfra` — an
 * http(s) origin listed in `allowList` (the bridge's local TB_OWN_INFRA_ORIGINS, exact origin match after URL
 * normalisation; never set by Portal).
 */
export function isPrivateInternalUrl(url: string, opts: { ownInfra?: boolean; allowList?: readonly string[] } = {}): boolean {
  if (typeof url !== "string" || url.length > 512) return false;
  if (RAILWAY_INTERNAL.test(url)) {
    const port = Number(url.slice(url.lastIndexOf(":") + 1));
    return port >= 1 && port <= 65535;
  }
  if (opts.ownInfra !== true) return false;
  const origin = bareOrigin(url);
  if (!origin) return false;
  return (opts.allowList ?? []).some((entry) => typeof entry === "string" && bareOrigin(entry.trim()) === origin);
}
