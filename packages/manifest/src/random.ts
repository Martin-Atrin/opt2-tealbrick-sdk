// Identifiers and opaque values (CORE §1, CREDENTIALS §3). The ONE source of randomness besides key generation.
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { OpaquePrefix, Sha256Digest, Ulid } from "@opt2-tealbrick/spec/credentials";
import { sha256Bytes } from "./jcs.ts";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** 26-char Crockford base32, upper case; first char ≤ 7 (48-bit time). */
export const ULID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

let lastTime = -1;
const lastRand = new Uint8Array(10);

/**
 * ULID (26 chars). Monotonic within one process: a call in the same millisecond (or after the clock moved back)
 * increments the previous 80-bit random part, so ids sort in creation order.
 */
export function ulid(now: number = Date.now()): Ulid {
  if (!Number.isInteger(now) || now < 0 || now > 0xffffffffffff) throw new RangeError("ulid: time out of range");
  if (now > lastTime) {
    lastTime = now;
    lastRand.set(randomBytes(10));
  } else {
    // same ms or clock went back: keep lastTime, increment the random part (overflow is astronomically unlikely)
    let i = 9;
    while (i >= 0 && lastRand[i] === 0xff) lastRand[i--] = 0;
    if (i < 0) throw new RangeError("ulid: random part overflow");
    lastRand[i]++;
  }
  let t = lastTime;
  let out = "";
  for (let i = 0; i < 10; i++) {
    out = CROCKFORD[t % 32] + out;
    t = Math.floor(t / 32);
  }
  // 80 random bits → 16 chars, 5 bits each, big-endian
  let acc = 0;
  let bits = 0;
  for (const byte of lastRand) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += CROCKFORD[(acc >>> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  return out;
}

/** Opaque value: fixed prefix + base64url of 32 random bytes (43 chars). The issuer stores only `opaqueDigest`. */
export function opaqueValue(prefix: OpaquePrefix): string {
  return prefix + randomBytes(32).toString("base64url");
}

/** sha256 of the raw string (UTF-8), not of its JCS form. */
export function opaqueDigest(value: string): Sha256Digest {
  return sha256Bytes(new TextEncoder().encode(value));
}

/** Constant-time comparison of two digests / secrets (length is not secret). */
export function digestEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}
