// RFC 8785 JSON Canonicalization Scheme + sha256 digests (CORE §3). The ONE implementation.
import { createHash } from "node:crypto";
import type { Sha256Digest } from "@opt2-tealbrick/spec/credentials";
import type { Json } from "@opt2-tealbrick/spec/sdk";


function serialize(v: unknown, out: string[]): void {
  if (v === null) return void out.push("null");
  switch (typeof v) {
    case "boolean":
      return void out.push(v ? "true" : "false");
    case "number":
      if (!Number.isFinite(v)) throw new TypeError("jcs: non-finite number");
      // ECMAScript Number.prototype.toString matches RFC 8785 number serialization; -0 → 0.
      return void out.push(Object.is(v, -0) ? "0" : String(v));
    case "string":
      if (!v.isWellFormed()) throw new TypeError("jcs: lone surrogate (I-JSON)");
      return void out.push(JSON.stringify(v));
    case "object": {
      if (Array.isArray(v)) {
        out.push("[");
        v.forEach((e, i) => {
          if (i) out.push(",");
          if (e === undefined) throw new TypeError("jcs: undefined in array");
          serialize(e, out);
        });
        return void out.push("]");
      }
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) throw new TypeError("jcs: only plain objects");
      const keys = Object.keys(v as object).sort(); // UTF-16 code unit order, as RFC 8785 requires
      out.push("{");
      let first = true;
      for (const k of keys) {
        const e = (v as Record<string, unknown>)[k];
        if (e === undefined) throw new TypeError(`jcs: undefined at key ${k}`);
        if (!first) out.push(",");
        first = false;
        if (!k.isWellFormed()) throw new TypeError("jcs: lone surrogate in key (I-JSON)");
        out.push(JSON.stringify(k), ":");
        serialize(e, out);
      }
      return void out.push("}");
    }
    default:
      throw new TypeError(`jcs: unsupported type ${typeof v}`);
  }
}

/** RFC 8785 canonical JSON. Rejects NaN/Infinity, bigint, undefined, functions, non-plain objects. */
export function canonicalize(value: Json): string {
  const out: string[] = [];
  serialize(value, out);
  return out.join("");
}

/** sha256 of raw bytes as "sha256:<hex>". */
export function sha256Bytes(bytes: Uint8Array): Sha256Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}` ;
}

/** sha256 of the JCS form of a JSON value. */
export function digest(value: Json): Sha256Digest {
  return sha256Bytes(new TextEncoder().encode(canonicalize(value)));
}

export type { Json };
