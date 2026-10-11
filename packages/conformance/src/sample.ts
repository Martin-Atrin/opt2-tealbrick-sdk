// Generic input generation from an operation's JSON Schema (no product ids): a minimal value with every
// required property, where every string is filled with `fill` (the checks pass a scope instance id the caller can
// access, so an app's `scope(input)` resolves to it whatever field it reads).
import type { Json } from "@opt2-tealbrick/spec/sdk";

type Schema = Record<string, unknown>;
const isObj = (v: unknown): v is Schema => !!v && typeof v === "object" && !Array.isArray(v);

function localRef(root: Schema, ref: string): Schema | undefined {
  if (!ref.startsWith("#/")) return undefined;
  let cur: unknown = root;
  for (const part of ref.slice(2).split("/")) cur = isObj(cur) ? cur[part.replace(/~1/g, "/").replace(/~0/g, "~")] : undefined;
  return isObj(cur) ? cur : undefined;
}

function str(s: Schema, fill: string): string {
  if (s.format === "email") return "conformance@example.org";
  if (s.format === "uri" || s.format === "url") return "https://example.org/conformance";
  if (s.format === "date-time") return new Date(0).toISOString();
  if (s.format === "date") return "1970-01-01";
  let v = fill;
  const max = typeof s.maxLength === "number" ? s.maxLength : undefined;
  const min = typeof s.minLength === "number" ? s.minLength : 0;
  if (max !== undefined && v.length > max) v = v.slice(0, max);
  while (v.length < min) v += "x";
  return v;
}

function gen(root: Schema, s: Schema, fill: string, depth: number): Json {
  if (depth > 8) return null;
  if (typeof s.$ref === "string") {
    const r = localRef(root, s.$ref);
    return r ? gen(root, r, fill, depth + 1) : null;
  }
  if ("const" in s) return s.const as Json;
  if (Array.isArray(s.enum) && s.enum.length > 0) return s.enum[0] as Json;
  for (const k of ["anyOf", "oneOf"] as const) if (Array.isArray(s[k]) && isObj((s[k] as unknown[])[0])) return gen(root, (s[k] as Schema[])[0], fill, depth + 1);
  if (Array.isArray(s.allOf)) return gen(root, Object.assign({}, ...(s.allOf as Schema[])), fill, depth + 1);
  const type = Array.isArray(s.type) ? s.type.find((t) => t !== "null") : s.type;
  switch (type) {
    case "string":
      return str(s, fill);
    case "integer":
    case "number": {
      const min = typeof s.minimum === "number" ? s.minimum : typeof s.exclusiveMinimum === "number" ? s.exclusiveMinimum + 1 : 1;
      const max = typeof s.maximum === "number" ? s.maximum : undefined;
      return max !== undefined && min > max ? max : min;
    }
    case "boolean":
      return false;
    case "null":
      return null;
    case "array": {
      const n = typeof s.minItems === "number" ? s.minItems : 0;
      const items = isObj(s.items) ? s.items : {};
      return Array.from({ length: n }, () => gen(root, items, fill, depth + 1));
    }
    default: {
      const out: Record<string, Json> = {};
      const props = isObj(s.properties) ? s.properties : {};
      const required = Array.isArray(s.required) ? (s.required as string[]) : [];
      for (const k of required) out[k] = gen(root, isObj(props[k]) ? (props[k] as Schema) : {}, fill, depth + 1);
      return out;
    }
  }
}

/** Minimal schema-valid sample of `schema` (best effort; callers validate with `validateInput`). */
export function sampleInput(schema: unknown, fill: string): Json {
  if (!isObj(schema)) return {};
  return gen(schema, schema, fill, 0);
}
