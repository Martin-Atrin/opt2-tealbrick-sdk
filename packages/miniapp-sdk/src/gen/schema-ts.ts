// JSON Schema (2020-12, the subset MANIFEST §5.1 allows: local `$ref` only) → TypeScript type text, for the per-app kit.
// Keywords that change the value's shape are mapped; validation-only keywords are ignored (the type stays a superset);
// shape keywords this emitter does not model yield `unknown` with a comment naming them.

/** Keywords with no effect on the TypeScript shape (annotations and value constraints). */
const IGNORED = new Set([
  "$schema",
  "$comment",
  "$defs",
  "definitions",
  "title",
  "description",
  "default",
  "examples",
  "deprecated",
  "readOnly",
  "writeOnly",
  "format",
  "minLength",
  "maxLength",
  "pattern",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minProperties",
  "maxProperties",
  "contains",
  "minContains",
  "maxContains",
  "propertyNames",
  "dependentRequired",
]);
/** Keywords mapped to TypeScript. */
const MAPPED = new Set(["type", "properties", "required", "additionalProperties", "items", "enum", "const", "anyOf", "oneOf", "allOf", "$ref"]);

const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const DEF_REF_RE = /^#\/(?:\$defs|definitions)\/([^/]+)$/;

type Schema = Record<string, unknown>;

/** One emitter per generated file: named `$defs` types are collected across the schemas it emits. */
export class SchemaEmitter {
  /** Named type declarations (`export type X = …;`) in first-reference order. */
  readonly declarations: string[] = [];
  readonly #names = new Set<string>();
  readonly #defs = new Map<string, string>();

  /** Reserves a type name (e.g. `NoteCreateInput`) so a `$defs` alias never takes it. */
  reserve(name: string): void {
    if (this.#names.has(name)) throw new Error(`type name collision: ${name}`);
    this.#names.add(name);
  }

  /** Emits the type of `schema`; `root` is the document local `$ref`s resolve against, `base` prefixes `$defs` aliases. */
  emit(schema: unknown, root: unknown, base: string): string {
    return this.#type(schema, { root, base, stack: [] }, "");
  }

  #type(schema: unknown, cx: Cx, indent: string): string {
    if (schema === true) return "unknown";
    if (schema === false) return "never";
    if (!isObject(schema)) return "unknown /* invalid schema */";
    const unsupported = Object.keys(schema).filter((k) => !IGNORED.has(k) && !MAPPED.has(k));
    if (unsupported.length > 0) return `unknown /* unsupported JSON Schema keyword(s): ${unsupported.sort().join(", ")} */`;

    const parts: string[] = [];
    if (typeof schema.$ref === "string") parts.push(this.#ref(schema.$ref, cx, indent));
    if ("const" in schema) parts.push(literal(schema.const));
    else if (Array.isArray(schema.enum)) parts.push(schema.enum.length > 0 ? group(schema.enum.map(literal), " | ") : "never");
    else {
      const base = this.#base(schema, cx, indent);
      if (base) parts.push(base);
    }
    for (const [kw, sep] of [
      ["anyOf", " | "],
      ["oneOf", " | "],
      ["allOf", " & "],
    ] as const) {
      const list = schema[kw];
      if (Array.isArray(list) && list.length > 0) parts.push(group(list.map((s) => this.#type(s, cx, indent)), sep));
    }
    if (parts.length === 0) return "unknown";
    return parts.length === 1 ? (parts[0] as string) : parts.map((p) => (p.includes(" | ") ? `(${p})` : p)).join(" & ");
  }

  /** The `type` keyword (or the shape implied by object/array keywords). */
  #base(schema: Schema, cx: Cx, indent: string): string | null {
    let types: unknown[];
    if (Array.isArray(schema.type)) types = schema.type;
    else if (typeof schema.type === "string") types = [schema.type];
    else if ("properties" in schema || "additionalProperties" in schema || "required" in schema) types = ["object"];
    else if ("items" in schema) types = ["array"];
    else return null;
    const out = types.map((t) => {
      switch (t) {
        case "string":
          return "string";
        case "number":
        case "integer":
          return "number";
        case "boolean":
          return "boolean";
        case "null":
          return "null";
        case "array":
          return this.#array(schema, cx, indent);
        case "object":
          return this.#object(schema, cx, indent);
        default:
          return `unknown /* unknown type ${JSON.stringify(t)} */`;
      }
    });
    return out.length === 0 ? "never" : group(out, " | ");
  }

  #array(schema: Schema, cx: Cx, indent: string): string {
    if (!("items" in schema)) return "unknown[]";
    if (schema.items === false) return "[]";
    return `Array<${this.#type(schema.items, cx, indent)}>`;
  }

  #object(schema: Schema, cx: Cx, indent: string): string {
    const props = isObject(schema.properties) ? schema.properties : {};
    const required = new Set(Array.isArray(schema.required) ? schema.required.filter((r): r is string => typeof r === "string") : []);
    const inner = `${indent}  `;
    const lines: string[] = [];
    for (const [key, sub] of Object.entries(props)) {
      const doc = docOf(sub);
      if (doc) lines.push(`${inner}/** ${doc} */`);
      lines.push(`${inner}${propKey(key)}${required.has(key) ? "" : "?"}: ${this.#type(sub, cx, inner)};`);
    }
    for (const key of required) if (!Object.hasOwn(props, key)) lines.push(`${inner}${propKey(key)}: unknown;`);
    const extra = schema.additionalProperties;
    if (extra !== false) {
      // A typed index signature must admit every declared property type; with declared properties it widens to unknown.
      const value = extra === undefined || extra === true || Object.keys(props).length > 0 ? "unknown" : this.#type(extra, cx, inner);
      lines.push(`${inner}[key: string]: ${value};`);
    }
    return lines.length === 0 ? "Record<string, never>" : `{\n${lines.join("\n")}\n${indent}}`;
  }

  #ref(ref: string, cx: Cx, indent: string): string {
    if (!ref.startsWith("#")) return "unknown /* non-local $ref */";
    const def = DEF_REF_RE.exec(ref);
    if (def) {
      const known = this.#defs.get(`${cx.base}${ref}`);
      if (known) return known;
      const target = resolvePointer(cx.root, ref);
      if (target === undefined) return `unknown /* unresolved $ref ${ref} */`;
      const name = this.#uniqueName(`${cx.base}${pascal(decodeToken(def[1] as string))}`);
      this.#defs.set(`${cx.base}${ref}`, name);
      const slot = this.declarations.length;
      this.declarations.push("");
      this.declarations[slot] = `export type ${name} = ${this.#type(target, { ...cx, stack: [] }, "")};`;
      return name;
    }
    if (cx.stack.includes(ref)) return "unknown /* recursive $ref */";
    const target = resolvePointer(cx.root, ref);
    if (target === undefined) return `unknown /* unresolved $ref ${ref} */`;
    return this.#type(target, { ...cx, stack: [...cx.stack, ref] }, indent);
  }

  #uniqueName(want: string): string {
    let name = want;
    for (let i = 2; this.#names.has(name); i++) name = `${want}${i}`;
    this.#names.add(name);
    return name;
  }
}

interface Cx {
  root: unknown;
  base: string;
  stack: string[];
}

function isObject(v: unknown): v is Schema {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Any JSON value is also a valid TypeScript literal type when written as JSON. */
function literal(v: unknown): string {
  return v === undefined ? "unknown" : JSON.stringify(v);
}

function group(items: string[], sep: string): string {
  const uniq = [...new Set(items)];
  return uniq.length === 1 ? (uniq[0] as string) : uniq.map((t) => (sep === " & " && t.includes(" | ") ? `(${t})` : t)).join(sep);
}

function propKey(key: string): string {
  return IDENT_RE.test(key) ? key : JSON.stringify(key);
}

/** One-line JSDoc text from `description` (else `title`); never closes the comment early. */
export function docOf(schema: unknown): string | null {
  if (!isObject(schema)) return null;
  const text = typeof schema.description === "string" ? schema.description : typeof schema.title === "string" ? schema.title : null;
  return text ? text.replace(/\s+/g, " ").trim().replaceAll("*/", "*\\/") : null;
}

function decodeToken(token: string): string {
  return decodeURIComponent(token).replaceAll("~1", "/").replaceAll("~0", "~");
}

function resolvePointer(root: unknown, ref: string): unknown {
  if (ref === "#") return root;
  if (!ref.startsWith("#/")) return undefined;
  let cur: unknown = root;
  for (const raw of ref.slice(2).split("/")) {
    const token = decodeToken(raw);
    if (Array.isArray(cur)) cur = cur[Number(token)];
    else if (isObject(cur) && Object.hasOwn(cur, token)) cur = cur[token];
    else return undefined;
  }
  return cur;
}

/**
 * snake/kebab id → PascalCase. Segments starting with a digit keep their `_` so `a_1` ≠ `a1`; an empty segment (from
 * `__`) also keeps one. Callers check the result set for collisions.
 */
export function pascal(id: string): string {
  return id
    .split(/[_\-.]/)
    .map((seg) => {
      if (seg === "") return "_";
      if (/^[0-9]/.test(seg)) return `_${seg}`;
      return seg[0]?.toUpperCase() + seg.slice(1).replace(/[^A-Za-z0-9]/g, "_");
    })
    .join("");
}

/** snake id → camelCase method/key name. */
export function camel(id: string): string {
  const p = pascal(id);
  return p.startsWith("_") ? p : p[0]?.toLowerCase() + p.slice(1);
}
