// JSON Schema → TypeScript emitter of the per-app kit.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { camel, docOf, pascal, SchemaEmitter } from "../../src/gen/schema-ts.ts";

const emit = (schema: unknown) => {
  const em = new SchemaEmitter();
  return { type: em.emit(schema, schema, "T"), decls: em.declarations };
};
const flat = (s: string) => s.replace(/\s+/g, " ");

describe("SchemaEmitter", () => {
  test("primitives, type unions, enum and const", () => {
    assert.equal(emit({ type: "string", maxLength: 3, format: "email" }).type, "string");
    assert.equal(emit({ type: "integer", minimum: 1 }).type, "number");
    assert.equal(emit({ type: ["string", "null"] }).type, "string | null");
    assert.equal(emit({ enum: ["a", 1, null] }).type, '"a" | 1 | null');
    assert.equal(emit({ type: "string", const: "x" }).type, '"x"');
    assert.equal(emit({ const: { a: [1] } }).type, '{"a":[1]}');
    assert.equal(emit(true).type, "unknown");
    assert.equal(emit(false).type, "never");
    assert.equal(emit({}).type, "unknown");
  });

  test("objects: required, optional, closed vs open, quoted keys, docs, arrays", () => {
    const t = flat(
      emit({
        type: "object",
        additionalProperties: false,
        required: ["id", "extra"],
        properties: { id: { type: "string", description: "The id */ here" }, "a-b": { type: "array", items: { type: "number" } }, list: { type: "array" } },
      }).type,
    );
    assert.equal(t, '{ /** The id *\\/ here */ id: string; "a-b"?: Array<number>; list?: unknown[]; extra: unknown; }');
    assert.equal(flat(emit({ type: "object", properties: { a: { type: "boolean" } } }).type), "{ a?: boolean; [key: string]: unknown; }");
    assert.equal(flat(emit({ type: "object", additionalProperties: { type: "string" } }).type), "{ [key: string]: string; }");
    assert.equal(emit({ type: "object", additionalProperties: false }).type, "Record<string, never>");
  });

  test("anyOf / oneOf / allOf", () => {
    assert.equal(emit({ anyOf: [{ type: "string" }, { type: "number" }] }).type, "string | number");
    assert.equal(emit({ oneOf: [{ const: 1 }, { const: 2 }] }).type, "1 | 2");
    assert.equal(flat(emit({ allOf: [{ type: "object", properties: { a: { type: "string" } }, additionalProperties: false }, { anyOf: [{ type: "null" }, { type: "string" }] }] }).type), "{ a?: string; } & (null | string)");
  });

  test("local $ref: $defs become named aliases, other pointers inline, recursion guarded", () => {
    const schema = {
      type: "object",
      additionalProperties: false,
      properties: { tag: { $ref: "#/$defs/tag" }, again: { $ref: "#/$defs/tag" }, inline: { $ref: "#/properties/tag" }, self: { $ref: "#" } },
      $defs: { tag: { type: "object", additionalProperties: false, required: ["name"], properties: { name: { type: "string" }, child: { $ref: "#/$defs/tag" } } } },
    };
    const r = emit(schema);
    assert.match(r.type, /tag\?: TTag;/);
    assert.match(r.type, /again\?: TTag;/);
    assert.match(r.type, /inline\?: TTag;/);
    assert.match(r.type, /self\?: \{/);
    assert.match(r.type, /unknown \/\* recursive \$ref \*\//);
    assert.equal(r.decls.length, 1);
    assert.equal(flat(r.decls[0] as string), "export type TTag = { name: string; child?: TTag; };");
  });

  test("unsupported or unresolvable keywords become unknown with a comment", () => {
    assert.equal(emit({ not: { type: "string" } }).type, "unknown /* unsupported JSON Schema keyword(s): not */");
    assert.equal(emit({ type: "object", patternProperties: {}, if: {} }).type, "unknown /* unsupported JSON Schema keyword(s): if, patternProperties */");
    assert.equal(emit({ $ref: "https://example.org/s.json" }).type, "unknown /* non-local $ref */");
    assert.equal(emit({ $ref: "#/$defs/missing" }).type, "unknown /* unresolved $ref #/$defs/missing */");
    assert.equal(emit({ type: "date" }).type, 'unknown /* unknown type "date" */');
  });

  test("reserve refuses a duplicate name and $defs aliases avoid reserved names", () => {
    const em = new SchemaEmitter();
    em.reserve("TTag");
    assert.throws(() => em.reserve("TTag"), /collision/);
    const s = { $ref: "#/$defs/tag", $defs: { tag: { type: "string" } } };
    assert.equal(em.emit(s, s, "T"), "TTag2");
  });
});

test("pascal / camel / docOf", () => {
  assert.equal(pascal("note_create"), "NoteCreate");
  assert.equal(pascal("a_1"), "A_1");
  assert.notEqual(pascal("a_1"), pascal("a1"));
  assert.notEqual(pascal("a__b"), pascal("a_b"));
  assert.equal(pascal("notes-basics"), "NotesBasics");
  assert.equal(camel("tb_hold_status"), "tbHoldStatus");
  assert.equal(docOf({ title: "T\n x" }), "T x");
  assert.equal(docOf("nope"), null);
});
