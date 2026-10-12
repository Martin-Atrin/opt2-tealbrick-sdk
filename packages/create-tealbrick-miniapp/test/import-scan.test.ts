import assert from "node:assert/strict";
import { test } from "node:test";
import { importSpecifiers } from "../template/scripts/import-scan.ts";

test("import scanner: statements found, words inside strings/comments/templates/regex ignored (Knowledge report, ui 0.1.1)", () => {
  const code = [
    'import React from "react";',
    'import { jsx } from "react/jsx-runtime";',
    'import "./side-effect.js";',
    'export { AppShell, default as Ui } from "./shell.js";',
    'export * from "./tokens.js";',
    'export * as icons from "./icons.js";',
    'const pages = [{ label: "Backups & export", href: "x" }, { label: "Import from file" }];',
    "const t = `export * from \"./not-a-module.js\" ${pages.length}`;",
    '// import nope from "./commented.js";',
    '/* export { x } from "./block.js"; */',
    "const re = /export \\{ y \\} from \"z\"/;",
    'const lazy = () => import("./lazy.js");',
    "obj.import(\"./method-call.js\");",
    "export const value = 1;",
    "export default function f() { return 'from \"./str.js\"'; }",
  ].join("\n");
  assert.deepEqual(importSpecifiers(code).sort(), ["./icons.js", "./lazy.js", "./shell.js", "./side-effect.js", "./tokens.js", "react", "react/jsx-runtime"].sort());
});

test("import scanner: the exact ui 0.1.1 label line no longer yields a bogus specifier", () => {
  const code = 'export const STANDARD_PAGES = [{ id: "backups", label: "Backups & export" }];\nimport { a } from "./a.js";';
  assert.deepEqual(importSpecifiers(code), ["./a.js"]);
});
