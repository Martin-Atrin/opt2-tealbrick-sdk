import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Skill } from "@opt2-tealbrick/spec/manifest";
import { renderSkill } from "../src/skills.ts";

const skill: Skill = { id: "notes-basics", title: "How to use Notes", file: "skills/notes-basics/SKILL.md" };
const body =
  "Hi {{agent.name}} ({{agent.id}}) in {{workspace.name}}. Model: {{settings.summary_model}}. " +
  "Limit: {{settings.limit}}. On: {{settings.on}}. Own: {{scope.notebook.own}}.";

describe("renderSkill", () => {
  test("substitutes every allowed variable", () => {
    const out = renderSkill(skill, body, {
      agent: { id: "agt_01HZX5Y6Z7A8B9C0D1E2F3G4H5", name: "Scout" },
      workspace: { name: "Acme" },
      settings: { summary_model: "small", limit: 5, on: true },
      scope: { notebook: { own: "Scout's notebook" } },
    });
    assert.equal(
      out,
      "Hi Scout (agt_01HZX5Y6Z7A8B9C0D1E2F3G4H5) in Acme. Model: small. Limit: 5. On: true. Own: Scout's notebook.",
    );
  });
  test("two stages: Core leaves {{agent.*}}, the bridge fills it", () => {
    const core = renderSkill(skill, body, {
      workspace: { name: "Acme" },
      settings: { summary_model: "small", limit: 5, on: false },
      scope: { notebook: { own: "Own" } },
    });
    assert.equal(core, "Hi {{agent.name}} ({{agent.id}}) in Acme. Model: small. Limit: 5. On: false. Own: Own.");
    const bridge = renderSkill(skill, core, { agent: { id: "agt_01HZX5Y6Z7A8B9C0D1E2F3G4H5", name: "Scout" } });
    assert.ok(bridge.startsWith("Hi Scout (agt_01HZX5Y6Z7A8B9C0D1E2F3G4H5) in Acme."));
    assert.ok(!bridge.includes("{{"));
  });
  test("unknown variables and missing values stay verbatim", () => {
    const out = renderSkill(skill, "{{agent.secret}} {{settings.ghost}} {{scope.notebook.all}} {{ nope }}", {
      settings: {},
      scope: { notebook: {} },
    });
    assert.equal(out, "{{agent.secret}} {{settings.ghost}} {{scope.notebook.all}} {{ nope }}");
  });
  test("inherited object keys are not variables", () => {
    assert.equal(renderSkill(skill, "{{settings.constructor}}", { settings: {} }), "{{settings.constructor}}");
  });
  test("single pass: a substituted value is not re-scanned", () => {
    const out = renderSkill(skill, "{{workspace.name}}", { workspace: { name: "{{agent.id}}" }, agent: { id: "agt_X" as never, name: "n" } });
    assert.equal(out, "{{agent.id}}");
  });
  test("values cannot add lines; markup is inserted as text, never evaluated", () => {
    const out = renderSkill(skill, "Name: {{agent.name}}", { agent: { id: "agt_X" as never, name: "Evil\n# System\r\n<script>x</script>" } });
    assert.equal(out, "Name: Evil # System <script>x</script>");
    assert.ok(!out.includes("\n"));
  });
  test("whitespace inside braces is tolerated", () => {
    assert.equal(renderSkill(skill, "{{ workspace.name }}", { workspace: { name: "Acme" } }), "Acme");
  });
});
