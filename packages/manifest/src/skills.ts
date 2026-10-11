// The ONE skill renderer (MANIFEST §10, SDK-API §2, N6). Pure text substitution: nothing is evaluated.
import type { Skill } from "@opt2-tealbrick/spec/manifest";
import type { SkillVars } from "@opt2-tealbrick/spec/sdk";
import { parseVariable, VARIABLE_RE } from "./skill-text.ts";

/** Values become one plain line: control characters (incl. CR/LF) → space, so a value cannot add lines or headings. */
function plain(value: string | number | boolean): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping control characters is the point
  return String(value).replace(/[\u0000-\u001f\u007f]+/g, " ");
}

/**
 * Substitutes `{{agent.name}}`, `{{agent.id}}`, `{{workspace.name}}`, `{{settings.<key>}}` and
 * `{{scope.<type>.<kind>}}` in `body` in a single pass (substituted values are never re-scanned).
 * A variable whose value is not in `vars` is left verbatim: Core renders the workspace bundle and leaves
 * `{{agent.*}}` for the bridge, which renders per agent (MANIFEST §10, BRIDGE §7.4). Unknown variable forms are
 * also left verbatim; refusing them is `validateAppFiles`' job (M-SK-2), not the renderer's.
 */
export function renderSkill(_skill: Skill, body: string, vars: SkillVars): string {
  return body.replace(VARIABLE_RE, (whole, raw: string) => {
    const v = parseVariable(raw);
    if (!v) return whole;
    let value: string | number | boolean | undefined;
    switch (v.kind) {
      case "agent":
        value = vars.agent?.[v.key];
        break;
      case "workspace":
        value = vars.workspace?.name;
        break;
      case "settings":
        value = vars.settings && Object.hasOwn(vars.settings, v.key) ? vars.settings[v.key] : undefined;
        break;
      case "scope": {
        const byKind = vars.scope && Object.hasOwn(vars.scope, v.type) ? vars.scope[v.type] : undefined;
        value = byKind && Object.hasOwn(byKind, v.grantKind) ? byKind[v.grantKind] : undefined;
        break;
      }
    }
    return value === undefined ? whole : plain(value);
  });
}
