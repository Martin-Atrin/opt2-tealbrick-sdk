// Internal (not exported from index): SKILL.md parsing and variable grammar shared by renderSkill and validateAppFiles.

/** `{{ ... }}` placeholder; group 1 = trimmed-able variable name. */
export const VARIABLE_RE = /\{\{([^{}]*)\}\}/g;

export type ParsedVariable =
  | { kind: "agent"; key: "name" | "id" }
  | { kind: "workspace"; key: "name" }
  | { kind: "settings"; key: string }
  | { kind: "scope"; type: string; grantKind: string };

const SNAKE = "[a-z][a-z0-9_]{1,39}";
const SETTINGS_RE = new RegExp(`^settings\\.(${SNAKE})$`);
const SCOPE_RE = new RegExp(`^scope\\.(${SNAKE})\\.([a-z]+)$`);

/** Parses one variable name (MANIFEST §10); null when it is not an allowed form. */
export function parseVariable(raw: string): ParsedVariable | null {
  const name = raw.trim();
  if (name === "agent.name") return { kind: "agent", key: "name" };
  if (name === "agent.id") return { kind: "agent", key: "id" };
  if (name === "workspace.name") return { kind: "workspace", key: "name" };
  const s = SETTINGS_RE.exec(name);
  if (s) return { kind: "settings", key: s[1] };
  const sc = SCOPE_RE.exec(name);
  if (sc) return { kind: "scope", type: sc[1], grantKind: sc[2] };
  return null;
}

export interface SkillFile {
  frontmatter: Record<string, string>;
  body: string;
}

/** Splits `---\n<yaml>\n---\n<body>`; frontmatter supports flat `key: value` lines (optionally quoted). */
export function parseSkillFile(text: string): SkillFile | { error: string } {
  const src = text.replace(/\r\n/g, "\n");
  if (!src.startsWith("---\n")) return { error: "missing YAML frontmatter" };
  const end = src.indexOf("\n---", 3);
  if (end < 0 || (src[end + 4] !== undefined && src[end + 4] !== "\n")) return { error: "unterminated frontmatter" };
  const frontmatter: Record<string, string> = {};
  for (const line of src.slice(4, end).split("\n")) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const m = /^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/.exec(line);
    if (!m) return { error: `unsupported frontmatter line: ${line.slice(0, 40)}` };
    if (Object.hasOwn(frontmatter, m[1])) return { error: `duplicate frontmatter key ${m[1]}` };
    let value = m[2].trim();
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.at(-1) === value[0]) value = value.slice(1, -1);
    frontmatter[m[1]] = value;
  }
  return { frontmatter, body: src.slice(end + 4).replace(/^\n/, "") };
}

// Tags as HTML parsers see them; `<https://…>` autolinks do not match (":" is not a tag-name char).
// `[^<>]` stops each attempt at the next "<", keeping the scan linear on hostile input.
const HTML_RE = /<\/?[A-Za-z][A-Za-z0-9-]*(\s[^<>]*)?\/?>|<!--|<!\[CDATA\[|<![A-Za-z]|<\?/;
const SCRIPT_URL_RE = /\]\(\s*<?\s*(javascript|vbscript|data):/i;
// Tool-call / MCP-directive / chat-template markup, also inside code (the model reads code blocks too).
const DIRECTIVE_RES: RegExp[] = [
  /<\/?\s*(function_calls|invoke|parameter|tool_use|tool_result|tool_call|tool_calls|system|antml:[a-z_]+)\b/i,
  /<\|[a-z_]+\|>/i,
  /"jsonrpc"\s*:/,
  /"method"\s*:\s*"(tools|resources|prompts|sampling|notifications)\//,
  /\[\/?(INST|SYS)\]/,
];

/** Removes fenced code blocks and inline code spans (HTML inside them is text, not markup). Line scan, linear. */
function stripCode(md: string): string {
  const out: string[] = [];
  let fence: string | null = null;
  for (const line of md.split("\n")) {
    const marker = /^(```|~~~)/.exec(line)?.[1] ?? null;
    if (fence) {
      if (marker === fence) fence = null;
    } else if (marker) {
      fence = marker;
    } else {
      out.push(line.replace(/`[^`]*`/g, ""));
    }
  }
  return out.join("\n");
}

/** S8 sanitize rules for skill text; returns the first violation or null. */
export function skillTextViolation(text: string): string | null {
  for (const re of DIRECTIVE_RES) if (re.test(text)) return "tool-call or MCP directive markup";
  const prose = stripCode(text);
  if (HTML_RE.test(prose)) return "raw HTML";
  if (SCRIPT_URL_RE.test(prose)) return "script or data URL";
  return null;
}
