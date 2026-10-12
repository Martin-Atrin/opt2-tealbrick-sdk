// Literal extraction for the M5 product-literal scan (CONFORMANCE §4.1): a small JS/TS tokenizer that drops line and
// block comments and returns the code literals — string literal bodies, template literal text chunks and regex literal
// bodies — so a product id named in a comment never counts, while one written as a value in code always does.
// Escapes are kept as written (no unescaping). Regex-vs-division follows the previous significant token, the usual
// heuristic; template `${…}` expressions are tokenized as code, nested to any depth.

/** Keywords after which a `/` starts a regex literal (an identifier or value before it means division). */
const REGEX_AFTER_WORD = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await"]);
const isIdent = (c: string) => /[A-Za-z0-9_$\u0080-\uffff]/.test(c);

/** Code literals of a JS/TS source text (comments excluded). */
export function codeLiterals(src: string): string[] {
  const out: string[] = [];
  /** brace depth inside each open template `${…}` expression (innermost last) */
  const tpl: number[] = [];
  /** previous significant token: a word, or a punctuator character */
  let prev = "";
  let i = 0;
  const n = src.length;

  /** Reads template text from `i` (just after a backtick or a closing `}`) to the closing backtick or the next `${`. */
  const templateChunk = () => {
    let s = "";
    while (i < n) {
      const c = src[i];
      if (c === "\\") {
        s += src.slice(i, i + 2);
        i += 2;
      } else if (c === "`") {
        i++;
        out.push(s);
        prev = "`";
        return;
      } else if (c === "$" && src[i + 1] === "{") {
        i += 2;
        out.push(s);
        tpl.push(0);
        prev = "{";
        return;
      } else {
        s += c;
        i++;
      }
    }
    out.push(s);
  };

  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      const e = src.indexOf("\n", i);
      i = e < 0 ? n : e;
    } else if (c === "/" && d === "*") {
      const e = src.indexOf("*/", i + 2);
      i = e < 0 ? n : e + 2;
    } else if (c === '"' || c === "'") {
      let s = "";
      i++;
      while (i < n && src[i] !== c && src[i] !== "\n") {
        if (src[i] === "\\") {
          s += src.slice(i, i + 2);
          i += 2;
        } else s += src[i++];
      }
      i++;
      out.push(s);
      prev = c;
    } else if (c === "`") {
      i++;
      templateChunk();
    } else if (c === "/") {
      const division = /[\w$)\]}`'"\u0080-\uffff]$/.test(prev) && !REGEX_AFTER_WORD.has(prev);
      let j = i + 1;
      let s = "";
      let cls = false;
      let closed = false;
      if (!division) {
        while (j < n && src[j] !== "\n") {
          const r = src[j];
          if (r === "\\") {
            s += src.slice(j, j + 2);
            j += 2;
            continue;
          }
          if (r === "[") cls = true;
          else if (r === "]") cls = false;
          else if (r === "/" && !cls) {
            closed = true;
            break;
          }
          s += r;
          j++;
        }
      }
      if (closed) {
        out.push(s);
        i = j + 1;
        while (i < n && isIdent(src[i])) i++;
        prev = "/re/";
      } else {
        i++;
        prev = "/";
      }
    } else if (isIdent(c)) {
      const st = i;
      while (i < n && isIdent(src[i])) i++;
      prev = src.slice(st, i);
    } else if (c === "{") {
      if (tpl.length) tpl[tpl.length - 1]++;
      prev = c;
      i++;
    } else if (c === "}") {
      i++;
      if (tpl.length && tpl[tpl.length - 1] === 0) {
        tpl.pop();
        templateChunk();
      } else {
        if (tpl.length) tpl[tpl.length - 1]--;
        prev = c;
      }
    } else {
      if (!/\s/.test(c)) prev = c;
      i++;
    }
  }
  return out;
}

/** True when a literal is the id itself or holds it as a `/`-delimited path segment. */
export function literalNamesId(literal: string, id: string): boolean {
  return literal === id || literal.split("/").includes(id);
}
