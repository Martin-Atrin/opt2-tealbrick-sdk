// Runs a target command WITHOUT a shell wrapper (C55): `sh -c` on Debian is dash, which dies on the signals the suite
// sends (e.g. SIGUSR2 for a heap snapshot) and makes the target look exited. A command line is split into argv
// (POSIX-style quotes and backslash escapes); shell syntax (pipes, redirects, `&&`, `;`, `$VAR`, globs) is refused
// with a clear error — wrap such a command in a script file.
import { type ChildProcess, type SpawnOptions, spawn } from "node:child_process";

const SHELL_SYNTAX = /[|&;<>()$`*?~]/;

/** Splits a command line into argv; throws on unbalanced quotes or unquoted shell syntax. */
export function splitCommand(cmd: string): string[] {
  const out: string[] = [];
  let cur = "";
  let has = false;
  let q: '"' | "'" | null = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i] as string;
    if (q === "'") {
      if (c === "'") q = null;
      else cur += c;
      continue;
    }
    if (q === '"') {
      if (c === '"') q = null;
      else if (c === "\\" && i + 1 < cmd.length && /["\\$`]/.test(cmd[i + 1] as string)) cur += cmd[++i];
      else if (c === "$" || c === "`") throw new Error(`command uses shell expansion (${c}); run it from a script instead: ${cmd}`);
      else cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      q = c;
      has = true;
    } else if (c === "\\" && i + 1 < cmd.length) {
      cur += cmd[++i];
      has = true;
    } else if (/\s/.test(c)) {
      if (has) out.push(cur);
      cur = "";
      has = false;
    } else if (SHELL_SYNTAX.test(c)) {
      throw new Error(`command uses shell syntax (${c}); run it from a script instead: ${cmd}`);
    } else {
      cur += c;
      has = true;
    }
  }
  if (q) throw new Error(`unbalanced quote in command: ${cmd}`);
  if (has) out.push(cur);
  if (out.length === 0) throw new Error("empty command");
  return out;
}

/** Spawns the command directly (no shell): the returned child's pid IS the target process. */
export function spawnCommand(cmd: string, opts: SpawnOptions): ChildProcess {
  const [file, ...args] = splitCommand(cmd);
  return spawn(file as string, args, { ...opts, shell: false });
}
