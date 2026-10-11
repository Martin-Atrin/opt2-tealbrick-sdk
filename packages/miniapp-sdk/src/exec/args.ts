// tb-exec command line (SDK-API §11, C33): `tb-exec [--helper-cmd "<cmd>" --helper-target 127.0.0.1:<port>]
// [--manifest <path>] -- <upstream command...>`. Pure parsing; no I/O.
import { TbError } from "../server/errors.ts";

/**
 * SPEC-GAP: SDK-API §11 gives tb-exec no way to learn its app manifest (needed for the claim's `manifestDigest` and
 * `version`, the service's `helper {port, paths}` and `backup {dump, restore}`), and no TB_* env carries it. The
 * narrowest reading: the thin layer bakes the app manifest into the image at this path; `--manifest` overrides it.
 */
export const DEFAULT_MANIFEST_PATH = "/opt/tb/tealbrick.manifest.json";

export interface ExecArgs {
  /** helper process command line (run through `/bin/sh -c`), with `helperTarget` */
  helperCmd: string | null;
  /** loopback `host:port` the authenticating helper proxy forwards declared paths to */
  helperTarget: { host: string; port: number } | null;
  manifestPath: string;
  /** upstream argv (after `--`), at least one element */
  command: string[];
}

const LOOPBACK = new Set(["127.0.0.1", "[::1]", "localhost"]);

function usage(message: string): TbError {
  return new TbError("usage", `${message}; usage: tb-exec [--helper-cmd "<cmd>" --helper-target 127.0.0.1:<port>] [--manifest <path>] -- <command...>`, 400);
}

function parseTarget(v: string): { host: string; port: number } {
  const m = /^(\[::1\]|127\.0\.0\.1|localhost):(\d{1,5})$/.exec(v);
  const port = m ? Number(m[2]) : 0;
  if (!m || !LOOPBACK.has(m[1] as string) || port < 1 || port > 65535) throw usage("--helper-target must be a loopback host:port");
  return { host: m[1] === "[::1]" ? "::1" : (m[1] as string), port };
}

export function parseArgs(argv: readonly string[]): ExecArgs {
  let helperCmd: string | null = null;
  let helperTarget: ExecArgs["helperTarget"] = null;
  let manifestPath = DEFAULT_MANIFEST_PATH;
  let i = 0;
  const value = (flag: string): string => {
    const v = argv[i + 1];
    if (v === undefined || v === "--" || v === "") throw usage(`${flag} needs a value`);
    i += 2;
    return v;
  };
  while (i < argv.length && argv[i] !== "--") {
    const a = argv[i] as string;
    if (a === "--helper-cmd") helperCmd = value(a);
    else if (a === "--helper-target") helperTarget = parseTarget(value(a));
    else if (a === "--manifest") manifestPath = value(a);
    else throw usage(`unknown argument ${JSON.stringify(a)}`);
  }
  if (argv[i] !== "--") throw usage("missing --");
  const command = argv.slice(i + 1);
  if (command.length === 0 || command[0] === "") throw usage("missing upstream command");
  if ((helperCmd === null) !== (helperTarget === null)) throw usage("--helper-cmd and --helper-target go together");
  return { helperCmd, helperTarget, manifestPath, command };
}
