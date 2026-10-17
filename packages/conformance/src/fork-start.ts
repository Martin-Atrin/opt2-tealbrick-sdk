// `forkStart(module)`: the CLI's `--start <module>` harness. The module's `start(env)` runs in a CHILD process
// (start-child.ts) instead of inside the runner, as in every deployment: an app that changes its own process (the SDK
// drops root to uid 1000, BSA-05 / C53) cannot take the runner's rights to write `--report` with it. Each start() is a
// fresh child, so restart checks get a real process restart. The child gets the runner's env plus the suite env (the
// TB_* names) and the suite env object as `start`'s argument; its stdout/stderr go to the runner's stderr (stdout stays
// the report). Programmatic `runApp({ start })` / `runBridgeTarget({ start })` callers still run in-process.
import { fork } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

/** runner → child */
export type ParentMsg = { t: "probe" } | { t: "start"; env: Record<string, string> } | { t: "call"; id: number; method: string } | { t: "stop" };
/** child → runner */
export type ChildMsg =
  | { t: "probe"; ok: boolean; message?: string }
  | { t: "ready"; fields: Record<string, string>; methods: string[] }
  | { t: "fail"; message: string }
  | { t: "result"; id: number; ok: boolean; message?: string }
  | { t: "stopped" };

export interface ForkStartOptions {
  /** start(env) must resolve within this many ms (default 60 000); the child is killed otherwise */
  bootTimeoutMs?: number;
  /** stop() grace before SIGKILL in ms (default 10 000) */
  stopTimeoutMs?: number;
  /** receives the child's stdout/stderr (default: written to this process's stderr) */
  output?: (chunk: Buffer) => void;
  /** working directory of the child (default: this process's; CONF-MULTIAPP peers run in their own checkout) */
  cwd?: string;
  /** false: the child gets only PATH, HOME, TMPDIR, LANG and the suite env, not this process's whole env (CONF-MULTIAPP peers: no CI secrets reach pinned third-party code) */
  inheritEnv?: boolean;
}

const MINIMAL_ENV = ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "SystemRoot"] as const;

/** The started child: the string fields of start()'s result, one async proxy per function member, and its pid. */
export type ForkedStart = Record<string, unknown> & { readonly pid: number; stop(): Promise<void> };

const TAIL = 400;
const childEntry = new URL(import.meta.url.endsWith(".ts") ? "./start-child.ts" : "./start-child.js", import.meta.url);

function spawnChild(modulePath: string, env: NodeJS.ProcessEnv, output: (c: Buffer) => void, cwd?: string) {
  const child = fork(childEntry, [pathToFileURL(resolve(modulePath)).href], { env, stdio: ["ignore", "pipe", "pipe", "ipc"], serialization: "json", ...(cwd ? { cwd } : {}) });
  const out = { tail: "" };
  const take = (d: Buffer) => {
    out.tail = (out.tail + d.toString("utf8")).slice(-TAIL);
    output(d);
  };
  child.stdout?.on("data", take);
  child.stderr?.on("data", take);
  // spawn / closed-channel errors surface through `exited` and the tail, never as an unhandled 'error' event
  child.on("error", (e) => {
    out.tail = `${out.tail}\n${e.message}`.slice(-TAIL);
  });
  const exited = new Promise<void>((r) => child.once("exit", () => r()));
  const gone = () => child.exitCode !== null || child.signalCode !== null;
  const how = () => `${child.signalCode ? `signal ${child.signalCode}` : `code ${child.exitCode}`}${out.tail.trim() ? `; last output: ${out.tail.trim()}` : ""}`;
  return { child, exited, gone, how };
}

/** Imports `modulePath` in a throwaway child and checks it exports start(env); throws a usage error otherwise. */
export async function checkStartModule(modulePath: string, timeoutMs = 30_000): Promise<void> {
  const { child, exited, gone, how } = spawnChild(modulePath, process.env, () => undefined);
  const answer = new Promise<ChildMsg | null>((r) => {
    child.once("message", (m: ChildMsg) => r(m));
    void exited.then(() => r(null));
    setTimeout(() => r(null), timeoutMs).unref();
  });
  child.send({ t: "probe" } satisfies ParentMsg);
  const m = await answer;
  if (!gone()) child.kill("SIGKILL");
  if (m?.t === "probe" && m.ok) return;
  throw new Error(`--start ${modulePath}: ${m?.t === "probe" ? m.message : `module check failed (${gone() ? how() : `no answer within ${timeoutMs} ms`})`}`);
}

/** Returns a `start(env)` harness that boots `modulePath`'s default export in a fresh child per call. */
export function forkStart<T extends object = Record<string, unknown>>(modulePath: string, opts: ForkStartOptions = {}): (env: Record<string, string>) => Promise<T & ForkedStart> {
  const bootMs = opts.bootTimeoutMs ?? 60_000;
  const stopMs = opts.stopTimeoutMs ?? 10_000;
  const output = opts.output ?? ((c: Buffer) => void process.stderr.write(c));
  return async (env) => {
    const { child, exited, gone, how } = spawnChild(modulePath, { ...(opts.inheritEnv === false ? Object.fromEntries(MINIMAL_ENV.filter((k) => process.env[k] !== undefined).map((k) => [k, process.env[k]])) : process.env), ...env }, output, opts.cwd);
    const pending = new Map<number, { ok: () => void; no: (e: Error) => void }>();
    let next = 0;
    const ready = new Promise<Extract<ChildMsg, { t: "ready" }>>((ok, no) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        no(new Error(`--start ${modulePath}: start(env) did not resolve within ${bootMs} ms (child killed)`));
      }, bootMs);
      child.on("message", (m: ChildMsg) => {
        if (m.t === "ready") {
          clearTimeout(timer);
          ok(m);
        } else if (m.t === "fail") {
          clearTimeout(timer);
          no(new Error(`--start ${modulePath}: start(env) failed: ${m.message}`));
        } else if (m.t === "result") {
          const p = pending.get(m.id);
          pending.delete(m.id);
          if (m.ok) p?.ok();
          else p?.no(new Error(m.message ?? "call failed"));
        }
      });
      void exited.then(() => {
        clearTimeout(timer);
        const e = new Error(`--start ${modulePath}: app process exited (${how()})`);
        no(e);
        for (const p of pending.values()) p.no(e);
        pending.clear();
      });
    });
    child.send({ t: "start", env } satisfies ParentMsg);
    const { fields, methods } = await ready;
    const call = (method: string) =>
      new Promise<void>((ok, no) => {
        if (gone() || !child.connected) return no(new Error(`--start ${modulePath}: app process exited (${how()})`));
        const id = ++next;
        pending.set(id, { ok, no });
        child.send({ t: "call", id, method } satisfies ParentMsg);
      });
    const stop = async () => {
      if (gone()) return;
      if (child.connected) child.send({ t: "stop" } satisfies ParentMsg);
      else child.kill("SIGTERM");
      const timer = setTimeout(() => child.kill("SIGKILL"), stopMs);
      await exited;
      clearTimeout(timer);
    };
    const handle: Record<string, unknown> = { ...fields, pid: child.pid as number };
    for (const m of methods) if (m !== "stop") handle[m] = () => call(m);
    handle.stop = stop;
    return handle as T & ForkedStart;
  };
}
