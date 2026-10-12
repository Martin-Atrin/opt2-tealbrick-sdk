// Upstream child supervision (SDK-API §11): spawn with the keys in env, forward signals, restart on a key change,
// report the exit code of a child that ended on its own (or after a forwarded stop signal).
import { type ChildProcess, spawn } from "node:child_process";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { signalExitCode } from "./util.ts";

export const RESTART_GRACE_MS = 10_000;

export class Upstream {
  readonly #command: readonly string[];
  readonly #log: Logger;
  #child: ChildProcess | null = null;
  #childExit: Promise<number> | null = null;
  #stopping = false;
  #resolveExited!: (code: number) => void;
  /** exit code of the child that ended outside a restart; tb-exec exits with it */
  readonly exited: Promise<number>;

  constructor(command: readonly string[], log: Logger) {
    this.#command = command;
    this.#log = log;
    this.exited = new Promise((r) => {
      this.#resolveExited = r;
    });
  }

  get pid(): number | undefined {
    return this.#child?.pid;
  }

  /** true once the child has been started (it may be waiting for required keys before that). */
  get started(): boolean {
    return this.#childExit !== null || this.#child !== null;
  }

  start(env: Record<string, string>): void {
    const [file, ...args] = this.#command as [string, ...string[]];
    const child = spawn(file, args, { env, stdio: "inherit" });
    this.#child = child;
    this.#childExit = new Promise<number>((resolve) => {
      let done = false;
      const finish = (code: number) => {
        if (done) return;
        done = true;
        resolve(code);
      };
      child.once("error", (e: NodeJS.ErrnoException) => {
        this.#log.error("upstream failed to start", { code: e.code ?? "spawn_failed" });
        if (child.pid === undefined) finish(e.code === "ENOENT" ? 127 : 126);
      });
      child.once("exit", (code, sig) => finish(code ?? signalExitCode(sig)));
    });
    const mine = this.#childExit;
    void mine.then((code) => {
      if (this.#childExit !== mine) return; // replaced by a restart
      this.#child = null;
      this.#log.info("upstream exited", { exitCode: code });
      this.#resolveExited(code);
    });
    this.#log.info("upstream started", { pid: child.pid ?? null });
  }

  /** Stops the running child (SIGTERM, SIGKILL after the grace period) and starts it again with `env`. */
  async restart(env: Record<string, string>): Promise<void> {
    const child = this.#child;
    const exit = this.#childExit;
    if (!child || !exit || this.#stopping) return;
    this.#childExit = null; // detach: this exit is not tb-exec's exit
    child.kill("SIGTERM");
    const t = setTimeout(() => child.kill("SIGKILL"), RESTART_GRACE_MS);
    await exit;
    clearTimeout(t);
    if (this.#stopping) {
      this.#resolveExited(await exit);
      return;
    }
    this.#log.info("upstream restarting", { reason: "keys_changed" });
    this.start(env);
  }

  /** Forwards a signal; stop signals (TERM/INT/QUIT) also end restarts so the child's exit ends tb-exec. */
  signal(sig: NodeJS.Signals): void {
    const stop = sig === "SIGTERM" || sig === "SIGINT" || sig === "SIGQUIT";
    if (stop) this.#stopping = true;
    if (this.#child) this.#child.kill(sig);
    else if (stop) this.#resolveExited(signalExitCode(sig)); // never started (waiting for keys): end tb-exec
  }

  get stopping(): boolean {
    return this.#stopping;
  }
}

/** The optional app-owned helper process (C6, `--helper-cmd`, run as `/bin/sh -c "exec <cmd>"` so signals reach it); restarted
// with backoff while tb-exec runs. */
export class HelperProcess {
  readonly #cmd: string;
  readonly #env: Record<string, string>;
  readonly #log: Logger;
  #child: ChildProcess | null = null;
  #stopped = false;
  #delay = 1000;
  #timer: NodeJS.Timeout | null = null;

  constructor(cmd: string, env: Record<string, string>, log: Logger) {
    this.#cmd = cmd;
    this.#env = env;
    this.#log = log;
  }

  start(): void {
    if (this.#stopped) return;
    const startedAt = Date.now();
    const child = spawn("/bin/sh", ["-c", `exec ${this.#cmd}`], { env: this.#env, stdio: "inherit" });
    this.#child = child;
    child.once("error", () => this.#log.error("helper failed to start", { code: "helper_spawn_failed" }));
    child.once("close", (code, sig) => {
      this.#child = null;
      if (this.#stopped) return;
      if (Date.now() - startedAt > 60_000) this.#delay = 1000;
      this.#log.warn("helper exited; restarting", { exitCode: code ?? signalExitCode(sig), inMs: this.#delay });
      this.#timer = setTimeout(() => this.start(), this.#delay);
      this.#delay = Math.min(this.#delay * 2, 30_000);
    });
  }

  /** Forwards a signal; a stop signal (TERM/INT/QUIT) also ends the restarts. */
  signal(sig: NodeJS.Signals): void {
    if (sig === "SIGTERM" || sig === "SIGINT" || sig === "SIGQUIT") this.#stopped = true;
    this.#child?.kill(sig);
  }

  /** Stops the helper (SIGTERM, SIGKILL after the grace period) and waits for it. */
  async stop(): Promise<void> {
    this.#stopped = true;
    if (this.#timer) clearTimeout(this.#timer);
    const child = this.#child;
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    const closed = new Promise<void>((r) => child.once("close", () => r()));
    child.kill("SIGTERM");
    const t = setTimeout(() => child.kill("SIGKILL"), RESTART_GRACE_MS);
    await closed;
    clearTimeout(t);
  }
}
