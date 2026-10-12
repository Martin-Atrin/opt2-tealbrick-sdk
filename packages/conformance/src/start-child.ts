// Child entry for `forkStart` (CLI `--start <module>`): imports the harness module in its own process, calls its
// default-exported (or named) `start(env)` and serves the returned object to the runner over the IPC channel. The app
// therefore runs in a separate process as in every deployment: whatever it does to its own process (the SDK's root →
// uid 1000 drop, umask, cwd, patched globals) cannot touch the runner. argv[2] = the module's file URL.
import type { ChildMsg, ParentMsg } from "./fork-start.ts";

type Harness = (env: Record<string, string>) => Promise<Record<string, unknown>>;

// resolves once the message is handed to the channel, so a following process.exit cannot drop it
const send = (m: ChildMsg): Promise<void> =>
  new Promise((done) => {
    if (!process.connected || !process.send) return done();
    process.send(m, () => done());
  });
const why = (e: unknown): string => (e instanceof Error ? e.message : String(e));

async function load(url: string): Promise<Harness> {
  const mod = (await import(url)) as { default?: unknown; start?: unknown };
  const fn = typeof mod.default === "function" ? mod.default : mod.start;
  if (typeof fn !== "function") throw new Error("no default-exported start(env) function");
  return fn as Harness;
}

let running: Record<string, unknown> | null = null;
let stopping: Promise<never> | null = null;

function stopAndExit(): Promise<never> {
  stopping ??= (async () => {
    const obj = running;
    let code = 0;
    try {
      if (typeof obj?.stop === "function") await (obj.stop as () => Promise<void>).call(obj);
    } catch (e) {
      process.stderr.write(`start-child: stop() failed: ${why(e)}\n`);
      code = 1;
    }
    await send({ t: "stopped" });
    process.exit(code);
  })();
  return stopping;
}

process.on("message", (raw: ParentMsg) => {
  void (async () => {
    const url = process.argv[2] ?? "";
    switch (raw.t) {
      case "probe":
        try {
          await load(url);
          await send({ t: "probe", ok: true });
        } catch (e) {
          await send({ t: "probe", ok: false, message: why(e) });
        }
        process.exit(0);
        break;
      case "start":
        try {
          const result = await (await load(url))(raw.env);
          if (!result || typeof result !== "object") throw new Error("start(env) did not resolve to an object");
          running = result;
          const fields: Record<string, string> = {};
          const methods: string[] = [];
          for (const [k, v] of Object.entries(result)) {
            if (typeof v === "string") fields[k] = v;
            else if (typeof v === "function") methods.push(k);
          }
          await send({ t: "ready", fields, methods });
        } catch (e) {
          await send({ t: "fail", message: why(e) });
          process.exit(1);
        }
        break;
      case "call": {
        const fn = running?.[raw.method];
        try {
          if (typeof fn !== "function") throw new Error(`start(env) result has no ${raw.method}()`);
          await (fn as () => Promise<unknown>).call(running);
          await send({ t: "result", id: raw.id, ok: true });
        } catch (e) {
          await send({ t: "result", id: raw.id, ok: false, message: why(e) });
        }
        break;
      }
      case "stop":
        await stopAndExit();
    }
  })();
});

// runner gone (crash, kill): stop the app instead of leaving it listening
process.on("disconnect", () => void stopAndExit());
