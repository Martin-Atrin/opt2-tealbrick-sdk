// Tiny upstream for tb-exec tests: records each start (pid, the key env, whether TB_* names leaked) and its signals.
import { appendFileSync } from "node:fs";

const [out, mode] = process.argv.slice(2) as [string, string | undefined];
const record = (line: unknown) => appendFileSync(out, `${JSON.stringify(line)}\n`);
record({ event: "start", pid: process.pid, key: process.env.ENGINE_KEY ?? null, tbNames: Object.keys(process.env).filter((k) => k.startsWith("TB_")) });
if (mode === "exit3") process.exit(3);
process.on("SIGTERM", () => {
  record({ event: "SIGTERM", pid: process.pid });
  process.exit(42);
});
process.on("SIGHUP", () => record({ event: "SIGHUP", pid: process.pid }));
setInterval(() => {}, 1000);
