// Boots the mini app from the TB_* env on the port given as argv[2] (used by the CLI --cmd test).
import { readFileSync } from "node:fs";
import { startMiniApp } from "./mini-app.ts";

const manifest = JSON.parse(readFileSync(new URL("../fixtures/sample.manifest.json", import.meta.url), "utf8"));
const app = await startMiniApp(manifest, process.env as Record<string, string>, {}, Number(process.argv[2]));
process.on("SIGTERM", () => {
  app.stop().then(() => process.exit(0));
});
