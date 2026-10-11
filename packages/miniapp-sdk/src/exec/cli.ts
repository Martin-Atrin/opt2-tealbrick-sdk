#!/usr/bin/env node
// `tb-exec` binary (SDK-API §11, C33): wrapper entrypoint of companion-service images.
import { FORWARDED_SIGNALS, startTbExec } from "./run.ts";

const handle = startTbExec({ argv: process.argv.slice(2), env: process.env });
for (const sig of FORWARDED_SIGNALS) process.on(sig, () => handle.signal(sig));
process.exitCode = await handle.exited;
process.exit();
