#!/usr/bin/env node
// `tb-gen` binary (SDK-API §15, §17): generated artifacts from tealbrick.manifest.json.
import { runTbGen } from "./main.ts";

process.exitCode = runTbGen(process.argv.slice(2), {
  cwd: process.cwd(),
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
});
