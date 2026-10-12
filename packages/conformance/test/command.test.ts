import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { procListeners } from "../src/checks/relay.ts";
import { spawnCommand, splitCommand } from "../src/command.ts";

describe("C55: targets run without a shell", () => {
  it("splitCommand: argv with quotes and escapes; shell syntax refused", () => {
    assert.deepEqual(splitCommand(`node "a b.ts" --x 'y z' c\\ d`), ["node", "a b.ts", "--x", "y z", "c d"]);
    for (const bad of ["a | b", "a && b", "a; b", "a > f", "echo $HOME", 'echo "$X"', "a `b`", "'unbalanced", ""]) assert.throws(() => splitCommand(bad), bad);
  });

  it("spawnCommand: the child pid IS the target (a signal reaches it, no dash in between)", async () => {
    const child = spawnCommand(`${process.execPath} -e "process.on('SIGUSR2',()=>{console.log('got');process.exit(0)});setInterval(()=>{},1000)"`, { stdio: ["ignore", "pipe", "inherit"] });
    let out = "";
    child.stdout?.on("data", (d: Buffer) => {
      out += d.toString();
    });
    await new Promise((r) => setTimeout(r, 300));
    process.kill(child.pid as number, "SIGUSR2");
    const code = await new Promise<number | null>((r) => child.once("exit", (c) => r(c)));
    assert.equal(code, 0);
    assert.match(out, /got/);
  });
});

describe("C55: B10.stdio_only /proc fallback", () => {
  it("finds a LISTEN tcp socket and any udp socket held by the tree; ignores others; null without /proc", () => {
    const root = mkdtempSync(join(tmpdir(), "procfake-"));
    try {
      mkdirSync(join(root, "net"));
      mkdirSync(join(root, "42", "fd"), { recursive: true });
      const hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
      writeFileSync(join(root, "net", "tcp"), `${hdr}   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1\n   1: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 222 1\n`);
      writeFileSync(join(root, "net", "udp"), `${hdr}   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 333 1\n`);
      symlinkSync("socket:[111]", join(root, "42", "fd", "3"));
      symlinkSync("socket:[222]", join(root, "42", "fd", "4"));
      symlinkSync("socket:[999]", join(root, "42", "fd", "5"));
      assert.deepEqual(procListeners([42], root), ["tcp 0100007F:1F90"], "only the LISTEN socket of pid 42 (outbound 222 ignored, 333 not ours)");
      symlinkSync("socket:[333]", join(root, "42", "fd", "6"));
      assert.deepEqual(procListeners([42], root), ["tcp 0100007F:1F90", "udp 00000000:0035"]);
      assert.equal(procListeners([42], join(root, "missing")), null);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
