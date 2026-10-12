// The ONE privilege drop (C53 / BSA-05) with a fake process: chown -R of the data (+ outside backup) dir before
// setgroups/setgid/setuid, read-back verification, no-op when not root.
import assert from "node:assert/strict";
import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { TbError } from "../src/server/errors.ts";
import { dropPrivileges, type PrivilegeProc, RUN_GID, RUN_UID } from "../src/server/privilege.ts";
import { tempDir } from "./helpers.ts";

function fakeRoot(over: Partial<PrivilegeProc> = {}): { proc: PrivilegeProc; log: string[] } {
  const log: string[] = [];
  let uid = 0;
  let gid = 0;
  const proc: PrivilegeProc = {
    getuid: () => uid,
    getgid: () => gid,
    setgroups: (g) => log.push(`setgroups:${JSON.stringify(g)}`),
    setgid: (id) => {
      log.push(`setgid:${id}`);
      gid = id;
    },
    setuid: (id) => {
      log.push(`setuid:${id}`);
      uid = id;
    },
    chown: (p, u, g) => log.push(`chown:${p}:${u}:${g}`),
    ...over,
  };
  return { proc, log };
}

describe("dropPrivileges", () => {
  test("not root (or no POSIX ids) → no-op, nothing touched", () => {
    const calls: string[] = [];
    const proc: PrivilegeProc = { getuid: () => 501, setuid: () => calls.push("setuid"), setgid: () => calls.push("setgid"), chown: () => calls.push("chown") };
    assert.equal(dropPrivileges({ dataDir: "/nonexistent/data", backupDir: "/nonexistent/backup" }, proc), false);
    assert.equal(dropPrivileges({ dataDir: "/nonexistent/data", backupDir: "/nonexistent/backup" }, {}), false);
    assert.deepEqual(calls, []);
  });

  test("root → chown -R data dir (symlinks not followed) and an outside backup dir, then setgroups([]), setgid, setuid", () => {
    const t = tempDir();
    try {
      const data = join(t.dir, "data");
      const backup = join(t.dir, "backup"); // missing: created, then chowned
      mkdirSync(join(data, "sub"), { recursive: true });
      writeFileSync(join(data, "app.db"), "x");
      writeFileSync(join(data, "sub", "key"), "y");
      symlinkSync("/etc", join(data, "link"));
      const { proc, log } = fakeRoot();
      assert.equal(dropPrivileges({ dataDir: data, backupDir: backup }, proc), true);
      const owner = `${RUN_UID}:${RUN_GID}`;
      assert.deepEqual(
        log.filter((l) => l.startsWith("chown:")).sort(),
        [data, join(data, "app.db"), join(data, "link"), join(data, "sub"), join(data, "sub", "key"), backup].map((p) => `chown:${p}:${owner}`).sort(),
      );
      assert.deepEqual(log.slice(-3), ["setgroups:[]", `setgid:${RUN_GID}`, `setuid:${RUN_UID}`]);
      assert.equal(proc.getuid?.(), RUN_UID);
    } finally {
      t.cleanup();
    }
  });

  test("backup dir inside the data dir is not walked twice", () => {
    const t = tempDir();
    try {
      mkdirSync(join(t.dir, "backup"));
      const { proc, log } = fakeRoot();
      dropPrivileges({ dataDir: t.dir, backupDir: join(t.dir, "backup") }, proc);
      assert.equal(log.filter((l) => l === `chown:${join(t.dir, "backup")}:${RUN_UID}:${RUN_GID}`).length, 1);
    } finally {
      t.cleanup();
    }
  });

  test("a failing step, missing setuid, or ids that do not read back as 1000 → privilege_drop_failed", () => {
    const t = tempDir();
    try {
      const dirs = { dataDir: t.dir, backupDir: join(t.dir, "backup") };
      const failed = (e: unknown) => e instanceof TbError && e.code === "privilege_drop_failed";
      assert.throws(
        () =>
          dropPrivileges(
            dirs,
            fakeRoot({
              setuid: () => {
                throw new Error("EPERM");
              },
            }).proc,
          ),
        failed,
      );
      assert.throws(() => dropPrivileges(dirs, fakeRoot({ setuid: undefined }).proc), failed);
      assert.throws(() => dropPrivileges(dirs, fakeRoot({ setuid: () => undefined }).proc), failed);
      assert.throws(
        () =>
          dropPrivileges(
            dirs,
            fakeRoot({
              chown: () => {
                throw new Error("EROFS");
              },
            }).proc,
          ),
        failed,
      );
    } finally {
      t.cleanup();
    }
  });
});
