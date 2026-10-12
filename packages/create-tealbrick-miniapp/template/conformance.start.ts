// Conformance harness (CONFORMANCE §2, app target): `tb-conformance app --start conformance.start.ts` boots the app with
// the env the suite gives it (fake bridge, enrolment code, TB_KEK, data dir) and drives it like the bridge does. The SDK
// listens on manifest `runtime.port` (SDK-API §13); `backupNow` lets the suite run the backup/restore round-trip (A7).
// `--test-roots` (C63): the suite passes TEST Portal Root Keys in TBCONF_PORTAL_ROOT_KEYS; only this harness reads it and
// hands them to startApp, so the key-set checks (A13) run against test roots. Production never reads that variable.
import { startApp } from "@opt2-tealbrick/miniapp-sdk";
import { app, manifest } from "./src/app.ts";

export default async function start(env: Record<string, string>): Promise<{ url: string; stop(): Promise<void>; backupNow(): Promise<void> }> {
  const harness = env.TBCONF_PORTAL_ROOT_KEYS ? ({ portalRootKeys: JSON.parse(env.TBCONF_PORTAL_ROOT_KEYS) } as Parameters<typeof startApp>[2]) : undefined;
  const running = await startApp(app, env, harness);
  return {
    url: `http://127.0.0.1:${manifest.runtime.port}`,
    stop: () => running.stop(),
    backupNow: async () => {
      await running.backups.runNow();
    },
  };
}
