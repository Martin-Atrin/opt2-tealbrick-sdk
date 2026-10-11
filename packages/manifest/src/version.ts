// SDK major rule (CORE §11, C35 item 6, C44): the SDK ships as 0.x during opt2; 0.x counts as major 1 until SDK 1.0.

/** Major of an SDK semver string; `0.x.y` → 1. Throws on a non-semver input. */
export function sdkMajorOf(version: string): number {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.+-]*)?$/.exec(version);
  if (!m) throw new TypeError(`sdkMajorOf: not a semver version: ${JSON.stringify(version)}`);
  const major = Number(m[1]);
  return major === 0 ? 1 : major;
}

/** Bridge/Core rule: the current major and the one before are served (CORE §11). */
export function sdkMajorServed(version: string, currentMajor: number): boolean {
  const major = sdkMajorOf(version);
  return major === currentMajor || major === currentMajor - 1;
}
