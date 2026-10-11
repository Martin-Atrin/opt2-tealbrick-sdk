// Minimal reader for the SDK archive formats (SDK-API §7.3: `tb-backup-*.tar.gz`, `tb-export-*.tar.gz`): gunzip +
// ustar/pax entries (regular files only). Read-only; used by the A7 checks to inspect what an app wrote.
import { gunzipSync } from "node:zlib";

export interface TarEntry {
  name: string;
  data: Uint8Array;
}

const BLOCK = 512;

function cstr(buf: Uint8Array, off: number, len: number): string {
  const slice = buf.subarray(off, off + len);
  const end = slice.indexOf(0);
  return new TextDecoder().decode(end === -1 ? slice : slice.subarray(0, end));
}

function paxPath(data: Uint8Array): string | null {
  for (const line of new TextDecoder().decode(data).split("\n")) {
    const m = /^\d+ path=(.*)$/.exec(line);
    if (m) return m[1];
  }
  return null;
}

/** Parses a (gzipped or plain) tar; throws on a malformed header. */
export function readTar(input: Uint8Array): TarEntry[] {
  const buf = input[0] === 0x1f && input[1] === 0x8b ? new Uint8Array(gunzipSync(input)) : input;
  const out: TarEntry[] = [];
  let off = 0;
  let nextName: string | null = null;
  while (off + BLOCK <= buf.length) {
    const header = buf.subarray(off, off + BLOCK);
    if (header.every((b) => b === 0)) break;
    const size = Number.parseInt(cstr(header, 124, 12).trim() || "0", 8);
    if (!Number.isFinite(size) || size < 0) throw new Error("tar: bad size");
    const type = String.fromCharCode(header[156] || 48);
    const prefix = cstr(header, 345, 155);
    const base = cstr(header, 0, 100);
    const data = buf.subarray(off + BLOCK, off + BLOCK + size);
    if (type === "x") nextName = paxPath(data);
    else if (type === "0" || type === "\0") {
      out.push({ name: nextName ?? (prefix ? `${prefix}/${base}` : base), data: new Uint8Array(data) });
      nextName = null;
    } else nextName = null;
    off += BLOCK + Math.ceil(size / BLOCK) * BLOCK;
  }
  return out;
}
