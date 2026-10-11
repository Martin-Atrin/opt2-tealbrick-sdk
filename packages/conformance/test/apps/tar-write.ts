// Test-only ustar + gzip writer (the mini app's backup/export archives).
import { gzipSync } from "node:zlib";

function header(name: string, size: number): Buffer {
  const h = Buffer.alloc(512, 0);
  h.write(name, 0, 100, "utf8");
  h.write("0000644\0", 100, "latin1");
  h.write("0000000\0", 108, "latin1");
  h.write("0000000\0", 116, "latin1");
  h.write(`${size.toString(8).padStart(11, "0")}\0`, 124, "latin1");
  h.write(`${Math.floor(Date.now() / 1000).toString(8).padStart(11, "0")}\0`, 136, "latin1");
  h.write("        ", 148, "latin1");
  h.write("0", 156, "latin1");
  h.write("ustar\u000000", 257, "latin1");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
  return h;
}

export function writeTarGz(entries: { name: string; data: Uint8Array }[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    parts.push(header(e.name, e.data.length), Buffer.from(e.data));
    const pad = (512 - (e.data.length % 512)) % 512;
    if (pad) parts.push(Buffer.alloc(pad, 0));
  }
  parts.push(Buffer.alloc(1024, 0));
  return gzipSync(Buffer.concat(parts));
}
