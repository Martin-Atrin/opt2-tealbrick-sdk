// Minimal POSIX ustar + gzip (node:zlib) for the backup and export archives (SDK-API §7.3). Regular files only; names
// ≤ 255 bytes through the ustar prefix field. The reader refuses traversal, absolute names, links and other special
// entries, duplicate names, bad checksums and truncated archives (`archive_invalid`).
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { open } from "node:fs/promises";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip, createGzip } from "node:zlib";
import { TbError } from "./errors.ts";

const BLOCK = 512;
/** 11 octal digits in the ustar size field */
const MAX_ENTRY_BYTES = 8 ** 11 - 1;
const MAX_ENTRIES = 100_000;

export interface TarSource {
  /** archive path (`a/b/c`) */
  name: string;
  /** local file whose bytes become the entry */
  path: string;
  size: number;
}

export interface TarEntry {
  name: string;
  size: number;
}

/** Receives one entry's body; `end` runs after the last byte. */
export interface TarSink {
  write(chunk: Buffer): Promise<void>;
  end(): Promise<void>;
}

function invalid(reason: string): TbError {
  return new TbError("archive_invalid", `archive refused: ${reason}`, 500);
}

/** Relative, `/`-separated, no empty / `.` / `..` segment, no backslash or NUL, ≤ 255 bytes. */
export function safeEntryName(name: string): boolean {
  if (name.length === 0 || Buffer.byteLength(name) > 255) return false;
  if (name.startsWith("/") || name.includes("\\") || name.includes("\0")) return false;
  return name.split("/").every((s) => s !== "" && s !== "." && s !== "..");
}

function splitName(name: string): { name: string; prefix: string } {
  if (Buffer.byteLength(name) <= 100) return { name, prefix: "" };
  for (let i = name.lastIndexOf("/"); i > 0; i = name.lastIndexOf("/", i - 1)) {
    const prefix = name.slice(0, i);
    const rest = name.slice(i + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(rest) <= 100) return { name: rest, prefix };
  }
  throw invalid(`entry name does not fit ustar: ${name}`);
}

function octal(h: Buffer, offset: number, length: number, value: number): void {
  h.write(`${value.toString(8).padStart(length - 1, "0")}\0`, offset, length, "latin1");
}

function header(name: string, size: number, mtime: number): Buffer {
  if (!safeEntryName(name)) throw invalid(`unsafe entry name: ${name}`);
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_ENTRY_BYTES) throw invalid(`entry too large: ${name}`);
  const h = Buffer.alloc(BLOCK);
  const n = splitName(name);
  h.write(n.name, 0, 100, "utf8");
  octal(h, 100, 8, 0o644);
  octal(h, 108, 8, 0);
  octal(h, 116, 8, 0);
  octal(h, 124, 12, size);
  octal(h, 136, 12, mtime);
  h.fill(0x20, 148, 156);
  h.write("0", 156, "latin1");
  h.write("ustar\u000000", 257, "latin1");
  h.write(n.prefix, 345, 155, "utf8");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "latin1");
  return h;
}

async function* blocks(sources: readonly TarSource[], mtime: number): AsyncGenerator<Buffer> {
  for (const s of sources) {
    yield header(s.name, s.size, mtime);
    let n = 0;
    for await (const chunk of createReadStream(s.path)) {
      n += (chunk as Buffer).length;
      if (n > s.size) throw invalid(`${s.name} grew while archiving`);
      yield chunk as Buffer;
    }
    if (n !== s.size) throw invalid(`${s.name} shrank while archiving`);
    const pad = (BLOCK - (s.size % BLOCK)) % BLOCK;
    if (pad) yield Buffer.alloc(pad);
  }
  yield Buffer.alloc(BLOCK * 2);
}

/** Writes `sources` as a new .tar.gz at `out` (fails if `out` exists). */
export async function writeTarGz(out: string, sources: readonly TarSource[]): Promise<void> {
  await pipeline(Readable.from(blocks(sources, Math.floor(Date.now() / 1000))), createGzip(), createWriteStream(out, { flags: "wx" }));
}

function field(h: Buffer, offset: number, length: number): string {
  const raw = h.subarray(offset, offset + length);
  const end = raw.indexOf(0);
  return raw.subarray(0, end < 0 ? length : end).toString("utf8");
}

function parseOctal(h: Buffer, offset: number, length: number): number {
  const s = field(h, offset, length).trim();
  if (!/^[0-7]{1,12}$/.test(s)) throw invalid("malformed numeric header field");
  return Number.parseInt(s, 8);
}

function parseHeader(h: Buffer): TarEntry | "end" {
  if (h.every((b) => b === 0)) return "end";
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : (h[i] as number);
  if (parseOctal(h, 148, 8) !== sum) throw invalid("header checksum mismatch");
  if (h.toString("latin1", 257, 262) !== "ustar") throw invalid("not a ustar archive");
  const type = h[156];
  if (type !== 0x30 && type !== 0) throw invalid("only regular file entries are accepted");
  const name = field(h, 0, 100);
  const prefix = field(h, 345, 155);
  const full = prefix ? `${prefix}/${name}` : name;
  if (!safeEntryName(full)) throw invalid(`unsafe entry name: ${JSON.stringify(full.slice(0, 80))}`);
  return { name: full, size: parseOctal(h, 124, 12) };
}

/** Pull reader over a byte stream: `take(n)` exactly n bytes (null at a clean EOF), `upTo(n)` the next ≤ n bytes. */
function byteReader(source: AsyncIterable<Buffer>) {
  const it = source[Symbol.asyncIterator]();
  let buf: Buffer = Buffer.alloc(0);
  const pull = async (): Promise<boolean> => {
    const r = await it.next();
    if (r.done) return false;
    buf = buf.length ? Buffer.concat([buf, r.value]) : r.value;
    return true;
  };
  return {
    async take(n: number): Promise<Buffer | null> {
      while (buf.length < n) {
        if (!(await pull())) {
          if (buf.length === 0) return null;
          throw invalid("truncated archive");
        }
      }
      const out = buf.subarray(0, n);
      buf = buf.subarray(n);
      return out;
    },
    async upTo(n: number): Promise<Buffer> {
      if (buf.length === 0 && !(await pull())) throw invalid("truncated archive");
      const out = buf.subarray(0, Math.min(n, buf.length));
      buf = buf.subarray(out.length);
      return out;
    },
  };
}

/**
 * Streams the entries of a .tar.gz in order. `onEntry` returns a sink for the body, null to skip it, or "stop" to end
 * the read early. Every entry header is checked before `onEntry` sees it.
 */
export async function readTarGz(file: string, onEntry: (entry: TarEntry) => Promise<TarSink | null | "stop">): Promise<void> {
  const raw = createReadStream(file);
  const gunzip = createGunzip();
  raw.on("error", (e) => gunzip.destroy(e));
  raw.pipe(gunzip);
  const r = byteReader(gunzip);
  const seen = new Set<string>();
  try {
    for (;;) {
      const h = await r.take(BLOCK);
      if (h === null) throw invalid("missing end-of-archive marker");
      const entry = parseHeader(h);
      if (entry === "end") return;
      if (seen.has(entry.name)) throw invalid(`duplicate entry ${entry.name}`);
      seen.add(entry.name);
      if (seen.size > MAX_ENTRIES) throw invalid("too many entries");
      const sink = await onEntry(entry);
      if (sink === "stop") return;
      let left = entry.size;
      while (left > 0) {
        const chunk = await r.upTo(left);
        left -= chunk.length;
        if (sink) await sink.write(chunk);
      }
      if (sink) await sink.end();
      const pad = (BLOCK - (entry.size % BLOCK)) % BLOCK;
      if (pad && (await r.take(pad)) === null) throw invalid("truncated archive");
    }
  } catch (e) {
    if (e instanceof TbError) throw e;
    throw invalid(e instanceof Error ? e.message : "unreadable archive");
  } finally {
    raw.destroy();
    gunzip.destroy();
  }
}

/** Sink writing a new file (fails if it exists) and reporting its sha256 and size at `end`. */
export async function fileSink(path: string, done: (r: { sha256: string; bytes: number }) => void): Promise<TarSink> {
  const fh = await open(path, "wx");
  const hash = createHash("sha256");
  let bytes = 0;
  return {
    async write(chunk) {
      hash.update(chunk);
      bytes += chunk.length;
      await fh.write(chunk);
    },
    async end() {
      await fh.close();
      done({ sha256: hash.digest("hex"), bytes });
    },
  };
}

/** Sink collecting at most `limit` bytes in memory. */
export function bufferSink(limit: number, done: (b: Buffer) => void): TarSink {
  const chunks: Buffer[] = [];
  let bytes = 0;
  return {
    async write(chunk) {
      bytes += chunk.length;
      if (bytes > limit) throw invalid("entry larger than allowed");
      chunks.push(Buffer.from(chunk));
    },
    async end() {
      done(Buffer.concat(chunks));
    },
  };
}
