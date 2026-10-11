// Test harness: Portal + bridge key pairs, a fake bridge internal API (claim, status long-poll), and token helpers
// built ONLY from the manifest package's signers (no hand-rolled JWS).
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { digest, type Ed25519KeyPair, generateKeyPair, signCallProof, signGrant, signSlice, signTicket, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceSlice } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, BridgeId, InstanceId, PersonId, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, HoldFamily } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";

export const nowS = () => Math.floor(Date.now() / 1000);

export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createNetServer();
    s.once("error", reject);
    s.listen(0, () => {
      const a = s.address();
      const port = typeof a === "object" && a ? a.port : 0;
      s.close(() => resolve(port));
    });
  });
}

export function tempDir(prefix = "tb-sdk-test-"): { dir: string; cleanup(): void } {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export function migrationsDir(root: string, files: Record<string, string> = { "0001_init.sql": "CREATE TABLE notes (id TEXT PRIMARY KEY, notebook TEXT NOT NULL, title TEXT NOT NULL);" }): string {
  const dir = join(root, "migrations");
  mkdirSync(dir, { recursive: true });
  for (const [f, body] of Object.entries(files)) writeFileSync(join(dir, f), body);
  return dir;
}

export interface World {
  portal: Ed25519KeyPair;
  bridgeKey: Ed25519KeyPair;
  ws: WorkspaceId;
  brg: BridgeId;
  ins: InstanceId;
  per: PersonId;
  agents: { a: AgentId; b: AgentId };
  rev: number;
}

export async function world(): Promise<World> {
  return {
    portal: await generateKeyPair(),
    bridgeKey: await generateKeyPair(),
    ws: `ws_${ulid()}`,
    brg: `brg_${ulid()}`,
    ins: `ins_${ulid()}`,
    per: `per_${ulid()}`,
    agents: { a: `agt_${ulid()}`, b: `agt_${ulid()}` },
    rev: 0,
  };
}

export async function slice(w: World, product: string, over: Partial<Pick<InstanceSlice, "pause" | "agents" | "grants" | "personNbf">> = {}): Promise<string> {
  w.rev += 1;
  const self = `tb:ins:${w.ins}` as const;
  return signSlice(
    {
      iss: "tb:portal",
      sub: self,
      aud: self,
      iat: nowS(),
      ws: w.ws,
      v: 1,
      rev: w.rev,
      ins: w.ins,
      product,
      portalKeys: [{ jwk: w.portal.publicJwk, status: "active" }],
      bridge: { id: w.brg, keys: [w.bridgeKey.publicJwk] },
      pause: over.pause ?? { workspace: false, agents: [], instances: [] },
      revoked: { jtis: [] },
      personNbf: over.personNbf ?? 0,
      grants: over.grants ?? [],
      agents: over.agents ?? [
        { id: w.agents.a, name: "Agent A", mode: "free", status: "active" },
        { id: w.agents.b, name: "Agent B", mode: "free", status: "active" },
      ],
    },
    w.portal,
  );
}

export async function grant(w: World, agent: AgentId, opts: { crud?: CrudAction[]; held?: HoldFamily[]; aud?: InstanceId } = {}): Promise<string> {
  return signGrant(
    {
      iss: "tb:portal",
      sub: `tb:agt:${agent}`,
      aud: `tb:ins:${opts.aud ?? w.ins}`,
      iat: nowS(),
      ws: w.ws,
      cnf: { brg: w.brg },
      crud: opts.crud ?? ["create", "read", "update", "delete"],
      mode: "free",
      held: opts.held ?? [],
      caps: {},
      wf: [],
      polrev: 1,
    },
    w.portal,
  );
}

export async function callProof(w: World, grantToken: string, op: string, input: Json, context: Record<string, Json> = {}, over: { aud?: InstanceId; inputFor?: Json } = {}): Promise<string> {
  const g = JSON.parse(Buffer.from(grantToken.split(".")[1] as string, "base64url").toString("utf8")) as { jti: string; sub: `tb:agt:${string}` };
  return signCallProof(
    {
      iss: `tb:brg:${w.brg}`,
      sub: g.sub as `tb:agt:${AgentId}`,
      aud: `tb:ins:${over.aud ?? w.ins}`,
      iat: nowS(),
      call: `call_${ulid()}`,
      gjti: g.jti,
      op,
      in: digest(over.inputFor ?? input),
      ctx: digest(context),
    },
    w.bridgeKey,
  );
}

export async function ticket(w: World, path = "/"): Promise<string> {
  return signTicket({ iss: "tb:portal", sub: `tb:per:${w.per}`, aud: `tb:ins:${w.ins}`, iat: nowS(), ws: w.ws, pur: "launch", path }, w.portal);
}

/** Fake bridge internal listener: claim + status long-poll (answers at once when a new slice is pushed). */
export class FakeBridge {
  readonly w: World;
  server: Server | null = null;
  port = 0;
  claims = 0;
  instanceKey: import("@opt2-tealbrick/spec/credentials").Ed25519PublicJwk | null = null;
  statuses: Record<string, unknown>[] = [];
  #slice: string | null = null;
  #rev = 0;
  #waiting: ServerResponse[] = [];

  constructor(w: World) {
    this.w = w;
  }

  async start(initialSlice: string): Promise<string> {
    this.#slice = initialSlice;
    this.#rev = this.w.rev;
    this.server = createServer((req, res) => void this.#handle(req, res));
    this.port = await freePort();
    await new Promise<void>((r) => this.server?.listen(this.port, "127.0.0.1", r));
    return `http://127.0.0.1:${this.port}`;
  }

  push(token: string): void {
    this.#slice = token;
    this.#rev = this.w.rev;
    for (const res of this.#waiting.splice(0)) this.#answer(res);
  }

  #answer(res: ServerResponse): void {
    if (res.writableEnded) return;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ slice: this.#slice, sliceRevision: this.#rev, keysRev: 0 }));
  }

  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : null;
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/tb/v1/claim") {
      this.claims += 1;
      this.instanceKey = body?.instancePublicKey ?? null;
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end(JSON.stringify({ ins: this.w.ins, bridge: { id: this.w.brg, publicKey: this.w.bridgeKey.publicJwk, internalUrl: `http://127.0.0.1:${this.port}` }, slice: this.#slice, _code: body?.code ? "seen" : "none" }));
    }
    if (url.pathname === "/tb/v1/status") {
      if (!req.headers["tb-assert"]) {
        res.writeHead(401);
        return void res.end();
      }
      this.statuses.push(body);
      if (body?.sliceRevision !== this.#rev) return this.#answer(res);
      const wait = Number(url.searchParams.get("wait") ?? "0");
      if (wait === 0) {
        res.writeHead(204);
        return void res.end();
      }
      this.#waiting.push(res);
      const t = setTimeout(() => {
        this.#waiting = this.#waiting.filter((r) => r !== res);
        if (!res.writableEnded) {
          res.writeHead(204);
          res.end();
        }
      }, 1500);
      t.unref();
      return;
    }
    res.writeHead(404);
    res.end();
  }

  async stop(): Promise<void> {
    for (const r of this.#waiting.splice(0)) r.end();
    this.server?.closeAllConnections();
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }
}

export async function until<T>(fn: () => Promise<T | undefined | null | false>, ms = 5000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error("until: timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}
