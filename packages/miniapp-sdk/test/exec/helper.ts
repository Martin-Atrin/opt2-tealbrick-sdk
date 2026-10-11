// Tiny service helper for tb-exec tests: echoes what reached it.
import { createServer } from "node:http";

const port = Number(process.argv[2]);
createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ path: req.url, method: req.method, body: Buffer.concat(chunks).toString("utf8"), assert: req.headers["tb-assert"] ?? null }));
}).listen(port, "127.0.0.1");
