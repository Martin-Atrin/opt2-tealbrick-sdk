// A free TCP port on 127.0.0.1 (tests that must know the app URL before it boots).
import { createServer } from "node:net";

export function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as { port: number }).port;
      srv.close(() => resolve(port));
    });
  });
}
