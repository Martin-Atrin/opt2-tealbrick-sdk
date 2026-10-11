// OpenAPI 3.1 generated in memory from the manifest (SDK-API §3.2 `GET /tb/v1/openapi.json`); never hand-written.
import { standardOpInputSchema } from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { OperationView } from "@opt2-tealbrick/spec/sdk";

const ANY_OBJECT = { type: "object" } as const;
const ERROR = {
  type: "object",
  required: ["error"],
  properties: { error: { type: "object", required: ["code", "message", "requestId"], properties: { code: { type: "string" }, message: { type: "string" }, requestId: { type: "string" }, details: ANY_OBJECT } } },
};

function inputSchema(op: OperationView): object {
  if (op.standard) return standardOpInputSchema(op.id);
  if (op.dynamic) return { type: "object", required: ["tool", "arguments"], properties: { tool: { type: "string" }, arguments: ANY_OBJECT } };
  return op.input ?? { type: "object", additionalProperties: false };
}

function outputSchema(op: OperationView): object {
  return !op.standard && op.output ? op.output : ANY_OBJECT;
}

export function buildOpenApi(manifest: Manifest, ops: readonly OperationView[], sdkVersion: string): object {
  const paths: Record<string, object> = {};
  for (const op of ops) {
    const agent = op.audience === "agent";
    const path = agent ? `/tb/v1/ops/${op.id}` : `/a/${manifest.id}/tb/v1/ops/${op.id}`;
    const okBody = { type: "object", required: ["status", "output"], properties: { status: { const: "ok" }, output: outputSchema(op), receiptId: { type: "string" } } };
    paths[path] = {
      post: {
        operationId: op.id,
        summary: op.title,
        ...(op.standard ? {} : { description: op.description }),
        "x-tealbrick": { crud: op.crud, effect: op.effect, audience: op.audience, idempotency: op.idempotency, receipt: op.receipt, standard: op.standard },
        security: agent ? [{ grant: [], callProof: [] }] : [{ session: [], csrf: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: agent
                ? { type: "object", required: ["input", "context"], properties: { input: inputSchema(op), context: ANY_OBJECT, idempotencyKey: { type: "string", minLength: 8, maxLength: 128 } } }
                : { type: "object", properties: { input: inputSchema(op), idempotencyKey: { type: "string", minLength: 8, maxLength: 128 } } },
            },
          },
        },
        responses: {
          "200": { description: "ok", content: { "application/json": { schema: okBody } } },
          ...(agent
            ? { "202": { description: "held", content: { "application/json": { schema: { type: "object", required: ["status", "holdId", "expiresAt"], properties: { status: { const: "held" }, holdId: { type: "string" }, expiresAt: { type: "string", format: "date-time" } } } } } } }
            : {}),
          default: { description: "error", content: { "application/json": { schema: ERROR } } },
        },
      },
    };
  }
  return {
    openapi: "3.1.0",
    info: { title: manifest.name, version: manifest.version, description: manifest.summary, "x-tealbrick-sdk": sdkVersion },
    paths,
    components: {
      securitySchemes: {
        grant: { type: "http", scheme: "bearer", bearerFormat: "tb-grant+jwt" },
        callProof: { type: "apiKey", in: "header", name: "TB-Call" },
        session: { type: "apiKey", in: "cookie", name: "tb_session" },
        csrf: { type: "apiKey", in: "header", name: "TB-CSRF" },
      },
    },
  };
}
