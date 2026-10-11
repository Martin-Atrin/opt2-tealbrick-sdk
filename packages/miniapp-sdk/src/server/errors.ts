// TbError and the ONE error envelope (CORE §8). Handlers throw TbError; the SDK maps it to the envelope.
import type { ErrorEnvelope } from "@opt2-tealbrick/spec/bridge";

export class TbError extends Error {
  readonly code: string;
  readonly httpStatus: number;
  readonly details: Record<string, unknown> | undefined;
  constructor(code: string, message: string, httpStatus = 400, details?: Record<string, unknown>) {
    super(message);
    this.name = "TbError";
    this.code = code;
    this.httpStatus = httpStatus;
    this.details = details;
  }
}

export function isTbError(e: unknown): e is TbError {
  return e instanceof TbError;
}

/** CORE §8 envelope; `details` only when the caller passed some. */
export function envelope(code: string, message: string, requestId: string, details?: Record<string, unknown>): ErrorEnvelope & { error: { details?: Record<string, unknown> } } {
  return { error: details ? { code, message, requestId, details } : { code, message, requestId } };
}
