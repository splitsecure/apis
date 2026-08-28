/** The protocol error codes the hub defines (wire.lock [error]). */
export type KnownProtocolErrorCode =
  | "approver_set_too_large"
  | "duplicate_request"
  | "invalid_callback_url"
  | "invalid_signature"
  | "malformed_request"
  | "operator_depth_exceeded"
  | "request_not_found"
  | "timestamp_out_of_range"
  | "unknown_approver"
  | "unknown_category"
  | "unknown_sender"
  | "wrong_recipient";

/** A known code, or a code this SDK build doesn't recognize yet (forward compat). */
export type ProtocolErrorCode = KnownProtocolErrorCode | (string & {});

const STATUS_FOR_CODE: Record<KnownProtocolErrorCode, number> = {
  approver_set_too_large: 400,
  duplicate_request: 409,
  invalid_callback_url: 400,
  invalid_signature: 401,
  malformed_request: 400,
  operator_depth_exceeded: 400,
  request_not_found: 404,
  timestamp_out_of_range: 400,
  unknown_approver: 400,
  unknown_category: 400,
  unknown_sender: 401,
  wrong_recipient: 403,
};

const DEFAULT_HTTP_STATUS = 400; // wire.lock: "default = http.StatusBadRequest"

/** An error the hub returned for a protocol request (wire.lock [error]). */
export class ProtocolError extends Error {
  readonly httpStatus: number;
  readonly code: ProtocolErrorCode;

  constructor(code: ProtocolErrorCode, message: string, httpStatus?: number) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
    this.httpStatus =
      httpStatus ??
      (Object.hasOwn(STATUS_FOR_CODE, code)
        ? STATUS_FOR_CODE[code as KnownProtocolErrorCode]
        : DEFAULT_HTTP_STATUS);
  }
}

/** A request that never reached the hub. */
export class TransportError extends Error {
  constructor(cause: unknown) {
    super(`stepauth: transport error: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "TransportError";
    this.cause = cause;
  }
}

/**
 * Reports whether a caller can retry err unchanged: a transport-level failure,
 * or a hub 5xx. Every other ProtocolError, including an unrecognized code, is
 * not retryable: each is a verdict on the exact bytes sent, so resending them
 * unchanged cannot change it.
 */
export function isRetryable(err: unknown): boolean {
  if (err instanceof TransportError) return true;
  return err instanceof ProtocolError && err.httpStatus >= 500;
}
