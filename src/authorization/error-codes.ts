export type ErrorCode =
	| "invalid_request"
	| "unauthorized_client"
	| "access_denied"
	| "unsupported_response_type"
	| "invalid_scope"
	| "server_error"
	| "temporarily_unavailable";

/**
 * The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than
 * once, or is otherwise malformed.
 */
export const INVALID_REQUEST: ErrorCode = "invalid_request" as const;

/**
 * The client is not authorized to request an authorization code using this method.
 */
export const UNAUTHORIZED_CLIENT: ErrorCode = "unauthorized_client" as const;

/**
 * The Resource Owner or Authorization Server denied the request.
 */
export const ACCESS_DENIED: ErrorCode = "access_denied" as const;

/**
 * The Authorization Server does not support obtaining an authorization code using this method.
 */
export const UNSUPPORTED_RESPONSE_TYPE: ErrorCode =
	"unsupported_response_type" as const;

/**
 * The requested scope is invalid, unknown, or malformed.
 */
export const INVALID_SCOPE: ErrorCode = "invalid_scope" as const;

/**
 * The Authorization Server encountered an unexpected condition that prevented it from fulfilling the request.
 *
 * Note: This error is needed because a HTTP 500 (Internal Server Error) status code cannot be returned to the client
 * via an HTTP redirect.
 */
export const SERVER_ERROR: ErrorCode = "server_error" as const;

/**
 * The Authorization Server is currently unable to handle the request due to temporary overloading or maintenance.
 *
 * Note: This error is needed because a HTTP 503 (Service Unavailable) status code cannot be returned to the client via
 * an HTTP redirect.
 */
export const TEMPORARILY_UNAVAILABLE: ErrorCode =
	"temporarily_unavailable" as const;
