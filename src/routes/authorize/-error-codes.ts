export const ErrorCodes = {
	/**
	 * The request is missing a required parameter, includes an unsupported
	 * parameter value (other than grant type), repeats a parameter, includes
	 * multiple credentials, utilizes more than one mechanism for authenticating
	 * the client, contains a `code_verifier` although no `code_challenge` was
	 * sent in the authorization request, or is otherwise malformed.
	 */
	INVALID_REQUEST: "invalid_request",

	/**
	 * The authenticated client is not authorized to use this authorization
	 * grant type.
	 */
	UNAUTHORIZED_CLIENT: "unauthorized_client",

	/**
	 * The Resource Owner or Authorization Server denied the request.
	 */
	ACCESS_DENIED: "access_denied",

	/**
	 * The Authorization Server does not support obtaining an authorization code
	 * using this method.
	 */
	UNSUPPORTED_RESPONSE_TYPE: "unsupported_response_type",

	/**
	 * The requested scope is invalid, unknown, or malformed.
	 */
	INVALID_SCOPE: "invalid_scope",

	/**
	 * The Authorization Server encountered an unexpected condition that prevented
	 * it from fulfilling the request.
	 *
	 * Note: This error is needed because a HTTP 500 (Internal Server Error) status
	 * code cannot be returned to the client via an HTTP redirect.
	 */
	SERVER_ERROR: "server_error",

	/**
	 * The Authorization Server is currently unable to handle the request due to
	 * temporary overloading or maintenance.
	 *
	 * Note: This error is needed because a HTTP 503 (Service Unavailable) status
	 * code cannot be returned to the client via
	 * an HTTP redirect.
	 */
	TEMPORARILY_UNAVAILABLE: "temporarily_unavailable",
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
