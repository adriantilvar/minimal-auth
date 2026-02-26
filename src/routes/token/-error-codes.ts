// Error codes
const ErrorCodes = {
	/**
	 * The request is missing a required parameter, includes an unsupported
	 * parameter value (other than grant type), repeats a parameter, includes
	 * multiple credentials, utilizes more than one mechanism for authenticating
	 * the client, contains a `code_verifier` although no `code_challenge` was sent
	 * in the authorization request, or is otherwise malformed.
	 */
	INVALID_REQUEST: "invalid_request",

	/**
	 * Client authentication failed (e.g., unknown client, no client authentication
	 * included, or unsupported authentication method).
	 *
	 * Notes:
	 * - The Authorization Server MAY return an HTTP 401 (Unauthorized) status code
	 *  to indicate which HTTP authentication schemes are supported.
	 * - If the client attempted to authenticate via the Authorization request header
	 * field, the Authorization Server MUST respond with an HTTP 401 (Unauthorized)
	 * status code and include the `WWW-Authenticate` response header field matching
	 * the authentication scheme used by the client.
	 */
	INVALID_CLIENT: "invalid_client",

	/**
	 * The provided authorization grant (e.g., authorization code, Resource Owner
	 * credentials) or refresh token is invalid, expired, revoked, does not match the
	 * redirect URI used in the authorization request, or was issued to another client.
	 */
	INVALID_GRANT: "invalid_grant",

	/**
	 * The authenticated client is not authorized to use this authorization grant type.
	 */
	UNAUTHORIZED_CLIENT: "unauthorized_client",

	/**
	 * The authorization grant type is not supported by the Authorization Server.
	 */
	UNSUPPORTED_GRANT_TYPE: "unsupported_grant_type",

	/**
	 * The requested scope is invalid, unknown, malformed, or exceeds the scope granted
	 *  by the Resource Owner.
	 */
	INVALID_SCOPE: "invalid_scope",
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
