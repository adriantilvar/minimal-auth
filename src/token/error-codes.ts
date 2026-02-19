export type ErrorCode =
	| "invalid_request"
	| "invalid_client"
	| "invalid_grant"
	| "unauthorized_client"
	| "unsupported_grant_type"
	| "invalid_scope";

/**
 * The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats
 * a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, contains
 * a `code_verifier` although no `code_challenge` was sent in the authorization request, or is otherwise malformed.
 */
export const INVALID_REQUEST: ErrorCode = "invalid_request" as const;

/**
 * Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication
 * method).
 *
 * Notes:
 * - The Authorization Server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP
 * authentication schemes are supported.
 * - If the client attempted to authenticate via the Authorization request header field, the Authorization Server MUST
 * respond with an HTTP 401 (Unauthorized) status code and include the `WWW-Authenticate` response header field matching
 * the authentication scheme used by the client.
 */
export const INVALID_CLIENT: ErrorCode = "invalid_client" as const;

/**
 * The provided authorization grant (e.g., authorization code, Resource Owner credentials) or refresh token is invalid,
 * expired, revoked, does not match the redirect URI used in the authorization request, or was issued to another client.
 */
export const INVALID_GRANT: ErrorCode = "invalid_grant" as const;

/**
 * The authenticated client is not authorized to use this authorization grant type.
 */
export const UNAUTHORIZED_CLIENT: ErrorCode = "unauthorized_client" as const;

/**
 * The authorization grant type is not supported by the Authorization Server.
 */
export const UNSUPPORTED_GRANT_TYPE: ErrorCode =
	"unsupported_grant_type" as const;

/**
 * The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the Resource Owner.
 */
export const INVALID_SCOPE: ErrorCode = "invalid_scope" as const;
