import { Hono, type HonoRequest } from "hono";
import { BAD_REQUEST } from "../lib/http/response-status-codes.js";
import type { OAuthClient, OAuthProvider } from "../lib/types.js";
import { containsFragment } from "../lib/utils.js";

/**
 * The Authorization Server MUST support the use of the HTTP GET method (Section 9.3.1 of [RFC9110]) for the
 * authorization endpoint and MAY support the POST method (Section 9.3.3 of [RFC9110]) as well.
 *
 * The /authorization endpoint URL MUST NOT include a fragment component. It MAY include a query string component,
 * which MUST be retained when adding additional query parameters.
 *
 * An Authorization Server that redirects a request potentially containing user credentials MUST avoid forwarding
 * these user credentials accidentally (see Section 7.5.4 for details).
 *
 * Cross-Origin Resource Sharing [WHATWG.CORS] MUST NOT be supported at the /authorization endpoint, as the client
 * does not access this endpoint directly. Instead, the client redirects the user agent to it.
 */
const authorization = new Hono();

//
authorization.get("/", async (ctx) => {
	if (containsFragment(ctx.req.url)) {
		return ctx.json<ErrorResponse>(
			{
				error: INVALID_REQUEST,
				error_description: "Request URI cannot contain a fragment component",
			},
			BAD_REQUEST.code,
		);
	}

	const response_type = getUniqueQuery(ctx.req, "response_type");
	if (!response_type) {
		return ctx.json<ErrorResponse>(
			{
				error: INVALID_REQUEST,
				error_description:
					"Request URI must include a `response_type` query parameter. It must not be included more than once.",
			},
			BAD_REQUEST.code,
		);
	}

	if (response_type !== "code") {
		return ctx.json<ErrorResponse>(
			{
				error: UNSUPPORTED_RESPONSE_TYPE,
				error_description:
					"This server can only provide authorization code grants. If you wish to obtain an authorization code, you must set the value of the `response_type` query parameter to 'code'.",
			},
			BAD_REQUEST.code,
		);
	}

	const code_challenge = getUniqueQuery(ctx.req, "code_challenge");
	if (!code_challenge) {
		return ctx.json<ErrorResponse>(
			{
				error: INVALID_REQUEST,
				error_description:
					"Request URI must include a `code_challenge` query parameter. It must not be included more than once.",
			},
			BAD_REQUEST.code,
		);
	}

	const code_challenge_method = getUniqueQuery(ctx.req, "code_challenge_method");
	if (!code_challenge_method) {
		return ctx.json<ErrorResponse>(
			{
				error: INVALID_REQUEST,
				error_description:
					"Request URI must include a `code_challenge_method` query parameter. It must not be included more than once.",
			},
			BAD_REQUEST.code,
		);
	}

	if (!isValidCodeChallengeMethod(code_challenge_method)) {
		return ctx.json<ErrorResponse>(
			{
				error: INVALID_REQUEST,
				error_description:
					"The provided `code_challenge_method` is not valid. For the time being, this server supports only `S256` as the value of the `code_challenge_method`",
			},
			BAD_REQUEST.code,
		);
	}

	const client_id = getUniqueQuery(ctx.req, "client_id");
	if (!client_id) {
		return ctx.json<ErrorResponse>(
			{
				error: INVALID_REQUEST,
				error_description:
					"Request URI must include a `client_id` query parameter. It must not be included more than once.",
			},
			BAD_REQUEST.code,
		);
	}

	const client = findOAuthClientById(client_id);
	// The client must be registered with the Authorization Server before initiating the protocol
	if (!client) {
		return ctx.json<ErrorResponse>(
			{
				error: UNAUTHORIZED_CLIENT,
				error_description:
					"No client is registered with the provided `client_id`. You need to register the client before requesting an authorization grant.",
			},
			BAD_REQUEST.code,
		);
	}

	const redirect_uri = getUniqueQuery(ctx.req, "redirect_uri");

	if (client.redirectUris.length > 1 && !redirect_uri) {
		return ctx.json<ErrorResponse>(
			{
				error: INVALID_REQUEST,
				error_description:
					"The request URI must include a `redirect_uri` query parameter, because the client has multiple redirect URIs registered with the server. It must not be included more than once.",
			},
			BAD_REQUEST.code,
		);
	}

	// The client must have passed a `redirect_uri`, or the client has only one registered redirect URI
	const redirectUri = redirect_uri ?? client.redirectUris[0];

	if (!isValidUri(redirectUri, client_id)) {
		return ctx.json<ErrorResponse>(
			{
				error: INVALID_REQUEST,
				error_description: "The provided `redirect_uri` is not valid for the client registered with the server.",
			},
			BAD_REQUEST.code,
		);
	}

	// Request is valid as far as the server is concerned at this point -> continue on client/authorization-code
	const authorization_uri = new URL("/authorization-code");
	authorization_uri.searchParams.set("response_type", response_type);
	authorization_uri.searchParams.set("code_challenge", code_challenge);
	authorization_uri.searchParams.set("code_challenge_method", code_challenge_method);
	authorization_uri.searchParams.set("client_id", client_id);

	return ctx.redirect(authorization_uri.toString());
});

// Functions (illustration purposes only)
function getUniqueQuery(req: HonoRequest<"/">, paramName: string): string | null {
	const param = req.queries(paramName);
	return param?.length === 1 ? param[0] : null;
}

function isValidCodeChallengeMethod(method: string) {
	return method === "S256";
}

function findOAuthClientById(_clientId: string): OAuthClient | null {
	return null;
}

function isValidUri(_uri: string, _clientId: string) {
	// The only exception is native apps using a localhost URI: In this case, the Authorization Server MUST allow variable port numbers as described in Section 7.3 of [RFC8252].
	return false;
}

// Responses
type SuccessResponse = {
	/**
	 * The authorization code generated by the Authorization Server, opaque to
	 * the client and bound to the client_id, code_challenge, and redirect_uri.
	 * It MUST expire shortly after it is issued to mitigate the risk of leaks.
	 * A maximum lifetime of 10 minutes is RECOMMENDED.
	 */
	code: string;
	/**
	 * The exact value received from the client. It is required only if the
	 * state parameter was present in the client authorization request.
	 */
	state?: unknown;
	/**
	 * The identifier of the Authorization Server, if the client interacts with
	 * more than one.
	 */
	iss?: OAuthProvider;
};

type ErrorResponse = {
	error: AuthorizationErrorCode;
	/**
	 * Human-readable ASCII text providing additional information, used to assist
	 * the client developer in understanding the error that occurred.
	 *
	 * Note: **MUST NOT** include characters outside the set %x20-21 / %x23-5B / %x5D-7E
	 */
	error_description?: string;
	/**
	 * A URI identifying a human-readable web page, used to provide the client
	 * developer with additional information about the error.
	 *
	 * Note: **MUST NOT** include characters outside the set %x21 / %x23-5B / %x5D-7E.
	 */
	error_uri?: string;
	/**
	 * The exact value received from the client. It is required if a state parameter
	 * was present in the client authorization request.
	 */
	state?: unknown;
	/**
	 * The identifier of the Authorization Server.
	 */
	iss?: OAuthProvider;
};

// Error Codes
export type AuthorizationErrorCode =
	| "invalid_request"
	| "unauthorized_client"
	| "access_denied"
	| "unsupported_response_type"
	| "invalid_scope"
	| "server_error"
	| "temporarily_unavailable";

/**
 * The request is missing a required parameter, includes an unsupported
 * parameter value (other than grant type), repeats a parameter, includes
 * multiple credentials, utilizes more than one mechanism for authenticating
 * the client, contains a `code_verifier` although no `code_challenge` was
 * sent in the authorization request, or is otherwise malformed.
 */
export const INVALID_REQUEST = "invalid_request" as const;

/**
 * The authenticated client is not authorized to use this authorization
 * grant type.
 */
export const UNAUTHORIZED_CLIENT = "unauthorized_client" as const;

/**
 * The Resource Owner or Authorization Server denied the request.
 */
export const ACCESS_DENIED = "access_denied" as const;

/**
 * The Authorization Server does not support obtaining an authorization code using this method.
 */
export const UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type" as const;

/**
 * The requested scope is invalid, unknown, or malformed.
 */
export const INVALID_SCOPE = "invalid_scope" as const;

/**
 * The Authorization Server encountered an unexpected condition that prevented it from fulfilling the request.
 *
 * Note: This error is needed because a HTTP 500 (Internal Server Error) status code cannot be returned to the client
 * via an HTTP redirect.
 */
export const SERVER_ERROR = "server_error" as const;

/**
 * The Authorization Server is currently unable to handle the request due to temporary overloading or maintenance.
 *
 * Note: This error is needed because a HTTP 503 (Service Unavailable) status code cannot be returned to the client via
 * an HTTP redirect.
 */
export const TEMPORARILY_UNAVAILABLE = "temporarily_unavailable" as const;

export default authorization;
