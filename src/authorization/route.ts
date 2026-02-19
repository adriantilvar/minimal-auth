import { Hono } from "hono";
import { containsFragment } from "../lib/utils.js";
import * as ErrorCodes from "./error-codes.js";

type ErrorResponse = {
	/**
	 * OAuth 2.0 defined error code.
	 */
	error: ErrorCodes.ErrorCode;
	/**
	 * Human-readable ASCII text providing additional information, used to assist the client developer in understanding
	 * the error that occurred.
	 *
	 * Note: **MUST NOT** include characters outside the set %x20-21 / %x23-5B / %x5D-7E
	 */
	error_description?: string;
	/**
	 * A URI identifying a human-readable web page, used to provide the client developer with additional information
	 * about the error.
	 *
	 * Note: **MUST NOT** include characters outside the set %x21 / %x23-5B / %x5D-7E.
	 */
	error_uri?: string;
	/**
	 * The exact value received from the client. It is required if a state parameter was present in the client
	 * authorization request.
	 */
	state?: string;
	/**
	 * The identifier of the Authorization Server.
	 */
	iss?: string;
};

type AuthorizationDecision =
	| { accessGranted: true }
	| { accessGranted: false; denialReason: string };

const authorization = new Hono();

/**
 * The Authorization Server MUST support the use of the HTTP GET method (Section 9.3.1 of [RFC9110]) for the
 * authorization endpoint and MAY support the POST method (Section 9.3.3 of [RFC9110]) as well.
 *
 * The /authorization endpoint URL MUST NOT include a fragment component. It MAY include a query string component,
 * which MUST be retained when adding additional query parameters.
 *
 * An Authorization Server that redirects a request potentially containing user credentials MUST avoid forwarding these
 * user credentials accidentally (see Section 7.5.4 for details).
 *
 * Cross-Origin Resource Sharing [WHATWG.CORS] MUST NOT be supported at the /authorization endpoint, as the client does
 * not access this endpoint directly. Instead, the client redirects the user agent to it.
 */

/**
 * Notes:
 * - ctx.redirect uses `HTTP 302 (Found)` status code by default
 * - Scope and state SHOULD NOT include sensitive client or Resource Owner information in plain text
 *
 * Example:
 * ```bash
 * GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
 *     &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
 *     &code_challenge=6fdkQaPm51l13DSukcAH3Mdx7_ntecHYd1vi3n0hMZY
 *     &code_challenge_method=S256 HTTP/1.1
 * Host: server.example.com
 * ```
 */
authorization.get("/", async (ctx) => {
	if (containsFragment(ctx.req.url)) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: "Request URI cannot contain a fragment component",
			},
			400,
		);
	}

	/**
	 * The Authorization Server must first authenticate the Resource Owner (via user agent).
	 */

	const response_type = ctx.req.query("response_type");
	const client_id = ctx.req.query("client_id");
	const code_challenge = ctx.req.query("code_challenge");
	const code_challenge_method =
		ctx.req.query("code_challenge_method") ?? "plain";
	const redirect_uri = ctx.req.query("redirect_uri");
	const scope = ctx.req.query("scope") ?? DEFAULT_AUTHORIZATION_SCOPE;
	const state = ctx.req.query("state");

	if (!response_type) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description:
					"Request URI must include a `response_type` query parameter",
			},
			400,
		);
	}

	if (!isValidResponseType(response_type)) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.UNSUPPORTED_RESPONSE_TYPE,
				error_description: "The provided `response_type` is not supported",
			},
			400,
		);
	}

	if (response_type === "code") {
		// Redirect flow done with the user agent
		if (!code_challenge) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"Request URI must include a `code_challenge` query parameter",
				},
				400,
			);
		}

		if (!isValidCodeChallengeMethod(code_challenge_method)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"The provided `code_challenge_method` is not valid",
				},
				400,
			);
		}

		if (!isValidScope(scope)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_SCOPE,
					error_description: `The provided \`scope\` is not valid`,
				},
				400,
			);
		}

		if (!client_id) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"Request URI must include a `client_id` query parameter",
				},
				400,
			);
		} // Inform on front-end

		if (!redirect_uri) {
			// can be omitted only if there's only one registered `redirect_uri` for the client
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"Request URI must include a `redirect_uri` query parameter",
				},
				400,
			);
		} // Inform on front-end

		if (!isValidURI(redirect_uri, client_id)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description: `The provided \`redirect_uri\` is not registered for the client with the provided \`client_id\``,
				},
				400,
			);
		} // Inform on front-end

		const client = findClientById(client_id);
		if (!client) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"The client with the provided `client_id` is not registered",
				},
				400,
			);
		} // Inform on front-end

		const failure_uri = new URL(redirect_uri);
		failure_uri.searchParams.set("iss", AUTHORIZATION_SERVER_ID);

		if (!canClientRequestAuthorizationCode(client)) {
			failure_uri.searchParams.set("error", ErrorCodes.UNAUTHORIZED_CLIENT);
			failure_uri.searchParams.set(
				"error_description",
				"Client is not authorized to request an authorization code",
			);
			return ctx.redirect(failure_uri.toString());
		}

		/**
		 * When a decision is established, the Authorization Server directs the user agent to the provided client
		 * redirect URI
		 */

		let authorizationDecision: AuthorizationDecision;
		try {
			authorizationDecision = getAuthorizationDecisionFor(client);
		} catch (e) {
			failure_uri.searchParams.set("error", ErrorCodes.SERVER_ERROR);
			failure_uri.searchParams.set(
				"error_description",
				"An unexpected condition prevented the server from fulfilling the request. Please try again.",
			);
			return ctx.redirect(failure_uri.toString());
		}

		if (!authorizationDecision.accessGranted) {
			failure_uri.searchParams.set("error", ErrorCodes.ACCESS_DENIED);
			failure_uri.searchParams.set(
				"error_description",
				authorizationDecision.denialReason,
			);
			return ctx.redirect(failure_uri.toString());
		}

		const success_uri = new URL(redirect_uri);
		success_uri.searchParams.set("iss", AUTHORIZATION_SERVER_ID);

		const code = generateCode();
		registerAuthorizationCode(
			client_id,
			code,
			code_challenge,
			code_challenge_method,
		);

		success_uri.searchParams.set("code", code);
		if (state) success_uri.searchParams.set("state", state);

		/**
		 * For example:
		 * ```http
		 * HTTP/1.1 302 Found
		 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
		 *           &state=xyz&iss=https%3A%2F%2Fauthorization-server.example.com
		 * ```
		 */
		return ctx.redirect(success_uri.toString());
	}
});

const AUTHORIZATION_SERVER_ID = "https://auth.example.com";
const DEFAULT_AUTHORIZATION_SCOPE = "read"; // defined by Authorization Server

function generateCode(): string {
	return crypto.randomUUID();
}

/**
 * Authorization Server MUST associate the code_challenge and code_challenge_method values with the issued
 * authorization code, so that the code challenge can be verified later. -> KV/DB
 *
 * The code_challenge and code_challenge_method values may be stored in encrypted form in the code
 */
function registerAuthorizationCode(
	clientId: string,
	code: string,
	codeChallenge: string,
	codeChallengeMethod: string,
): void {}

function isValidResponseType(responseType: string) {
	return true;
}

function isValidCodeChallengeMethod(method: string) {
	return method === "S256" || method === "plain";
}

function isValidURI(uri: string, clientID: string) {
	// The only exception is native apps using a localhost URI: In this case, the Authorization Server MUST allow variable port numbers as described in Section 7.3 of [RFC8252].
	return true;
}

function isValidScope(scope: string): boolean {
	return true;
}

function findClientById(clientId: string) {
	return {};
}

function getAuthorizationDecisionFor(client: {}): AuthorizationDecision {
	return { accessGranted: false, denialReason: "Just because" };
}

function canClientRequestAuthorizationCode(client: {}): boolean {
	return true;
}

export default authorization;
