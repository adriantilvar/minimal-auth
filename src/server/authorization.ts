import { Hono } from "hono";
import * as ErrorCodes from "../lib/errors/authorization.js";
import { containsFragment, isString } from "../lib/utils.js";

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

const authorization = new Hono();

/**
 * The Authorization Server MUST support the use of the HTTP GET method (Section 9.3.1 of [RFC9110]) for the
 * authorization endpoint and MAY support the POST method (Section 9.3.3 of [RFC9110]) as well.
 *
 * The /authorization endpoint URL MUST NOT include a fragment component. It MAY include a query string component, which MUST be retained when adding additional query parameters.
 *
 * An Authorization Server that redirects a request potentially containing user credentials MUST avoid forwarding these
 * user credentials accidentally (see Section 7.5.4 for details).
 *
 * Cross-Origin Resource Sharing [WHATWG.CORS] MUST NOT be supported at the /authorization endpoint, as the client does
 * not access this endpoint directly. Instead, the client redirects the user agent to it.
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

	const response_type = ctx.req.query("response_type");
	const client_id = ctx.req.query("client_id");
	const code_challenge = ctx.req.query("code_challenge");
	const code_challenge_method =
		ctx.req.query("code_challenge_method") ?? "plain";
	const redirect_uri = ctx.req.query("redirect_uri");
	// TODO: Validate that the parameters are not included more than once -> invalid_requesst

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
		if (!code_challenge) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"Request URI must include a `code_challenge` query parameter",
				},
				400,
			);
		} // Request rejected

		if (!isValidCodeChallengeMethod(code_challenge_method)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"The provided `code_challenge_method` is not valid",
				},
				400,
			);
		} // Request rejected

		if (!client_id) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"Request URI must include a `client_id` query parameter",
				},
				400,
			);
		} // Request rejected -> Inform the client

		if (!isString(client_id)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description: "The value of `client_id` must be a string",
				},
				400,
			);
		} //  Request rejected -> Inform the client

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
		} //  Request rejected -> Inform the client

		if (!isValidUri(redirect_uri, client_id)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description: `The provided \`redirect_uri\` is not registered for the client with the provided \`client_id\``,
				},
				400,
			);
		} //  Request rejected -> Inform the client

		// Request is valid as far as the server is concerned at this point -> continue on client/authorization-code
		return ctx.redirect("/authorization-code");
	}
});

function isValidResponseType(_responseType: string) {
	return true;
}

function isValidCodeChallengeMethod(method: string) {
	return method === "S256" || method === "plain";
}

function isValidUri(_uri: string, _clientId: string) {
	// The only exception is native apps using a localhost URI: In this case, the Authorization Server MUST allow variable port numbers as described in Section 7.3 of [RFC8252].
	return true;
}

export default authorization;
