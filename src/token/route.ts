import { Hono } from "hono";
import type { AccessTokenType, Scope } from "../lib/types.js";
import { containsFragment } from "../lib/utils.js";
import * as ErrorCodes from "./error-codes.js";

type SuccessResponse = {
	access_token: string;
	token_type: AccessTokenType;
	expires_in: number;
	scope?: Scope;
	refresh_token?: string;
};

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
};

const token = new Hono();

const supportedGrantTypes = new Set([
	"authorization_code",
	"refresh_token",
	"client_credentials",
]);

// TODO: Request and response parameters MUST NOT be included more than once.

/**
 * Notes:
 * - ctx.json uses `application/json` media type by default
 */
token.post("/", async (ctx) => {
	if (containsFragment(ctx.req.url)) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: "Request URI cannot contain a fragment component",
			},
			400,
		);
	}

	const contentType = ctx.req.header("Content-Type");

	if (!contentType) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: "Request must include `Content-Type` header",
			},
			400,
		);
	}

	const [mediaType, encoding] = contentType.split("; ");

	if (mediaType !== "application/x-www-form-urlencoded") {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description:
					"Only `application/x-www-form-urlencoded` media type is supported",
			},
			400,
		);
	}

	if (encoding && encoding !== "charset=utf-8") {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: "Only UTF-8 encoding is supported",
			},
			400,
		);
	}

	const { grant_type, client_id } = await ctx.req.parseBody();

	if (!grant_type) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: "Request must contain `grant_type` parameter",
			},
			400,
		);
	}

	if (typeof grant_type !== "string") {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: "The `grant_type` value must be a string",
			},
			400,
		);
	}

	if (!supportedGrantTypes.has(grant_type)) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: `The '${grant_type}' grant type is not supported`,
				// TODO: Point to documentation about supported grant types using `error_uri`
			},
			400,
		);
	}

	/**
	 * TODO: Confidential clients MUST authenticate with the Authorization Server when making requests to the /token endpoint.
	 */

	// I guess I need to identify the client to know if they are confidential?
	// if (!client_id) {
	// 	throw new Error("Request must contain `client_id`");
	// }

	// if (typeof client_id !== "string") {
	// 	return ctx.json(
	// 		{
	// 			error: "some_error",
	// 			error_description: "some_description",
	// 			error_uri: "some_error_page",
	// 		},
	// 		400,
	// 	); // Uses `application/json` by default
	// }

	// Authenticate client

	// Success
	const access_token: string = "some_access_token";
	const token_type: AccessTokenType = "bearer";
	const expires_in: number = 3600;
	const scope: string = "scope_requested" ?? "DEFAULT_SCOPE";
	/**
	 *  MUST be bound to the `scope` and `Resource Servers` as consented by the `Resource Owne`r.
	 */
	const refresh_token: string = "some_refresh_token";

	/**
	 * TODO: Authorization Server must keep track of the tokens it issues -> KV/DB
	 */

	ctx.header("Cache-Control", "no-store");

	return ctx.json<SuccessResponse>(
		{
			access_token,
			token_type,
			expires_in,
			scope,
			refresh_token,
		},
		200,
	);
});

export default token;
