import { Hono } from "hono";
import * as ErrorCodes from "../lib/errors/token.js";
import type {
	AccessTokenType,
	AuthorizationCodeRecord,
	CodeChallengeMethod,
	GrantType,
	Scope,
} from "../lib/types.js";
import { containsFragment, isString } from "../lib/utils.js";

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

/**
 * NOTE:
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

	const { grant_type, client_id, code, code_verifier, scope } =
		await ctx.req.parseBody();
	// TODO: Validate that request parameters are not included more than once.

	if (!grant_type) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: "Request must contain `grant_type` parameter",
			},
			400,
		);
	}

	if (!isString(grant_type)) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: "The value of `grant_type` must be a string",
			},
			400,
		);
	}

	if (!isValidGrantType(grant_type)) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.UNSUPPORTED_GRANT_TYPE,
				error_description: `The '${grant_type}' grant type is not a supported.`,
				// TODO: Point to documentation about supported grant types using `error_uri`
			},
			400,
		);
	}

	if (scope && !isString(scope)) {
		return ctx.json<ErrorResponse>(
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description: "The `scope` parameter must be a string",
			},
			400,
		);
	}

	/**
	 * TODO: Confidential clients MUST authenticate with the Authorization Server
	 *
	 * It is RECOMMENDED to use asymmetric (public-key based) methods for client authentication, such as mTLS [RFC8705] * or using signed JWTs in accordance with [RFC7521], [RFC7523], and their update [I-D.ietf-oauth-rfc7523bis]
	 * (defined in [OpenID] as the client authentication method private_key_jwt).
	 */

	/**
	 * TODO: Public clients MUST provide `client_id` and some form of authentication should be enforced
	 * 	if (!client_id) {
	 *  	return ctx.json<ErrorResponse>(
	 *  		{
	 *  			error: ErrorCodes.INVALID_REQUEST,
	 *  			error_description: "Request contain the `client_id` parameter",
	 *  		},
	 *  		400,
	 *  	);
	 *  }
	 *
	 *  if (!isString(client_id)) {
	 *  	return ctx.json<ErrorResponse>(
	 *  		{
	 *  			error: ErrorCodes.INVALID_REQUEST,
	 *  			error_description: "The value of `client_id` must be a string",
	 *  		},
	 *  		400,
	 *  	);
	 *  }
	 */

	if (grant_type === "authorization_code") {
		if (!code) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"Request must contain the `code` parameter with the value received from the Authorization Server",
				},
				400,
			);
		}

		if (!isString(code)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description: "The value of `code` must be a string",
				},
				400,
			);
		}

		/**
		 * NOTE:
		 * Check that `code_verifier` is present IFF a `code_challenge` parameter was present in the authorization request
		 * If there was no `code_challenge` in the authorization request, the server MUST reject this request
		 */

		// Strict requirement of `code_verifier` for the authorization code grant
		if (!code_verifier) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description:
						"Request must contain the `code_verifier` parameter",
				},
				400,
			);
		}

		if (!isString(code_verifier)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_REQUEST,
					error_description: "The `code_verifier` parameter must be a string",
				},
				400,
			);
		}

		const authorizationRecord = findAuthorizationRecordByCode(code);
		if (!authorizationRecord) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_GRANT,
					error_description: "The provided authorization code is invalid",
				},
				400,
			);
		}

		// NOTE: Revoked tokens should not exist; alternatively a revoke check can be implemented

		if (!canUseAuthorizationCode(authorizationRecord.clientId)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.UNAUTHORIZED_CLIENT,
					error_description:
						"This client is not authorized to use an authorization code to obtain an access token",
				},
				400,
			);
		}

		if (authorizationRecord.isUsed) {
			// Revoke all access tokens and refresh tokens previously issued for this authorization code
			revokeTokensFor(code);

			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_GRANT,
					error_description:
						"The provided `code` has already been used. All tokens issued for it are now revoked.",
				},
				400,
			);
		}

		if (isExpiredTimestamp(authorizationRecord.expiresAt)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_GRANT,
					error_description: "The provided authorization code is invalid",
				},
				400,
			);
		}

		/**
		 * TODO: If the client uses OAuth 2.0, a redirect URI check should be enforced. This is not needed in OAuth 2.1
		 *
		 * 		if (redirect_uri !== authorizationRecord.redirectUri) {
		 *	return ctx.json<ErrorResponse>(
		 *		{
		 *			error: ErrorCodes.INVALID_REQUEST,
		 *			error_description:
		 *				"The provided `redirect_uri` does not match the one in the associated authorization request",
		 *		},
		 *		400,
		 *	);
		 *}
		 *
		 */

		// NOTE: The `client_id` is used regardless of whether it's a confidential or public client
		if (authorizationRecord.clientId !== client_id) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_GRANT,
					error_description: "The provided authorization code is invalid",
				},
				400,
			);
		}

		// NOTE: The Authorization Server can choose to ignore the requested scope and just provide the approved scope
		if (scope && !isWithinScope(scope, authorizationRecord.scope)) {
			// NOTE: The Authorization Server can choose to revoke the code or inform the client of the approved scope
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_SCOPE,
					error_description:
						"The requested scope exceeds the scope granted by the Resource Owner",
				},
				400,
			);
		}

		if (!isValidCode(code)) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_GRANT,
					error_description: `The provided code is invalid.`,
				},
				400,
			);
		}

		if (
			!isCodeChallengeVerified({
				codeVerifier: code_verifier,
				codeChallenge: authorizationRecord.codeChallenge,
				codeChallengeMethod: authorizationRecord.codeChallengeMethod,
			})
		) {
			return ctx.json<ErrorResponse>(
				{
					error: ErrorCodes.INVALID_GRANT,
					error_description: "The provided authorization code is invalid",
				},
				400,
			);
		}

		const access_token = generateAccessToken();
		const token_type: AccessTokenType = "bearer";
		const expires_in: number = 3600;
		/**
		 *  MUST be bound to the `scope` and `Resource Servers` as consented by the `Resource Owne`r.
		 */
		const refresh_token: string = generateRefreshToken();
		const refreshTokenExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes from now

		/**
		 * TODO: Authorization Server must keep track of the tokens it issues -> KV/DB
		 */

		ctx.header("Cache-Control", "no-store");

		return ctx.json<SuccessResponse>(
			{
				access_token,
				token_type,
				expires_in,
				scope: (scope as string) ?? "DEFAULT_SCOPE",
				refresh_token,
			},
			200,
		);
	}
});

function isCodeChallengeVerified(_info: {
	codeVerifier: string;
	codeChallenge: string;
	codeChallengeMethod: CodeChallengeMethod;
}): boolean {
	// Verify the code_verifier by calculating the code challenge received and comparing it with the previously
	// associated code_challenge, after transforming it according to the code_challenge_method method
	return true;
}

function revokeTokensFor(_code: string): void {}

function isExpiredTimestamp(_expirationTime: number): boolean {
	return false;
}

function isValidCode(_code: string): boolean {
	return true;
}

const supportedGrantTypes = new Set([
	"authorization_code",
	"refresh_token",
	"client_credentials",
]);

function isValidGrantType(grant: string): grant is GrantType {
	return supportedGrantTypes.has(grant);
}

function findAuthorizationRecordByCode(_code: string): AuthorizationCodeRecord {
	return {} as AuthorizationCodeRecord;
}

function canUseAuthorizationCode(_clientId: string): boolean {
	return true;
}

function isWithinScope(scope1: Scope, scope2: Scope) {
	return scope1 === scope2;
}

function generateAccessToken() {
	return "secure_access_token";
}

function generateRefreshToken() {
	return "secure_refresh_token";
}

export default token;
