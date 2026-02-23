import { Hono } from "hono";
import { type TokenErrorCode, TokenErrorCodes } from "../../src/lib/errors/oauth.js";
import type {
	AccessTokenType,
	AuthorizationCodeRecord,
	ClientAccessRecord,
	CodeChallengeMethod,
	GrantType,
	OAuthClient,
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
	error: TokenErrorCode | (string & {});
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

async function auth(name: string) {
	/**
	 * For confidential clients, the authorization server MAY accept any
	 * form of client authentication meeting its security requirements
	 * (e.g., client secret, public/private key pair).
	 *
	 * It is RECOMMENDED to use asymmetric (public-key based) methods for
	 * client authentication such as mTLS [RFC8705] or using signed JWTs
	 * ("Private Key JWT") in accordance with [RFC7521], [RFC7523], and
	 * their update [I-D.ietf-oauth-rfc7523bis] (defined in [OpenID] as the
	 * client authentication method private_key_jwt).
	 *
	 * When such methods for client authentication are used, authorization
	 * servers do not need to store sensitive symmetric keys, making these
	 * methods more robust against a number of attacks.
	 *
	 * When client authentication is not possible, the authorization server
	 * SHOULD employ other means to validate the client's identity -- for
	 * example, by requiring the registration of the client redirect URI or
	 * enlisting the resource owner to confirm identity.  A valid redirect
	 * URI is not sufficient to verify the client's identity when asking for
	 * resource owner authorization but can be used to prevent delivering
	 * credentials to a counterfeit client after obtaining resource owner
	 * authorization.
	 */
}

async function handleAuthorizationCodeRequest(name: string) {
	return "Hello World";
}

/**
 * NOTE:
 * - ctx.json uses `application/json` media type by default
 */
token.post("/", async (ctx) => {
	if (containsFragment(ctx.req.url)) {
		return ctx.json<ErrorResponse>(
			{
				error: TokenErrorCodes.INVALID_REQUEST,
				error_description: "Request URI cannot contain a fragment component",
			},
			400,
		);
	}

	const contentType = ctx.req.header("Content-Type")?.toLowerCase();
	if (!contentType) {
		return ctx.json<ErrorResponse>(
			{
				error: TokenErrorCodes.INVALID_REQUEST,
				error_description: "Request must include `Content-Type` header",
			},
			400,
		);
	}

	if (!contentType.includes("application/x-www-form-urlencoded")) {
		return ctx.json<ErrorResponse>(
			{
				error: TokenErrorCodes.INVALID_REQUEST,
				error_description: "Only `application/x-www-form-urlencoded` media type is supported",
			},
			400,
		);
	}

	if (!contentType.includes("charset=utf-8")) {
		return ctx.json<ErrorResponse>(
			{
				error: TokenErrorCodes.INVALID_REQUEST,
				error_description: "Request must explicitly specify charset=utf-8",
			},
			400,
		);
	}

	// Validate that request body parameters are not included more than once
	const [duplicatesError, body] = await ensureNoDuplicates(ctx.req.parseBody());
	if (duplicatesError) {
		return ctx.json<ErrorResponse>(
			{
				error: TokenErrorCodes.INVALID_REQUEST,
				error_description: "The request body contains duplicate parameters. Please ensure parameters appear only once",
			},
			400,
		);
	}

	if (!body.grant_type) {
		return ctx.json<ErrorResponse>(
			{
				error: TokenErrorCodes.INVALID_REQUEST,
				error_description: "Request must contain `grant_type` parameter",
			},
			400,
		);
	}

	if (!isString(body.grant_type)) {
		return ctx.json<ErrorResponse>(
			{
				error: TokenErrorCodes.INVALID_REQUEST,
				error_description: "The value of `grant_type` must be a string",
			},
			400,
		);
	}

	if (!isValidGrantType(body.grant_type)) {
		return ctx.json<ErrorResponse>(
			{
				error: TokenErrorCodes.UNSUPPORTED_GRANT_TYPE,
				error_description: `The '${body.grant_type}' grant type is not a supported.`,
				// TODO: Point to documentation about supported grant types using `error_uri`
			},
			400,
		);
	}

	/**
	 * Before initiating the protocol, the client must have established an
	 * identifier at the Authorization Server.
	 */

	/**
	 * TODO: Confidential clients MUST authenticate with the Authorization Server
	 *
	 * It is RECOMMENDED to use asymmetric (public-key based) methods for client authentication, such as mTLS [RFC8705] * or using signed JWTs in accordance with [RFC7521], [RFC7523], and their update [I-D.ietf-oauth-rfc7523bis]
	 * (defined in [OpenID] as the client authentication method private_key_jwt).
	 */

	// So, I need to know whether this is a public or confidential client. How?
	// 1. I request the client_id and check the type
	// 2. I provide separate endpoints for public/confidential clients

	/**
	 * TODO: Public clients MUST provide `client_id` and some form of authentication should be enforced
	 * 	if (!client_id) {
	 *  	return ctx.json<ErrorResponse>(
	 *  		{
	 *  			error: TokenErrorCodes.INVALID_REQUEST,
	 *  			error_description: "Request contain the `client_id` parameter",
	 *  		},
	 *  		400,
	 *  	);
	 *  }
	 *
	 *  if (!isString(client_id)) {
	 *  	return ctx.json<ErrorResponse>(
	 *  		{
	 *  			error: TokenErrorCodes.INVALID_REQUEST,
	 *  			error_description: "The value of `client_id` must be a string",
	 *  		},
	 *  		400,
	 *  	);
	 *  }
	 */

	if (body.grant_type === "authorization_code") {
		const { code, code_verifier, scope = DEFAULT_SCOPE } = body;

		if (!code) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_REQUEST,
					error_description:
						"Request must contain the `code` parameter with the value received from the Authorization Server",
				},
				400,
			);
		}

		if (!isString(code)) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_REQUEST,
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
					error: TokenErrorCodes.INVALID_REQUEST,
					error_description: "Request must contain the `code_verifier` parameter",
				},
				400,
			);
		}

		if (!isString(code_verifier)) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_REQUEST,
					error_description: "The `code_verifier` parameter must be a string",
				},
				400,
			);
		}

		// So here I need to authenticate the client if I can actually

		/**
		 * Client is authenticated either through
		 */

		const authorizationRecord = findAuthorizationRecordByCode(code);
		if (!authorizationRecord) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_GRANT,
					error_description: "The provided authorization code is invalid",
				},
				400,
			);
		}

		if (!canUseAuthorizationCode(authorizationRecord.clientId)) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.UNAUTHORIZED_CLIENT,
					error_description: "This client is not authorized to use an authorization code to obtain an access token",
				},
				400,
			);
		}

		if (authorizationRecord.isUsed) {
			// Revoke all access tokens and refresh tokens previously issued for this authorization code
			revokeTokensForCode(code);

			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_GRANT,
					error_description: "The provided `code` has already been used. All tokens issued for it are now revoked.",
				},
				400,
			);
		}

		if (isExpiredTimestamp(authorizationRecord.expiresAt)) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_GRANT,
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
		 *			error: TokenErrorCodes.INVALID_REQUEST,
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
					error: TokenErrorCodes.INVALID_GRANT,
					error_description: "The provided authorization code is invalid",
				},
				400,
			);
		}

		if (scope && !isString(scope)) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_REQUEST,
					error_description: "The `scope` parameter must be a string",
				},
				400,
			);
		}

		// NOTE: The Authorization Server can choose to ignore the requested scope and just provide the approved scope
		if (scope && !isWithinScope(scope, authorizationRecord.scope)) {
			// NOTE: The Authorization Server can choose to revoke the code or inform the client of the approved scope
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_SCOPE,
					error_description: "The requested scope exceeds the scope granted by the Resource Owner",
				},
				400,
			);
		}

		if (!isValidCode(code)) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_GRANT,
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
					error: TokenErrorCodes.INVALID_GRANT,
					error_description: "Failed to verify the `code_challenge` with the provided `code_verifier`",
				},
				400,
			);
		}

		const token_type: AccessTokenType = "bearer";
		const access_token = generateAccessToken({ scope });
		const refresh_token: string = generateRefreshToken({ scope });

		// Authorization Server must keep track of the tokens it issues -> KV/DB
		try {
			await registerAccess({
				clientId: client_id,
				scope,
				providerId: AUTHORIZATION_SERVER_ID,
				tokenType: token_type,
				accessToken: access_token,
				accessTokenExpiresAt: Date.now() + ACCESS_TOKEN_LIFETIME_S,
				refreshToken: refresh_token,
				refreshTokenExpiresAt: Date.now() + REFRESH_TOKEN_LIFETIME_S,
			});
		} catch (_) {
			// Not specified in OAuth, but reasonable to assume something can go wrong
			return ctx.json<ErrorResponse>(
				{
					error: "server_error", // OR "temporarily_unavailable"
					error_description: "An unexpected condition prevented fulfilling the request.",
				},
				500, // OR 503 (Service Unavailable)
			);
		}

		ctx.header("Cache-Control", "no-store");

		return ctx.json<SuccessResponse>(
			{
				scope,
				access_token,
				token_type,
				expires_in: ACCESS_TOKEN_LIFETIME_S,
				refresh_token,
			},
			200,
		);
	}

	// Not using `client_id` for this flow
	if (body.grant_type === "client_credentials") {
		/*
		 * TODO: The client MUST authenticate with the Authorization Server to use this method
		 *
		 * Although beyond the OAuth spec, it is RECOMMENDED to use asymmetric (public-key based) methods for client
		 * authentication, such as mTLS [RFC8705] or using signed JWTs in accordance with [RFC7521], [RFC7523], and their
		 * update [I-D.ietf-oauth-rfc7523bis] (defined in [OpenID] as the client authentication method private_key_jwt).
		 */
		const credentialsCookie = getCookie(ctx, "credential_cookie");
		if (!isValidCredential(credentialsCookie)) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_CLIENT,
					error_description: `The provided client credentials are invalid.`,
				},
				400,
			);
		}

		const clientRegistration = getClientRegistration(credentialsCookie);

		// This method MUST be used only by confidential clients
		if (clientRegistration.type !== "confidential") {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.UNAUTHORIZED_CLIENT,
					error_description: "Only confidential clients can use a 'client_credentials' grant",
				},
				400,
			);
		}

		// NOTE: The Authorization Server can choose to ignore the requested scope and just provide the approved scope
		if (scope && !isWithinScope(scope, credentialsCookie)) {
			// NOTE: The Authorization Server can choose to revoke the code or inform the client of the approved scope
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_SCOPE,
					error_description: "The requested scope exceeds the scope allowed by the `Resource Owner`",
				},
				400,
			);
		}

		const token_type: AccessTokenType = "bearer";
		const access_token = generateAccessToken({ scope });

		// NOTE: A refresh token SHOULD NOT be issued for this flow

		// Authorization Server must keep track of the tokens it issues -> KV/DB
		try {
			await registerAccess({
				clientId: clientRegistration.client_id,
				scope,
				providerId: AUTHORIZATION_SERVER_ID,
				tokenType: token_type,
				accessToken: access_token,
				accessTokenExpiresAt: Date.now() + ACCESS_TOKEN_LIFETIME_S,
			});
		} catch (_) {
			// Not specified in OAuth, but reasonable to assume something can go wrong
			return ctx.json<ErrorResponse>(
				{
					error: "server_error", // OR "temporarily_unavailable"
					error_description: "An unexpected condition prevented fulfilling the request.",
				},
				500, // OR 503 (Service Unavailable)
			);
		}

		ctx.header("Cache-Control", "no-store");

		return ctx.json<SuccessResponse>(
			{
				scope,
				access_token,
				token_type,
				expires_in: ACCESS_TOKEN_LIFETIME_S,
			},
			200,
		);
	}

	if (body.grant_type === "refresh_token") {
		if (!refresh_token) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_REQUEST,
					error_description: "Request must contain the `refresh_token`",
				},
				400,
			);
		}

		if (!isString(refresh_token)) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_REQUEST,
					error_description: "The value of `refresh_token` must be a string",
				},
				400,
			);
		}

		// Confidential clients MUST authenticate with the Authorization Server
		const credentialsCookie = getCookie(ctx, "credential_cookie");
		if (!isValidCredential(credentialsCookie)) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_CLIENT,
					error_description: `The provided client credentials are invalid.`,
				},
				400,
			);
		}

		const { client_id: clientId } = getClientRegistration(credentialsCookie);

		/**
		 * NOTE:
		 * When client authentication is not possible, the Authorization Server SHOULD issue sender-constrained
		 * refresh tokens or use refresh token rotation
		 */

		const accessRecord = await findAccessRecordByClientId(clientId);
		if (!accessRecord) {
			// NOTE: Revoked tokens should not exist; alternatively a revoke check can be implemented
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.UNAUTHORIZED_CLIENT,
					error_description: "The client was not issued an access token or the access token has been revoked.",
				},
				400,
			);
		}

		if (!accessRecord.refreshToken) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.UNAUTHORIZED_CLIENT,
					error_description:
						"The client was not issued a refresh token and therefore cannot use this authorization method.",
				},
				400,
			);
		}

		if (accessRecord.refreshToken !== refresh_token) {
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_GRANT,
					error_description: "The provided `refresh_token` is invalid",
				},
				400,
			);
		}

		if (isExpiredTimestamp(accessRecord.refreshTokenExpiresAt)) {
			// If it still exists but is expired, we remove it
			await revokeTokensForClient(clientId);

			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_GRANT,
					error_description: "The provided `refresh_token` has expired. You need to start a new OAuth flow.",
				},
				400,
			);
		}

		// NOTE: The Authorization Server can choose to ignore the requested scope and just provide the approved scope
		if (scope && !isWithinScope(scope, accessRecord.scope)) {
			// NOTE: The Authorization Server can choose to revoke the code or inform the client of the approved scope
			return ctx.json<ErrorResponse>(
				{
					error: TokenErrorCodes.INVALID_SCOPE,
					error_description: "The requested scope exceeds the scope allowed by the `Resource Owner`",
				},
				400,
			);
		}

		// Review: issue new access_token + new refresh_token
		const token_type: AccessTokenType = "bearer";
		const freshAccessToken = generateAccessToken({ scope });
		const newRefreshToken: string = generateRefreshToken({ scope });

		// Authorization Server must keep track of the tokens it issues -> KV/DB
		try {
			await registerAccess({
				clientId,
				scope,
				providerId: AUTHORIZATION_SERVER_ID,
				tokenType: token_type,
				accessToken: freshAccessToken,
				accessTokenExpiresAt: Date.now() + ACCESS_TOKEN_LIFETIME_S,
				refreshToken: newRefreshToken,
				refreshTokenExpiresAt: Date.now() + REFRESH_TOKEN_LIFETIME_S,
			});
		} catch (_) {
			// Not specified in OAuth, but reasonable to assume something can go wrong
			return ctx.json<ErrorResponse>(
				{
					error: "server_error", // OR "temporarily_unavailable"
					error_description: "An unexpected condition prevented fulfilling the request.",
				},
				500, // OR 503 (Service Unavailable)
			);
		}

		ctx.header("Cache-Control", "no-store");

		return ctx.json<SuccessResponse>(
			{
				scope,
				access_token: freshAccessToken,
				token_type,
				expires_in: ACCESS_TOKEN_LIFETIME_S,
				refresh_token: newRefreshToken,
			},
			200,
		);
	}
});

const AUTHORIZATION_SERVER_ID = "https://auth.example.com";

const DEFAULT_SCOPE = "example_scope"; // Up to Authorization Server

const ACCESS_TOKEN_LIFETIME_S = 7200; // Up to Authorization Server (2h here)
const REFRESH_TOKEN_LIFETIME_S = 604_800; //  Up to Authorization Server (7 days here)

function getClientId(_name: string) {
	return "Hello World";
}

function isValidCredential(_name: string): boolean {
	return true;
}

function isValidRefreshToken(_token: string): boolean {
	return true;
}

function getClientRegistration(_cookie: string): OAuthClient {
	return {} as OAuthClient;
}

function getCookie(_ctx: unknown, _name: string) {
	return "Hello World";
}

async function findAccessRecordByClientId(_token: string): Promise<ClientAccessRecord | null> {
	return null;
}

function isCodeChallengeVerified(_info: {
	codeVerifier: string;
	codeChallenge: string;
	codeChallengeMethod: CodeChallengeMethod;
}): boolean {
	// Verify the code_verifier by calculating the code challenge received and comparing it with the previously
	// associated code_challenge, after transforming it according to the code_challenge_method method
	return true;
}

async function revokeTokensForClient(_clientId: string): Promise<void> {}

function revokeTokensForCode(_code: string): void {}

function isExpiredTimestamp(_expirationTime: number): boolean {
	return false;
}

function isValidCode(_code: string): boolean {
	return true;
}

const supportedGrantTypes = new Set(["authorization_code", "refresh_token", "client_credentials"]);

function isValidGrantType(grant: string): grant is GrantType {
	return supportedGrantTypes.has(grant);
}

function isValidUri(_uri: string, _clientId: string) {
	// The only exception is native apps using a localhost URI: In this case, the Authorization Server MUST allow variable port numbers as described in Section 7.3 of [RFC8252].
	return true;
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

function generateAccessToken(_info: { scope: Scope }) {
	/**
	 * MUST be bound to the `scope` and `Resource Servers` as consented by the `Resource Owner`.
	 * To bind it to the `Resource Servers` the Resource Indicators for OAuth 2.0 [RFC8707] can be implemented
	 */
	return "secure_access_token";
}

function generateRefreshToken(_info: { scope: Scope }) {
	/**
	 *  MUST be bound to the `scope` and `Resource Servers` as consented by the `Resource Owner`.
	 * To bind it to the `Resource Servers` the Resource Indicators for OAuth 2.0 [RFC8707] can be implemented
	 */
	return "secure_refresh_token";
}

async function ensureNoDuplicates(
	requestBody: Promise<Record<string, string | File>>,
): Promise<[Error, null] | [null, Record<string, string | File>]> {
	const deduplicatedBody = await requestBody; // Not deduplicated currently

	return [null, deduplicatedBody];
}

async function registerAccess(_info: ClientAccessRecord): Promise<void> {}

export default token;
