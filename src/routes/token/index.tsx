import { createFileRoute } from "@tanstack/react-router";
import { getRequestHeader } from "@tanstack/react-start/server";
import { type TokenErrorCode, TokenErrorCodes } from "@/lib/errors/oauth";
import { BAD_REQUEST, OK, UNAUTHORIZED } from "@/lib/http/response-status-codes";
import type {
	AccessToken,
	AccessTokenType,
	AuthorizationCodeRecord,
	ClientAccessRecord,
	GrantType,
	OAuthClient,
	Scope,
} from "@/lib/types";

/**
 * Before initiating the protocol, the client must have established an
 * identifier at the Authorization Server.
 *
 * Confidential clients MUST authenticate with the Authorization Server
 *
 * Since the client secret authentication method involves a password,
 * the authorization server MUST protect any endpoint utilizing it
 * against brute force attacks.
 *
 * It is RECOMMENDED to use asymmetric (public-key based) methods for client
 * authentication, such as mTLS [RFC8705] * or using signed JWTs in accordance
 *  with [RFC7521], [RFC7523], and their update [I-D.ietf-oauth-rfc7523bis]
 * (defined in [OpenID] as the client authentication method private_key_jwt).
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

// NOTE: The fragment component is stripped by the server, but it should also be enforced by client
export const Route = createFileRoute("/token/")({
	server: {
		handlers: {
			POST: async ({ request }) => {
				const contentType = getRequestHeader("Content-Type");
				if (!contentType) {
					// Automatically sets the Content-Type header to `application/json` and serializes the JSON object
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_REQUEST,
							error_description: "The request must include `Content-Type` header",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				const [mediaType, encoding] = contentType.split("; ");

				if (mediaType !== "application/x-www-form-urlencoded") {
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_REQUEST,
							error_description: "The request must use `application/x-www-form-urlencoded` media type.",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				// If not provided, we assume UTF-8; if another encoding is provided, we reject the request
				if (encoding && encoding.toLowerCase() !== "charset=utf-8") {
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_REQUEST,
							error_description: "The request must use UTF-8 character encoding.",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				const body = await request.formData();

				const [grantType] = getUniqueField(body, "grant_type");
				if (!grantType) {
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_REQUEST,
							error_description:
								"The request content must include a `grant_type` parameter. It must not be included more than once.",
						},
						{
							status: BAD_REQUEST.code,
						},
					);
				}

				if (!isValidGrantType(grantType)) {
					return Response.json({
						error: TokenErrorCodes.UNSUPPORTED_GRANT_TYPE,
						error_description: `The '${grantType}' grant type is not a supported.`,
					});
				}

				// We strictly require the `client_id`, as we want to know if the client is public or confidential
				const [clientId] = getUniqueField(body, "client_id");
				if (!clientId) {
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_REQUEST,
							error_description:
								"The request content must include a `client_id` parameter. It must not be included more than once.",
						},
						{
							status: BAD_REQUEST.code,
						},
					);
				}

				const client = await findOAuthClientById(clientId);
				if (!client) {
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_CLIENT,
							error_description:
								"No client is registered with the provided `client_id`. You need to register the client before requesting an access token.",
						},
						{
							status: BAD_REQUEST.code,
						},
					);
				}

				if (client.type === "public") {
					/**
					 * Some form of authentication should be enforced when dealing with public clients.
					 * However, this is not covered by OAuth 2.1, so we omit the implementation
					 */
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_CLIENT,
							error_description: "The server does not support public clients for the time being.",
						},
						{
							status: BAD_REQUEST.code,
						},
					);
				}

				// We're only dealing with confidential clients

				/**
				 * This grant type represents access on behalf of an end-user (user-to-machine).
				 *
				 * It can be used by both public and confidential clients.
				 */
				if (grantType === "authorization_code") {
					// We must first authenticate the client
					const [ok, authFailure] = authenticateClient(client, body);
					if (!ok) {
						return Response.json(
							{
								error: authFailure.error,
								error_description: authFailure.error_description,
							},
							authFailure.responseInit,
						);
					}

					// After we authenticate the client, we check if they are allowed to use this grant type
					if (!canUseGrantType(grantType, client)) {
						return Response.json(
							{
								error: TokenErrorCodes.UNAUTHORIZED_CLIENT,
								error_description: "The client is not authorized to use this authorization grant type.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// Not strictly necessary in OAuth 2.1 if the client has registered only one redirect URI
					// However, it can be enforced for backwards compatibility with OAuth 2.0
					const [redirectUri] = getUniqueField(body, "code");
					if (!redirectUri) {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_REQUEST,
								error_description:
									"The request content must include a `redirect_uri` parameter. It must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We check that the provided redirect URI is registered with the client
					if (!isValidRedirectUri(redirectUri, client)) {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_REQUEST,
								error_description:
									"The provided redirect URI is not registered for this client or is otherwise invalid.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We must check that the other required parameters for this grant type are present

					const [code] = getUniqueField(body, "code");
					if (!code) {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_REQUEST,
								error_description:
									"The request content must include a `code` parameter. It must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We check if the code exists in a record (matching algorithm is out of scope)
					const authorizationCodeRecord = await findAuthorizationCodeRecordByCode(code);
					if (!authorizationCodeRecord) {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_GRANT,
								error_description:
									"No record was found for the provided `code`. The code is either incorrect or it has been revoked.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We make sure it was issued to this client
					if (authorizationCodeRecord.clientId !== clientId) {
						// NOTE: Additional security measures might be taken in this case, because the code should be unique
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_GRANT,
								error_description: "The provided `code` is invalid.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We make sure it's not expired
					if (isExpiredTimestamp(authorizationCodeRecord.expiresAt)) {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_GRANT,
								error_description:
									"The provided `code` has expired. Please request another code from the authorization server.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We make sure it wasn't used before
					if (authorizationCodeRecord.isUsed) {
						// We revoke all access and refresh tokens previously issued based on that authorization code
						await revokeTokensForCode(code);

						return Response.json(
							{
								error: TokenErrorCodes.INVALID_GRANT,
								error_description:
									"The provided `code` has already been used. All tokens previously issued for it are now revoked.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					const [codeVerifier] = getUniqueField(body, "code_verifier");
					if (!codeVerifier) {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_REQUEST,
								error_description:
									"The provided request content must include a `code_verifier` parameter. It must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We validate the code verifier
					if (!isValidCodeVerifier(codeVerifier, authorizationCodeRecord)) {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_REQUEST,
								error_description: "The provided `code_verifier` is invalid.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// The Authorization Server can ignore the scope entirely, but if present, we must validate it
					const [scope, scopeError] = getUniqueField(body, "scope");
					if (scopeError?.reason === "duplicate_param") {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_REQUEST,
								error_description:
									"The `scope` query parameter is optional. However, if provided, it must have a valid value and it must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					if (scope && !isScopeWithin(scope, authorizationCodeRecord.scope)) {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_REQUEST,
								error_description: "The provided `scope` is not valid for the authorization code.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// Scope requested or scope authorized by the Resource Owner (client could request lesser scope)
					const validatedScope = scope ?? authorizationCodeRecord.scope;

					// Success! We can generate the tokens
					const token_type: AccessTokenType = "bearer";

					// TODO: Must handle the registration function failing
					const { accessToken, accessTokenExpiresAt, refreshToken } = await registerClientAccess({
						clientId,
						scope: validatedScope,
						providerId: AUTHORIZATION_SERVER_ID,
						tokenType: token_type,
					});

					return Response.json(
						{
							scope: validatedScope,
							access_token: accessToken,
							token_type,
							expires_in: remainingSecondsUntilTimestamp(accessTokenExpiresAt),
							refresh_token: refreshToken,
						},
						{
							status: OK.code,
							headers: {
								"Cache-Control": "no-store",
							},
						},
					);
				}

				/**
				 * This grant type represents access on behalf of the client itself (machine-to-machine).
				 *
				 * It can be used only by confidential clients
				 */
				if (grantType === "client_credentials") {
					const [ok, authFailure] = authenticateClient(client, body);
					if (!ok) {
						return Response.json(
							{
								error: authFailure.error,
								error_description: authFailure.error_description,
							},
							authFailure.responseInit,
						);
					}

					if (client.type !== "confidential") {
						return Response.json(
							{
								error: TokenErrorCodes.UNAUTHORIZED_CLIENT,
								error_description: "The client is not authorized to use this authorization grant type.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// The Authorization Server can ignore the scope entirely, but if present, we must validate it
					const [scope, scopeError] = getUniqueField(body, "scope");
					if (scopeError?.reason === "duplicate_param") {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_REQUEST,
								error_description:
									"The `scope` query parameter is optional. However, if provided, it must have a valid value and it must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					if (scope && !isScopeWithin(scope, client.scope)) {
						return Response.json(
							{
								error: TokenErrorCodes.INVALID_REQUEST,
								error_description: "The provided `scope` is not valid for the authorization code.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// Scope requested or scope authorized by the Resource Owner (client could request lesser scope)
					const validatedScope = scope ?? client.scope;

					// Success! We can generate the tokens
					const token_type: AccessTokenType = "bearer";

					// TODO: Must handle the registration function failing
					const { accessToken, accessTokenExpiresAt, refreshToken } = await registerClientAccess({
						clientId,
						scope: validatedScope,
						providerId: AUTHORIZATION_SERVER_ID,
						tokenType: token_type,
					});

					return Response.json(
						{
							scope: validatedScope,
							access_token: accessToken,
							token_type,
							expires_in: remainingSecondsUntilTimestamp(accessTokenExpiresAt),
							refresh_token: refreshToken,
						},
						{
							status: OK.code,
							headers: {
								"Cache-Control": "no-store",
							},
						},
					);
				}

				if (grantType === "refresh_token") {
					return Response.json({
						error: "server_error",
						error_description: "Functionality is not yet implemented",
					});
				}

				// The request should never get here, but in case it does, we handle it
				return Response.json({
					error: "server_error",
					error_description: "Server cannot process the request.",
				});
			},
		},
	},
});

const AUTHORIZATION_SERVER_ID = "https://auth.example.com";

function getUniqueField(formData: FormData, fieldName: string) {
	const field = formData.getAll(fieldName);

	if (!field || !Array.isArray(field)) return [undefined, { reason: "missing_param" }] as const;
	if (field.length > 1) return [undefined, { reason: "duplicate_param" }] as const;

	return [field[0] as string, null] as const;
}

async function findOAuthClientById(_clientId: string): Promise<OAuthClient | null> {
	return {
		type: "confidential",
		client_id: "4u0rfoisdjflsj",
		redirect_uris: ["http://example.com"],
		grant_types: ["authorization_code"],
		response_types: ["code"],
		token_endpoint_auth_method: "client_secret_basic",
		supported_oauth_versions: ["2.0", "2.1"],
	};
}

function isValidClientSecret(secret: string, client: OAuthClient, type: "post" | "basic") {
	/**
   *  When using the HTTP Basic authentication scheme as defined in
     Section 11 of [RFC9110] to authenticate with the authorization
     server, the client identifier is encoded using the application/x-www-
     form-urlencoded encoding algorithm per Appendix B, and the encoded
     value is used as the username; the client secret is encoded using the
     same algorithm and used as the password.
   */
	return false;
}

const supportedGrantTypes = new Set(["authorization_code", "refresh_token", "client_credentials"]);

function isValidGrantType(grant: string): grant is GrantType {
	return supportedGrantTypes.has(grant);
}

type AuthenticationError = {
	error: TokenErrorCode;
	error_description: string;
	responseInit?: ResponseInit;
};

function authenticateClientWithSecretPost(name: string) {
	return "Hello World";
}

function authenticateClientWithBasic(name: string) {
	return "Hello World";
}

/**
 * For confidential clients, the authorization server MAY accept any form of
 * client authentication meeting its security requirements (e.g., client secret,
 * public/private key pair).
 */
function authenticateClient(
	client: OAuthClient,
	body: FormData,
): [true, null] | [false, AuthenticationError] {
	// TODO: Prevent multiple methods of authentication at the same time

	// The client uses POST parameters
	if (client.token_endpoint_auth_method === "client_secret_post") {
		const [clientSecret] = getUniqueField(body, "client_secret");
		if (!clientSecret) {
			return [
				false,
				{
					error: TokenErrorCodes.INVALID_REQUEST,
					error_description:
						"The request content must include a `client_secret` parameter for authenticating the client. It must not be included more than once. Alternatively, you can modify the client authentication preferences with the authorization server.",
					responseInit: { status: BAD_REQUEST.code },
				},
			];
		}

		if (!isValidClientSecret(clientSecret, client, "post")) {
			return [
				false,
				{
					error: TokenErrorCodes.INVALID_CLIENT,
					error_description: "The provided client secret is not valid.",
					responseInit: { status: UNAUTHORIZED.code },
				},
			];
		}

		// Client is authenticated
		return [true, null] as const;
	}

	// The client uses basic authentication
	if (client.token_endpoint_auth_method === "client_secret_basic") {
		const authorization = getRequestHeader("Authorization"); // NOTE: This is a side-effect; might fail
		if (!authorization) {
			return [
				false,
				{
					error: TokenErrorCodes.INVALID_CLIENT,
					error_description:
						"The request content must include an 'Authorization' header for authenticating the client. Alternatively, you can modify the client authentication preferences with the authorization server.",
					responseInit: {
						status: UNAUTHORIZED.code,
						headers: {
							"WWW-Authenticate": `Basic realm="User Visible Realm", charset="UTF-8"`,
						},
					},
				},
			];
		}

		const [authorizationType, clientSecret] = authorization.split(" ");
		if (authorizationType !== "Basic") {
			return [
				false,
				{
					error: TokenErrorCodes.INVALID_CLIENT,
					error_description:
						"The authorization header must be set to 'Basic'. The value must be separated with a space (e.g., `Authorization: Basic your_value`).",
					responseInit: {
						status: UNAUTHORIZED.code,
						headers: {
							"WWW-Authenticate": `Basic realm="User Visible Realm", charset="UTF-8"`,
						},
					},
				},
			];
		}

		if (!isValidClientSecret(clientSecret, client, "basic")) {
			return [
				false,
				{
					error: TokenErrorCodes.INVALID_CLIENT,
					error_description: "The provided client secret is not valid.",
					responseInit: {
						status: UNAUTHORIZED.code,
						headers: {
							"WWW-Authenticate": `Basic realm="User Visible Realm", charset="UTF-8"`,
						},
					},
				},
			];
		}

		// Client is succesfully authenticated
		return [true, null] as const;
	}

	return [
		false,
		{
			error: TokenErrorCodes.INVALID_CLIENT,
			error_description:
				"The client does not have a valid authentication method for the /token endpoint registered with the server.",
			responseInit: {
				status: UNAUTHORIZED.code,
			},
		},
	] as const;
}

function canUseGrantType(grantType: string, client: OAuthClient) {
	return false;
}

function isValidRedirectUri(uri: string, client: OAuthClient) {
	/**
	 * The validation of a redirect URI must comply with the OAuth 2.1 communication
	 * security and other security best practices. This implementation is for
	 * illustrations purposes only,
	 *
	 * An exception is made for native apps using a localhost URI: In this case, the
	 * Authorization Server MUST allow variable port numbers as described in Section
	 * 7.3 of [RFC8252]
	 */

	return client.redirect_uris.includes(uri);
}

function isExpiredTimestamp(_timestamp: number): boolean {
	return false;
}

async function findAuthorizationCodeRecordByCode(_code: string): Promise<AuthorizationCodeRecord> {
	return {
		code: "afijlajd",
		scope: "read",
		clientId: "od23-r43a-oieh-j3oia",
		redirectUri: "http://example.com",
		codeChallenge: "aofjaojfoa",
		codeChallengeMethod: "S256",
		userAgent: "chromium_something",
		isUsed: false,
		expiresAt: Date.now() + 10 * 60 * 1000, // 10 mins from now
	};
}

function isValidCodeVerifier(_codeVerifier: string, _targetRecord: AuthorizationCodeRecord) {
	/**
	 * Verify the code_verifier by calculating the code challenge received from it and
	 * comparing it with the previously associated code_challenge, after transforming
	 * it according to the code_challenge_method method specified by the client
	 */

	return false;
}

async function revokeTokensForCode(_code: string): Promise<void> {}

function generateAccessToken(_info: { scope: Scope; token_type: AccessTokenType }) {
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

function isScopeWithin(_source: Scope, _target: Scope | undefined) {
	return false;
}

function remainingSecondsUntilTimestamp(_timestamp: number) {
	return 0;
}

type ClientTokens = {
	accessToken: AccessToken;
	accessTokenExpiresAt: number;
	refreshToken?: string;
};

const ACCESS_TOKEN_LIFETIME_S = 7200; // Up to Authorization Server (2h here)
const REFRESH_TOKEN_LIFETIME_S = 604_800; //  Up to Authorization Server (7 days here)

async function registerClientAccess(_info: Partial<ClientAccessRecord>): Promise<ClientTokens> {
	const accessToken = generateAccessToken({
		scope: _info.scope as string,
		token_type: _info.tokenType as AccessTokenType,
	});
	const accessTokenExpiresAt = Date.now() + ACCESS_TOKEN_LIFETIME_S;
	const refreshToken: string = generateRefreshToken({ scope: _info.scope as string });
	const refreshTokenExpiresAt = Date.now() + REFRESH_TOKEN_LIFETIME_S;

	// Here we actually go and store it in the storage
	await createClientAccess({
		clientId: _info.clientId as string,
		scope: _info.scope as string,
		providerId: AUTHORIZATION_SERVER_ID,
		tokenType: _info.tokenType as AccessTokenType,
		accessToken,
		accessTokenExpiresAt,
		refreshToken,
		refreshTokenExpiresAt,
	}); // TODO: Should guard against potential registration errors with the storage

	return { accessToken, accessTokenExpiresAt, refreshToken } as ClientTokens;
}

async function createClientAccess(info: ClientAccessRecord): Promise<void> {}
