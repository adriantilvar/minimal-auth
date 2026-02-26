import { createFileRoute } from "@tanstack/react-router";
import { getRequestHeader } from "@tanstack/react-start/server";
import { BAD_REQUEST, INTERNAL_SERVER_ERROR, OK, UNAUTHORIZED } from "@/lib/const/http-response-status";
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
 * For confidential clients, the authorization server MAY accept any form of
 * client authentication meeting its security requirements (e.g., client secret,
 * public/private key pair).
 *
 * It is RECOMMENDED to use asymmetric (public-key based) methods for client
 * authentication, such as mTLS [RFC8705] * or using signed JWTs in accordance
 *  with [RFC7521], [RFC7523], and their update [I-D.ietf-oauth-rfc7523bis]
 * (defined in [OpenID] as the client authentication method private_key_jwt).
 *
 * Since the client secret authentication method involves a password,
 * the authorization server MUST protect any endpoint utilizing it
 * against brute force attacks.
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
				if (!isSecureConnection(request.url)) {
					return Response.json(
						{
							error: ErrorCodes.INVALID_REQUEST,
							error_description: "The request must be made over HTTPS.",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				const contentType = getRequestHeader("Content-Type");
				if (!contentType) {
					// Automatically sets the Content-Type header to `application/json` and serializes the JSON object
					return Response.json(
						{
							error: ErrorCodes.INVALID_REQUEST,
							error_description: "The request must include `Content-Type` header",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				const [mediaType, encoding] = contentType.split("; ");

				if (mediaType !== "application/x-www-form-urlencoded") {
					return Response.json(
						{
							error: ErrorCodes.INVALID_REQUEST,
							error_description: "The request must use `application/x-www-form-urlencoded` media type.",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				// If not provided, we assume UTF-8; if another encoding is provided, we reject the request
				if (encoding && encoding.toLowerCase() !== "charset=utf-8") {
					return Response.json(
						{
							error: ErrorCodes.INVALID_REQUEST,
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
							error: ErrorCodes.INVALID_REQUEST,
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
						error: ErrorCodes.UNSUPPORTED_GRANT_TYPE,
						error_description: `The '${grantType}' grant type is not a supported.`,
					});
				}

				// We strictly require the `client_id`, as we want to know if the client is public or confidential
				const [clientId] = getUniqueField(body, "client_id");
				if (!clientId) {
					return Response.json(
						{
							error: ErrorCodes.INVALID_REQUEST,
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
							error: ErrorCodes.INVALID_CLIENT,
							error_description:
								"No client is registered with the provided `client_id`. You need to register the client before requesting an access token.",
						},
						{
							status: BAD_REQUEST.code,
						},
					);
				}

				// We check if the client is allowed to use the grant type they provided
				if (!canUseGrantType(grantType, client)) {
					return Response.json(
						{
							error: ErrorCodes.UNAUTHORIZED_CLIENT,
							error_description: "The client is not authorized to use this authorization grant type.",
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
							error: ErrorCodes.INVALID_CLIENT,
							error_description: "The server does not support public clients for the time being.",
						},
						{
							status: BAD_REQUEST.code,
						},
					);
				}

				// We're only dealing with a confidential client-- we must authenticate it regardless of grant type

				// We make sure the client can use either 'client_secret_basic' or 'client_secret_post'
				if (!client.token_endpoint_auth_method || client.token_endpoint_auth_method === "none") {
					return Response.json(
						{
							error: ErrorCodes.INVALID_CLIENT,
							error_description:
								"The client registration does not have a valid authentication method for the /token endpoint.",
						},
						{ status: UNAUTHORIZED.code },
					);
				}

				const authorization = getRequestHeader("Authorization");
				const clientSecret = getUniqueField(body, "client_secret")[0];

				// We guard against multiple authentication methods being used at the same time
				if (authorization && clientSecret) {
					return Response.json(
						{
							error: ErrorCodes.INVALID_REQUEST,
							error_description: "The request must use only one method for authenticating the client.",
						},
						{ status: UNAUTHORIZED.code },
					);
				}

				const [ok, authFailure] =
					client.token_endpoint_auth_method === "client_secret_basic"
						? authenticateWithClientSecretBasic(client, authorization)
						: authenticateWithClientSecretPost(client, clientSecret);

				if (!ok) {
					return Response.json(
						{
							error: authFailure.error,
							error_description: authFailure.error_description,
						},
						authFailure.responseInit,
					);
				}

				/**
				 * This grant type represents access on behalf of the client itself (machine-to-machine).
				 *
				 * It can be used only by confidential clients
				 */
				if (grantType === "client_credentials") {
					// Additional guard to ensure only condifential clients use it
					if (client.type !== "confidential") {
						return Response.json(
							{
								error: ErrorCodes.UNAUTHORIZED_CLIENT,
								error_description: "The client is not authorized to use this authorization grant type.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// The Authorization Server can ignore the scope entirely, but if present, we must validate it
					const [requestScope, scopeError] = getUniqueField(body, "scope");
					if (scopeError?.reason === "duplicate_param") {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description:
									"The `scope` query parameter is optional. However, if provided, it must have a valid value and it must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					if (requestScope && !isScopeWithin(requestScope, client.scope)) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description: "The provided `scope` is not within the allowed scope for this client.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// Success! We can generate the tokens
					const scope = requestScope ?? client.scope; // server must enforce default scope on client registration
					const token_type: AccessTokenType = "bearer";
					// TODO: Must handle the registration function failing
					const { accessToken, accessTokenExpiresAt, refreshToken } = await registerClientAccess({
						clientId,
						scope,
						tokenType: token_type,
					});

					return Response.json(
						{
							scope,
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

				// TODO: ensure in authorization request old codes get removed

				/**
				 * This grant type represents access on behalf of an end-user (user-to-machine).
				 *
				 * It can be used by both public and confidential clients.
				 */
				if (grantType === "authorization_code") {
					// We must ensure the client uses PKCE
					const [code] = getUniqueField(body, "code");
					if (!code) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description:
									"The request content must include a `code` parameter. It must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We check that there is an authorization code for the client (server ensures only one exists at a time)
					const codeRecord = await findAuthorizationCodeByClientId(clientId);
					if (!codeRecord) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_GRANT,
								error_description:
									"No record was found for the provided `code`. The code is either incorrect or it has been revoked.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We make sure it wasn't used before
					if (codeRecord.isUsed) {
						// We revoke all access and refresh tokens previously issued based on that authorization code
						await revokeTokensForCode(code);

						return Response.json(
							{
								error: ErrorCodes.INVALID_GRANT,
								error_description:
									"The provided `code` has already been used. All tokens previously issued for it are now revoked.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We make sure it's not expired
					if (isExpiredTimestamp(codeRecord.expiresAt)) {
						// If it expired without having been used before, we just remove it
						await deleteAuthorizationCode(codeRecord.id);

						return Response.json(
							{
								error: ErrorCodes.INVALID_GRANT,
								error_description:
									"The provided `code` has expired. You need to start a new authorization flow.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// Providing the `redirect_uri` is not strictly necessary in OAuth 2.1
					// However, it can be enforced for backwards compatibility with OAuth 2.0
					const [redirectUri] = getUniqueField(body, "code");
					if (!redirectUri) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description:
									"The request content must include a `redirect_uri` parameter. It must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We check that the provided redirect URI is the same as the one used for the grant request
					if (redirectUri !== codeRecord.redirectUri) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description:
									"The provided redirect URI does not match the one used for the authorization code grant request.",
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
								error: ErrorCodes.INVALID_REQUEST,
								error_description:
									"The provided request content must include a `code_verifier` parameter. It must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We validate the code verifier
					if (!isValidCodeVerifier(codeVerifier, codeRecord)) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description: "The provided `code_verifier` is invalid.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// The Authorization Server can ignore the scope entirely, but if present, we must validate it
					const [requestScope, scopeError] = getUniqueField(body, "scope");
					if (scopeError?.reason === "duplicate_param") {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description:
									"The `scope` query parameter is optional. However, if provided, it must have a valid value and it must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					if (requestScope && !isScopeWithin(requestScope, codeRecord.scope)) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description: "The provided `scope` is not valid for the authorization code.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// Success! We can generate the tokens
					const scope = requestScope ?? client.scope;
					const token_type: AccessTokenType = "bearer";

					// TODO: Must handle the registration function failing
					const { accessToken, accessTokenExpiresAt, refreshToken } = await registerClientAccess({
						clientId,
						scope,
						tokenType: token_type,
					});

					return Response.json(
						{
							scope,
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
					const [requestRefreshToken] = getUniqueField(body, "refresh_token");
					if (!requestRefreshToken) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description:
									"The request content must include a `refresh_token` parameter. It must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We check that the client has an access record
					const accessRecord = await findAccessRecordByClientId(clientId);
					if (!accessRecord) {
						return Response.json(
							{
								error: ErrorCodes.UNAUTHORIZED_CLIENT,
								error_description: "This client has not been granted access or the access has been revoked.",
							},
							{
								status: UNAUTHORIZED.code,
							},
						);
					}

					// We check that a refresh token exists for this client
					if (!accessRecord.refreshToken) {
						return Response.json(
							{
								error: ErrorCodes.UNAUTHORIZED_CLIENT,
								error_description:
									"Thre is no refresh token associated with this client. The server either did not provide a refresh token to this client or the previous refresh token has been revoked.",
							},
							{
								status: UNAUTHORIZED.code,
							},
						);
					}

					// We check that the existing token is not expired
					if (isExpiredTimestamp(accessRecord.refreshTokenExpiresAt)) {
						// If the refresh token is expired, the access token must be long expired as well
						await deleteAccessRecord(accessRecord.id);

						return Response.json(
							{
								error: ErrorCodes.INVALID_GRANT,
								error_description:
									"The provided `refresh_token` has expired. You need to start a new authorizaztion flow.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// We validate the refresh token received in the request
					if (!isMatchingRefreshToken(requestRefreshToken, accessRecord.refreshToken)) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_GRANT,
								error_description: "The provided `refresh_token` is invalid.",
							},
							{
								status: UNAUTHORIZED.code,
							},
						);
					}

					// The Authorization Server can ignore the scope entirely, but if present, we must validate it
					const [requestScope, scopeError] = getUniqueField(body, "scope");
					if (scopeError?.reason === "duplicate_param") {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description:
									"The `scope` query parameter is optional. However, if provided, it must have a valid value and it must not be included more than once.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					if (requestScope && !isScopeWithin(requestScope, accessRecord.scope)) {
						return Response.json(
							{
								error: ErrorCodes.INVALID_REQUEST,
								error_description: "The provided `scope` is not valid for the authorization code.",
							},
							{
								status: BAD_REQUEST.code,
							},
						);
					}

					// Success! We can generate the tokens
					const scope = requestScope ?? client.scope;
					const token_type: AccessTokenType = "bearer";

					// We genereate both a new access token as well as a new refresh token-- client must discard old ones

					// TODO: Must handle the registration function failing
					const { accessToken, accessTokenExpiresAt, refreshToken } = await registerClientAccess({
						clientId,
						scope,
						tokenType: token_type,
					});

					return Response.json(
						{
							scope,
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

				// The request should never get here, but in case it does, we handle it
				return Response.json(
					{
						error: "server_error",
						error_description: "Server cannot process the request.",
					},
					{ status: INTERNAL_SERVER_ERROR.code },
				);
			},
		},
	},
});

function isSecureConnection(url: string) {
	/**
	 * This is for illustration purposes-only. In production environment, HTTPS should be enforced at the host level
	 */
	return url.includes("localhost") || url.startsWith("https://");
}

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
		token_endpoint_auth_method: "client_secret_post",
		supported_oauth_versions: ["2.0", "2.1"],
	};
}

function isValidClientSecret(_secret: string, _client: OAuthClient, _type: "post" | "basic") {
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

function authenticateWithClientSecretPost(
	client: OAuthClient,
	clientSecret: string | undefined,
): [true, null] | [false, AuthenticationError] {
	if (!clientSecret) {
		return [
			false,
			{
				error: ErrorCodes.INVALID_REQUEST,
				error_description:
					"The request content must include a `client_secret` parameter for authenticating this client. It must not be included more than once. Alternatively, you can modify the client authentication preferences with the authorization server.",
				responseInit: { status: BAD_REQUEST.code },
			},
		];
	}

	if (!isValidClientSecret(clientSecret, client, "post")) {
		return [
			false,
			{
				error: ErrorCodes.INVALID_CLIENT,
				error_description: "The provided client secret is not valid.",
				responseInit: { status: UNAUTHORIZED.code },
			},
		];
	}

	// Client is authenticated
	return [true, null] as const;
}

function authenticateWithClientSecretBasic(
	client: OAuthClient,
	authorization: string | undefined,
): [true, null] | [false, AuthenticationError] {
	if (!authorization) {
		return [
			false,
			{
				error: ErrorCodes.INVALID_CLIENT,
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
				error: ErrorCodes.INVALID_CLIENT,
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
				error: ErrorCodes.INVALID_CLIENT,
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

function canUseGrantType(_grantType: string, _client: OAuthClient) {
	return false;
}

function isExpiredTimestamp(_timestamp: number): boolean {
	return false;
}

async function findAuthorizationCodeByClientId(_clientId: string): Promise<AuthorizationCodeRecord | null> {
	return {
		id: "some_db_id",
		code: "afijlajd",
		scope: "read",
		clientId: "od23-r43a-oieh-j3oia",
		redirectUri: "http://example.com",
		codeChallenge: "aofjaojfoa",
		codeChallengeMethod: "S256",
		userAgent: "chromium_something",
		isUsed: false,
		expiresAt: 1761482700,
	};
}

async function findAccessRecordByClientId(_clientId: string): Promise<ClientAccessRecord | null> {
	return {} as ClientAccessRecord;
}

async function deleteAccessRecord(_recordId: string): Promise<void> {}

function isValidCodeVerifier(_codeVerifier: string, _targetRecord: AuthorizationCodeRecord) {
	/**
	 * Verify the code_verifier by calculating the code challenge received from it and
	 * comparing it with the previously associated code_challenge, after transforming
	 * it according to the code_challenge_method method specified by the client
	 */

	return false;
}

function isMatchingRefreshToken(_source: string, _target: string) {
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
		id: "random_id",
		clientId: _info.clientId as string,
		scope: _info.scope as string,
		tokenType: _info.tokenType as AccessTokenType,
		accessToken,
		accessTokenExpiresAt,
		refreshToken,
		refreshTokenExpiresAt,
	});

	// TODO: Should guard against potential registration errors with the storage

	return { accessToken, accessTokenExpiresAt, refreshToken } as ClientTokens;
}

async function createClientAccess(_info: ClientAccessRecord): Promise<void> {}

async function deleteAuthorizationCode(_id: string): Promise<void> {}
