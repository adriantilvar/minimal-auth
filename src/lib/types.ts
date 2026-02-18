/**
 * Client types are defined based on their ability to authenticate securely with the authorization server:
 * - "confidential"-- clients that have credentials with the authorization server
 * - "public"-- clients without credentials
 *
 * Note: There is no requirement that an authorization server supports a particular client type.
 */
type ClientType = "confidential" | "public";

type ClientRegistration = {
	type: ClientType;
	/**
	 * Represents the registration info provided by the client and it is used to identify it in the context of an
	 * authorization server.
	 *
	 * Notes:
	 * - It can be issued by the authorization server itself or by another party.
	 * - It is **NOT** a secret and **MUST NOT** be used alone for client authentication.
	 */
	clientID: string; // TODO: AS should document the size it issues
	/**
	 * The URI of the client that the authorization server redirects the user agent back to after completing its
	 * interaction with the resource owner.
	 *
	 * Notes:
	 * - The authorization server **MAY** allow the client to register multiple redirect URIs
	 * - A redirect URI **MUST** be an absolute URI
	 * - A redirect URI  **MAY** include a query string component, which **MUST** be retained when adding additional
	 * query parameters
	 * - A redirect URI  **MUST NOT** include a fragment component
	 */
	redirectURI: string | string[]; // TODO: enforce absolute URI
};

/**
 * What the authorization server receives in a client request body
 *
 * Note: The parameters can only be transmitted in the request content **MUST NOT** be included in the request URI
 */
type ClientRequest = {
	clientID: ClientRegistration["clientID"];
	clientSecret: string;
};

type Grant = "authorization_code" | "refresh_token" | "client_credentials";

/**
 * A string representing an authorization issued to the client that allows it to access specific protected resources.
 *
 * The `Resource Server` may use the token to retrieve authorization info, or the token may self-contain the
 * authorization info in a verifiable manner (i.e. a token string consisting of a signed data payload).
 *
 * Notes:
 * - An access token is considered opaque to the client, even if it has a structure
 * - The client **MUST NOT** expect to be able to parse the access token value
 * - Access tokens are short-lived to reduce the blast radius of a leak
 * - No consistent encoding or format is required, other than what is expected by the `Resource Server`
 */
type AccessToken = string;

/**
 * The `Authorization Server` and `Resource Server` can use the scope mechanism to limit what type of resources or
 * level of access a particular `client` can have. For example, a `client` may only need "read" access to a resource,
 * and doesn't need to update the resource.
 *
 * The value of the "scope" parameter is expressed as a list of space-delimited, case-sensitive strings. If the value
 * contains multiple spaced-delimited strings, their order does not matter.
 *
 * Notes:
 * - Scopes are defined by `Authorization Server` or by extensions or profiles of OAuth (e.g. OpenID). It is
 * recommended to avoid defining custom scopes that conflict with scopes from known extensions.
 */
type Scope = string;

/**
 * ## Limited-Scope Access Token
 *
 * A 'limited-scope' access token is intended to be issued to `clients` with less privileges than the user granted the
 * access has.
 *
 * To request a limited-scope access token, the `client` uses the `scope` request parameter at the authorization or
 * token endpoints, depending on the grant type used.
 *
 * Notes:
 * - The `Authorization Server` provides the client the ability to request specific scopes and associates those scopes
 * with the access token issued to the `client`.
 * - The `Resource Server` is then responsible for enforcing scopes when presented with a limited-scope access token.
 * - The `Authorization Server` **MAY** fully or partially ignore the scope requested by the client, based on its
 * policy or the `Resource Server's` instructions.
 * - The `Authorization Server` **SHOULD** document its scope requirements and default value (if defined).
 *
 * ## Bearer Tokens
 *
 * A 'bearer token' is a security token with the property that any party in possession of the token (a "bearer") can
 * use it in any way that any other party in possession of it can.
 *
 * Notes:
 * - Using a bearer token does not require a bearer to prove possession of cryptographic key material
 * (proof-of-possession). They may, however, be enhanced with proof-of-possession specs such as DPoP [RFC9449] and
 * mTLS [RFC8705].
 * - If a bearer token uses an encoding mechanism to contain the authorization info in the token itself, it MUST use
 * integrity protection sufficient to prevent the token from being modified (an example is the JSON Web Token Profile
 * for Access Tokens [RFC9068]).
 *
 * ## Sender-Constrained Access Tokens
 *
 * A 'sender-constrained' access token binds its use to a specific sender. The sender is obliged to demonstrate
 * knowledge of a certain secret as a prerequisite for the acceptance of that access token at the recipient (e.g. a
 * `Resource Server`).
 */
type AccessTokenType = "limited_scope" | "bearer" | "sender_constrained";

// TOKEN ENDPOINT

/**
 * The request must use the `application/x-www-form-urlencoded` media type, with the character encoding of UTF-8.
 *
 * Example
 * ```bash
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 * Content-Type: application/x-www-form-urlencoded
 *
 * grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
 * &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
 * &code_verifier=3641a2d12d66101249cdf7a79c000c05d214bf146497bed
 *```
 *
 */
type TokenRequest = {
	type: "POST";
	/**
	 * The grant type determines the further parameters required or supported by the token request
	 */
	grantType: Grant;
	/**
	 * The client ID is needed when a form of client authentication that relies on it is used, or the grant type requires
	 * identification of public clients.
	 */
	clientId?: ClientRegistration["clientID"];
};

/**
 * Notes:
 * - The response must use the `application/json` media type.
 * - The Authorization Server **MUST** include the HTTP `Cache-Control` response header field with a value of
 * `'no-store'` in any response containing tokens, credentials, or other sensitive information.
 *
 * Example:
 * ```bash
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 *
 * {
 *    "access_token":"2YotnFZFEjr1zCsicMWpAA",
 *    "token_type":"Bearer",
 *    "expires_in":3600,
 *    "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
 *    "example_parameter":"example_value"
 * }
 * ```
 */
type TokenSuccessResponse = {
	status: 200;
	accessToken: string;
	/**
	 * The type of the access token issued. Value is case insensitive.
	 */
	tokenType: "some_type"; // value is case insensitive
	/**
	 * The lifetime of the access token in seconds. For example, the value `3600` denotes that the access token will
	 * expire in one hour from the time the response was generated.
	 */
	expiresIn: number;
	scope: string; // defined by Authorization Server -> OIDC
	/**
	 * A token that can be used to obtain new access tokens based on the grant passed in the corresponding token request.
	 *
	 * Note:
	 * It **MUST** be bound to the scope and Resource Servers as consented by the Resource Owner.
	 */
	refreshToken?: string;
};

/**
 * Notes:
 * - The response must use the `application/json` media type.
 *
 * Example:
 *
 * ```bash
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 * Cache-Control: no-store
 *
 * {
 * "error": "invalid_request"
 * }
 * ```
 */
type TokenErrorResponse = (
	| InvalidRequest
	| InvalidClient
	| InvalidGrant
	| UnauthorizedClient
	| UnsupportedGrantType
	| InvalidScope
) & {
	errorDescription?: string; // MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E
	errorURI?: string; // MUST NOT include characters outside the set %x21 / %x23-5B / %x5D-7E.
};

/**
 * The request is missing a required parameter, includes an unsupported parameter value (other than grant type),
 * repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client,
 * contains a `code_verifier` although no `code_challenge` was sent in the authorization request, or is malformed.
 */
type InvalidRequest = {
	status: 400;
	error: "invalid_request";
};

/**
 * Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication
 * method). The Authorization Server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP
 * authentication schemes are supported. If the client attempted to authenticate via the Authorization request header
 * field, the Authorization Server MUST respond with an HTTP 401 (Unauthorized) status code and include the
 * WWW-Authenticate response header field matching the authentication scheme used by the client.
 */
type InvalidClient = {
	status: 400 | 401;
	error: "invalid_client";
};

/**
 * The provided authorization grant (e.g., authorization code, Resource Owner credentials) or refresh token is invalid,
 * expired, revoked, does not match the redirect URI used in the authorization request, or was issued to another client.
 */
type InvalidGrant = {
	status: 400;
	error: "invalid_grant";
};

/**
 * The authenticated client is not authorized to use this authorization grant type.
 */
type UnauthorizedClient = {
	status: 400;
	error: "unauthorized_client";
};

/**
 * The authorization grant type is not supported by the Authorization Server.
 */
type UnsupportedGrantType = {
	status: 400;
	error: "unsupported_grant_type";
};

/**
 * The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the Resource Owner.
 */
type InvalidScope = {
	status: 400;
	error: "invalid_scope";
};
