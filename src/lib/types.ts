/**
 * Client types are defined based on their ability to authenticate securely with the authorization server:
 * - "confidential"-- clients that have credentials with the authorization server and can hold a `client_secret`
 * - "public"-- clients without credentials and can't hold a `client_secret`
 *
 * Note: There is no requirement that an authorization server supports a particular client type.
 */
export type ClientType = "confidential" | "public";

export type GrantType =
	| "authorization_code"
	| "client_credentials"
	| "refresh_token"
	| "urn:ietf:params:oauth:grant-type:jwt-bearer"
	| "urn:ietf:params:oauth:grant-type:saml2-bearer";

export type ResponseType = "code"; // The only one supported by OAuth 2.1

export type TokenEndpointAuthMethod = "none" | "client_secret_post" | "client_secret_basic";

export type OAuthClient = {
	type: ClientType;
	/**
	 * Represents the registration info provided by the client and it is used to
	 * identify it in the context of an authorization server.
	 *
	 * Notes:
	 * - It can be issued by the authorization server itself or by another party.
	 * - It is **NOT** a secret and **MUST NOT** be used alone for client authentication.
	 */
	client_id: string; // TODO: Should document the size it issues

	/**
	 * Represents an OAuth 2.1 client secret string that the Authorization Server can optionally provide to confidential clients during the client registration process.
	 *
	 * Notes:
	 * - It is used by a confidential client to authenticate to the /token endpoint.
	 * - If issued, this MUST be unique for each "client_id" and SHOULD be unique for
	 * multiple instances of a client using the same "client_id".
	 */
	client_secret?: string;

	/**
	 * OAuth 2.1 grant type strings that the client can use at the token endpoint. If not
	 * provided, defaults to `authorization_code`.
	 *
	 * They are defined as:
	 * - "authorization_code": The authorization code grant type defined in the OAuth spec
	 * - "client_credentials": The client credentials grant type defined in the OAuth spec
	 * - "refresh_token": The refresh token grant type defined in the OAuth spec
	 * - "urn:ietf:params:oauth:grant-type:jwt-bearer": The JWT Bearer Token Grant Type
	 * defined in OAuth JWT Bearer Token Profiles [RFC7523]
	 * - "urn:ietf:params:oauth:grant-type:saml2-bearer": The SAML 2.0 Bearer Assertion
	 * Grant defined in OAuth SAML 2 Bearer Token Profiles [RFC7522]
	 */
	grant_types: GrantType[];

	/**
	 * Array of the OAuth 2.1 response type strings that the client can
	 * use at the authorization endpoint. If not provided, defaults to `code`
	 */
	response_types: ResponseType[];

	/**
	 * The URI of the client that the authorization server redirects the
	 * user agent back to after completing its
	 * interaction with the resource owner.
	 *
	 * Clients using flows with redirection MUST register their
	 * redirection URI values.
	 *
	 * Notes:
	 * - The authorization server **MAY** allow the client to register
	 * multiple redirect URIs
	 * - A redirect URI **MUST** be an absolute URI
	 * - A redirect URI  **MAY** include a query string component, which
	 * **MUST** be retained when adding additional
	 * query parameters
	 * - A redirect URI  **MUST NOT** include a fragment component
	 */
	redirect_uris: string[]; // TODO: enforce absolute URI

	/**
	 * An indicator of the requested authentication method for the token endpoint. If not
	 * provided, defaults to `client_secret_basic`
	 *
	 * The values defined by [RFC7591] are:
	 * - "none": The client is a public client and does not have a client secret
	 * - "client_secret_post": The client uses the HTTP POST parameters
	 * - "client_secret_basic": The client uses HTTP Basic
	 */
	token_endpoint_auth_method: TokenEndpointAuthMethod;

	/**
	 * A space-separated list of scope values that the client can use when
	 * requesting access tokens.
	 *
	 * The semantics of values in this list are service specific.  If
	 * omitted, an authorization server MAY register a
	 * client with a default set of scopes.
	 */
	scope?: string;

	/**
	 * URL string referencing the client's JSON Web Key (JWK) Set
	 * [RFC7517] document, which contains the client's public keys.  The
	 * value of this field MUST point to a valid JWK Set document.
	 *
	 * These
	 * keys can be used by higher-level protocols that use signing or
	 * encryption.  For instance, these keys might be used by some
	 * applications for validating signed requests made to the token
	 * endpoint when using JWTs for client authentication [RFC7523].
	 *
	 * Use
	 * of this parameter is preferred over the "jwks" parameter, as it
	 * allows for easier key rotation.  The "jwks_uri" and "jwks"
	 * parameters MUST NOT both be present in the same request or
	 * response.
	 */
	jwks_uri?: string;

	/**
	 * Client's JSON Web Key Set [RFC7517] document value, which contains
	 * the client's public keys. The value of this field MUST be a JSON
	 * object containing a valid JWK Set.
	 *
	 * These keys can be used by
	 * higher-level protocols that use signing or encryption.
	 *
	 * This
	 * parameter is intended to be used by clients that cannot use the
	 * "jwks_uri" parameter, such as native clients that cannot host
	 * public URLs. The "jwks_uri" and "jwks" parameters MUST NOT both
	 * be present in the same request or response.
	 */
	jwks?: Record<string, unknown>;

	/**
	 * Human-readable string name of the client to be presented to the
	 * end-user during authorization.
	 *
	 * If omitted, the authorization server MAY display the raw
	 * "client_id" value to the end-user
	 * instead.
	 *
	 * It is RECOMMENDED that clients always send this field.
	 */
	client_name?: string;

	/**
	 * URL string of a web page providing information about the client.
	 * The value of this field
	 * MUST point to a valid web page.
	 *
	 * If present, the server SHOULD display this URL to the end-user in a
	 * clickable fashion.
	 *
	 * It is RECOMMENDED that clients always send this field.
	 */
	client_uri?: string;

	/**
	 * URL string that references a logo for the client. The value of
	 * this field MUST point to a valid image file.
	 *
	 * If present, the server SHOULD display this image to the end-user
	 * during approval.
	 */
	logo_uri?: string;

	/**
	 *  Array of strings representing ways to contact people responsible
	 * for this client, typically email addresses.
	 *
	 * The authorization server MAY make these contact addresses available
	 * to end-users for support requests for the
	 * client.
	 */
	contacts?: string[];

	/**
	 * URL string that points to a human-readable terms of service
	 * document for the client that describes a contractual
	 * relationship between the end-user and the client that the end-user
	 * accepts when
	 * authorizing the client.  The value of this field MUST point to a
	 * valid web page.
	 *
	 * The authorization server SHOULD display this URL to the end-user
	 * if it is provided.
	 */
	tos_uri?: string;

	/**
	 *  URL string that points to a human-readable privacy policy document
	 * that describes how the deployment organization
	 * collects, uses, retains, and discloses personal data. The value of
	 * this field MUST point to a valid web page.
	 *
	 * The authorization server SHOULD display this URL to the end-user
	 * if it is provided.
	 */
	policy_uri?: string;

	/**
	 * Which OAuth versions this client supports. Different versions have
	 * slightly different implementation details.
	 */
	supported_oauth_versions: OAuthVersion[]; // NOTE: not specified by any spec
};

export type OAuthProvider = string;

type OAuthVersion = "2.0" | "2.1";

// The 'plain' literal is considered a security vulnerability and therefore is not supported
export type CodeChallengeMethod = "S256";

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
export type Scope = string;

export type PermissionName = string;
export type Permission = {
	id: string;
	name: PermissionName;
	description: string;
};

export type AuthorizationCodeRecord = {
	id: string;
	code: string;
	expiresAt: number; // seconds
	scope: Scope;
	clientId: string;
	userAgent: string;
	redirectUri: string;
	codeChallenge: string;
	codeChallengeMethod: CodeChallengeMethod;
	isUsed: boolean;
};

export type ClientAccessRecord = {
	id: string;
	clientId: string;
	scope: Scope;
	tokenType: AccessTokenType;
	accessToken: AccessToken;
	accessTokenExpiresAt: number;
} & (
	| {
			refreshToken?: undefined;
			refreshTokenExpiresAt?: undefined;
	  }
	| {
			refreshToken: RefreshToken;
			refreshTokenExpiresAt: number;
	  }
);

/**
 *
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
 *
 * Notes:
 * - `Authorization Servers` and `Resource Servers` **SHOULD** use mechanisms for sender constraining access tokens
 * such as DPoP [RFC 9449], or mTLS [RFC 8705]
 * - It is RECOMMENDED to use end-to-end TLS between the client and the `Resource Server`.
 */
export type AccessTokenType = "limited_scope" | "bearer" | "sender_constrained";

/**
 * A string representing an authorization issued to the client that allows it to access specific protected resources.
 * They are usually JWTs and contain a payload in JSON format. They are short-lived and usually expire after a few
 * minutes.
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
export type AccessToken = string;

export type RefreshToken = string;
