/**
 * Client types are defined based on their ability to authenticate securely with the authorization server:
 * - "confidential"-- clients that have credentials with the authorization server
 * - "public"-- clients without credentials
 *
 * Note: There is no requirement that an authorization server supports a particular client type.
 */
export type ClientType = "confidential" | "public";

export type TokenEndpointAuthMethod = "none" | "client_secret_post" | "client_secret_basic"

// Similar to Better-Auth -> https://github.com/better-auth/better-auth/blob/6f545cad26bd9451c67339cea67fe035e859faa0/packages/oauth-provider/src/types/oauth.ts#L262)
export type OAuthClient = {
	type: ClientType;
	/**
	 * Represents the registration info provided by the client and it is used to identify it in the context of an
	 * authorization server.
	 *
	 * Notes:
	 * - It can be issued by the authorization server itself or by another party.
	 * - It is **NOT** a secret and **MUST NOT** be used alone for client authentication.
	 */
	client_id: string; // TODO: AS should document the size it issues
	/**
	 * The URI of the client that the authorization server redirects the user agent back to after completing its
	 * interaction with the resource owner. Clients using flows with redirection MUST register their redirection URI
	* values.
	 *
	 * Notes:
	 * - The authorization server **MAY** allow the client to register multiple redirect URIs
	 * - A redirect URI **MUST** be an absolute URI
	 * - A redirect URI  **MAY** include a query string component, which **MUST** be retained when adding additional
	 * query parameters
	 * - A redirect URI  **MUST NOT** include a fragment component
	 */
  redirect_uris: string[]; // TODO: enforce absolute URI
  /**
   * String indicator of the requested authentication method for the token endpoint. The values defined by [RFC7591]
   * are:
   *
         *  - "none": The client is a public client as defined in OAuth 2.0,
            Section 2.1, and does not have a client secret.
   *
         *  - "client_secret_post": The client uses the HTTP POST parameters
            as defined in OAuth 2.0, Section 2.3.1.
   *
         *  - "client_secret_basic": The client uses HTTP Basic as defined in
            OAuth 2.0, Section 2.3.1.
   */
  token_endpoint_auth_method: TokenEndpointAuthMethod

  // Not specified by any spec
	/**
	 * Currently, S256 is the only method that does not expose the code verifier in the authorization request. If the
	 * client is capable of using S256, it MUST use it, as S256 is Mandatory To Implement (MTI) on the server.
	 *
	 * Clients are permitted to use plain only if they cannot support S256 for some technical reason,
	 */
	supportsS256: boolean; // defaults to true
	/**
	 * Which OAuth versions this client supports. Different versions have slightly different implementation details.
	 */
	supportedOAuthVersions: OAuthVersion[];
	/**
	 * Which grant types the client is allowed to request from the authorizaztion server and use to obtain tokens.
	 */
	allowedGrantTypes: GrantType[];
};

export type OAuthProvider = string;

type OAuthVersion = "2.0" | "2.1";

export type GrantType = "authorization_code" | "refresh_token" | "client_credentials";

export type CodeChallengeMethod = "plain" | "S256";

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
	code: string;
	scope: string;
	expiresAt: number; // seconds
	clientId: string;
	userAgent: string;
	redirectUri: string;
	codeChallenge: string;
	codeChallengeMethod: CodeChallengeMethod;
	isUsed: boolean;
};

export type ClientAccessRecord = {
	clientId: string;
	scope: Scope;
	providerId: string;
	tokenType: AccessTokenType;
	accessToken: AccessToken;
	accessTokenExpiresAt: number;
} & (
	| {
			refreshToken?: undefined;
			refreshTokenExpiresAt?: undefined;
	  }
	| {
			refreshToken: string;
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
