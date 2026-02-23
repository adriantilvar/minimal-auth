import type { OAuthClient, Scope } from "../lib/types.js";

/**
 * Authorization Code Grant flow function
 *
 * An authorization code is a temporary credential used by the
 * client to obtain an access token and optionally a refresh token.
 *
 * To initiate the flow, the client constructs a URL to the
 * Authorization Server’s /authorize endpoint, then directs the
 * Resource Owner's user agent to it.
 *
 * Notes:
 * The Authorization Server MUST support the use of the HTTP GET method (Section 9.3.1 of [RFC9110]) for the
 * authorization endpoint and MAY support the POST method (Section 9.3.3 of [RFC9110]) as well.
 *
 * The /authorization endpoint URL MUST NOT include a fragment component. It MAY include a query string component,
 * which MUST be retained when adding additional query parameters.
 *
 * An Authorization Server that redirects a request potentially containing user credentials MUST avoid forwarding
 * these user credentials accidentally (see Section 7.5.4 for details).
 *
 * Cross-Origin Resource Sharing [WHATWG.CORS] MUST NOT be supported at the /authorization endpoint, as the client
 * does not access this endpoint directly. Instead, the client redirects the user agent to it.
 */
export const getServerTime = createServerFn({ method: "GET" }).handler(async () => {
	// This runs only on the server
});

export async function initiateOAuthAuthorizationCodeGrantFlow({
	clientId,
	redirectUri,
	scope,
	state,
}: {
	clientId: string;
	redirectUri?: string;
	scope?: Scope;
	state?: string;
}) {
	const client = await findOAuthClientById(clientId);
	// The client must be registered with the Authorization Server before initiating the protocol
	if (!client) {
		throw new Error(
			"No client with the provided `client_id` is registered. You need to register the client with the authorization server before starting an authorization code grant flow.",
		);
	}

	// The client may omit a redirect URI only if there is only one redirect URI registered with the authorization server
	if (client.redirectUris.length > 1 && !redirectUri) {
		throw new Error(
			"You must provide a `redirectUri`, because the client has multiple redirect URIs registered with the authorization server.",
		);
	}

	if (redirectUri && !isValidRedirectUri(redirectUri)) {
		throw new Error("The provided `redirectUri` is invalid");
	}

	const codeVerifier = generateCodeVerifier();
	await saveCodeVerifier(codeVerifier); // Error handling omitted for brevity

	const codeChallenge = generateCodeChallenge(codeVerifier);

	// Constructing the authorization URL
	const authorization_uri = new URL("/authorize");
	authorization_uri.searchParams.set("response_type", "code");
	authorization_uri.searchParams.set("client_id", clientId);
	authorization_uri.searchParams.set("code_challenge", codeChallenge);
	authorization_uri.searchParams.set("code_challenge_method", "S256"); // Currently only supported method by OAuth 2.1
	authorization_uri.searchParams.set("redirect_uri", redirectUri ?? client.redirectUris[0]);

	// The state and scope parameters SHOULD NOT include sensitive client or Resource Owner
	// information in plain text, as they can be transmitted over insecure channels or stored insecurely.
	if (scope) authorization_uri.searchParams.set("scope", scope);
	if (state) authorization_uri.searchParams.set("state", state);

	return redirect(authorization_uri.toString());
}

async function findOAuthClientById(_clientId: string): Promise<OAuthClient | null> {
	return null;
}

function isValidRedirectUri(_redirectUri: string): boolean {
	return false;
}

/**
 * Clients use a unique secret, called a code verifier, per authorization
 * request to protect against authorization code injection and CSRF attacks.
 *
 * The client generates the code verifier to store it temporarily, then
 * derives the code challenge to include it in the authorization request.
 *
 * The client uses the code verifier when exchanging the authorization
 * code at a /token endpoint to prove that it is the same client that
 * requested the authorization code.
 *
 */
function generateCodeVerifier() {
	/**
	 * The code verifier is a unique high-entropy cryptographically random
	 * string generated for each authorization request, using the unreserved
	 * characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~", with a
	 * minimum length of 43 characters and a maximum length of 128 characters.
	 */
	return "code_verifier";
}

async function saveCodeVerifier(_codeVerifier: string) {}

/**
 * The client creates a code challenge derived from the code verifier
 * by applying an 'S256' transformation to the code verifier.
 *
 * Currently, S256 is the only method that does not expose the code
 * verifier in the authorization request. S256 is Mandatory To Implement
 * (MTI) on the server, so if the client is capable of using S256, it
 * MUST use it.
 *
 * Clients are permitted to use plain only if they cannot support S256
 * for some technical reason.
 */
function generateCodeChallenge(_codeVerifier: string) {
	/**
	 * It is RECOMMENDED that the output of a suitable random number
	 * generator be used to create a 32-octet sequence. The octet sequence is
	 * then base64url-encoded to produce a 43-octet URL-safe string to use as
	 * the code verifier.
	 */
	return "code_challenge";
}

function redirect(url: string) {}

// TanStack Start mock
function createServerFn(_opt: { method: "GET" }) {
	return {
		handler: (_fn: () => Promise<void>) => {},
	};
}
