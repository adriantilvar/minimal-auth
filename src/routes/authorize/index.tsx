import { createFileRoute, redirect, useRouter } from "@tanstack/react-router";
import { createMiddleware } from "@tanstack/react-start";
import { AuthorizationErrorCodes } from "@/lib/errors/oauth";
import type { CodeChallengeMethod, OAuthClient } from "@/lib/types";

/**
 * Notes:
 * - We enforce PKCE is across all clients—even confidential ones—to
 * bolster security.
 */

type AuthorizationRouteParams = {
	client_id: string;
	redirect_uri: string;
	response_type: "code";
	code_challenge: string;
	code_challenge_method: CodeChallengeMethod;
};

/**
 * If the request fails due to a missing, invalid, or mismatching redirection URI,
 * or if the client identifier is missing or invalid, the Authorization Server
 * SHOULD inform the Resource Owner of the error and MUST NOT automatically
 * redirect the user-agent to the invalid redirection URI.
 */

const clientValidationMiddleware = createMiddleware().server(async ({ next, request }) => {
	const search = new URL(request.url).searchParams; // search params are always strings

	const clientId = getUniqueSearchParam(search, "client_id");
	if (!clientId) {
		// We can't redirect the client to the provided redirect_uri, so we inform them of the error another way
		return redirect({
			to: ERROR_ENDPOINT,
			search: {
				error: AuthorizationErrorCodes.INVALID_REQUEST,
				error_description:
					"Request URI must include a `client_id` query parameter. It must not be included more than once.",
			},
		});
	}

	const client = await findOAuthClientById(clientId);
	if (!client) {
		return redirect({
			to: ERROR_ENDPOINT,
			search: {
				error: AuthorizationErrorCodes.INVALID_REQUEST,
				error_description:
					"No client is registered with the provided `client_id`. You need to register the client before requesting an authorization grant.",
			},
		});
	}

	const redirectUri = getUniqueSearchParam(search, "redirect_uri");
	if (client.redirectUris.length > 1 && !redirectUri) {
		return redirect({
			to: ERROR_ENDPOINT,
			search: {
				error: AuthorizationErrorCodes.INVALID_REQUEST,
				error_description:
					"The request URI must include a `redirect_uri` query parameter, because the client has multiple redirect URIs registered with the server. It must not be included more than once.",
			},
		});
	}

	if (redirectUri && !isValidRedirectUri(redirectUri, client)) {
		return redirect({
			to: ERROR_ENDPOINT,
			search: {
				error: AuthorizationErrorCodes.INVALID_REQUEST,
				error_description:
					"The provided redirect URI is not registered for this client or is otherwise invalid.",
			},
		});
	}

	// The client must have passed a valid `redirect_uri`, or the client has only one registered redirect URI
	const safeRedirectUri = redirectUri ?? client.redirectUris[0];

	// At this point we can safely redirect the client to the provided redirect URI
	return next({
		context: {
			redirectUri: safeRedirectUri, // adding it just in case it's missing
		},
	});
});

export const Route = createFileRoute("/authorize/")({
	server: {
		handlers: ({ createHandlers }) => createHandlers({ GET: { middleware: [clientValidationMiddleware] } }),
	},
	// NOTE: Duplicate search params are not allowed. You should ensure that-- it's skipped here for brevity.
	validateSearch: (search: Record<string, unknown>): AuthorizationRouteParams => {
		const { client_id, redirect_uri, response_type, code_challenge, code_challenge_method } = search;
		/**
		 * If the Resource Owner denies the access request or if the request fails for
		 * reasons other than a missing or invalid redirection URI, the Authorization
		 * Server informs the client by redirecting the user-agent to the provided
		 * redirection URI including the relevant error parameters
		 */

		if (!response_type) {
			throw new Error(
				"Request URI must include a `response_type` query parameter. It must not be included more than once.",
			);
		}

		if (response_type !== "code") {
			throw new Response(JSON.stringify({ error: "invalid_request" }), {
				status: 400,
				headers: {
					"Content-Type": "application/json",
				},
			});
			// throw new Error("This server can only provide authorization code grants. If you wish to obtain an authorization code, you must set the value of the `response_type` parameter to 'code'.")
		}

		if (!code_challenge) {
			throw new Error(
				"Request URI must include a `code_challenge` query parameter. It must not be included more than once.",
			);
		}

		if (typeof code_challenge !== "string") {
			throw new Error("The `code_challenge` parameter must be a string.");
		}

		if (!code_challenge_method) {
			throw new Error(
				"Request URI must include a `code_challenge_method` query parameter. It must not be included more than once.",
			);
		}

		if (!isValidCodeChallengeMethod(code_challenge_method)) {
			throw new Error(
				"The provided `code_challenge_method` is not valid. For the time being, this server supports only 'S256'.",
			);
		}

		// The search params are validated, so we return them with type-safety
		return {
			client_id: client_id as string, // validated before in clientValidationMiddleware
			redirect_uri: redirect_uri as string, // validated before in clientValidationMiddleware
			response_type,
			code_challenge,
			code_challenge_method,
		};
	},
	// If `validateSearch` throws and error, `errorComponent` will be rendered instead of `component`
	errorComponent: ({ error }) => {
		// 2. Here we can handle the search param error however we'd like
		const router = useRouter();

		return (
			<main className="error">
				<h2>Invalid Authorization Request</h2>
				<p>{error.message}</p>
				<button
					type="button"
					// onClick={() => router.navigate({ to: "/invalid-authorization-request" })}
				>
					Read more
				</button>
			</main>
		);
	},
	component: RouteComponent,
});

function RouteComponent() {
	const { response_type } = Route.useSearch();

	return (
		<main>
			Hello "/authorize/"!
			<div>
				Here's your param list:
				<ul>
					<li>response_type={response_type}</li>
				</ul>
			</div>
		</main>
	);
}

// Utilities
const ERROR_ENDPOINT = "/authorization-failure";

function getUniqueSearchParam(search: URLSearchParams, paramName: string): string | null {
	const param = search.getAll(paramName);

	return Array.isArray(param) && param.length === 1 ? param[0] : null;
}

async function findOAuthClientById(_clientId: string): Promise<OAuthClient | null> {
	return {
		type: "confidential",
		clientId: "4u0rfoisdjflsj",
		redirectUris: ["localhost:3000/cb1"],
		supportsS256: true,
		allowedGrantTypes: ["authorization_code"],
		supportedOAuthVersions: ["2.0", "2.1"],
	};
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

	return client.redirectUris.includes(uri);
}

function isValidCodeChallengeMethod(method: unknown): method is CodeChallengeMethod {
	return typeof method === "string" && method.toUpperCase() === "S256";
}
