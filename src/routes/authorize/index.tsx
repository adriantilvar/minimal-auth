import { createFileRoute, redirect } from "@tanstack/react-router";
import { createClientOnlyFn, createMiddleware } from "@tanstack/react-start";
import type { ComponentProps } from "react";
import { AuthorizationErrorCodes } from "@/lib/errors/oauth";
import type {
	AuthorizationCodeRecord,
	CodeChallengeMethod,
	OAuthClient,
	Permission,
	PermissionName,
	Scope,
} from "@/lib/types";
import { isString } from "@/lib/utils";

// NOTE: The fragment component is stripped by the server, but it should also be enforced by client
const authorizationRequestValidation = createMiddleware().server(async ({ next, request }) => {
	const search = new URL(request.url).searchParams; // search params are always strings

	/**
	 * If the `client_id` is missing or invalid (no client with that id exists), we
	 * cannot validate the `redirect_uri`. We must inform the Resource Owner of the
	 * error, but we cannot redirect the user-agent to an untrusted redirect URI.
	 *
	 * The OAuth spec does not mandate how the Resource Owner should be informed in
	 * this case, so the implementation is up to the Authorization Server. In our
	 * case, we redirect the user-agent to an error page that we host.
	 */

	const [clientId] = getUniqueSearchParam(search, "client_id");
	if (!clientId) {
		throw redirect({
			href: createUrl(ERROR_ENDPOINT, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description:
						"Request URI must include a `client_id` query parameter. It must not be included more than once.",
				},
			}).toString(),
		});
	}

	const client = await findOAuthClientById(clientId);
	if (!client) {
		throw redirect({
			href: createUrl(ERROR_ENDPOINT, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description:
						"No client is registered with the provided `client_id`. You need to register the client before requesting an authorization grant.",
				},
			}).toString(),
		});
	}

	const [redirectUri] = getUniqueSearchParam(search, "redirect_uri");
	if (!redirectUri) {
		// NOTE: Can allow the client to omit `redirect_uri` if it has only one redirect URI registered with the AS
		throw redirect({
			href: createUrl(ERROR_ENDPOINT, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description:
						"The request URI must include a `redirect_uri` query parameter. It must not be included more than once.",
				},
			}).toString(),
		});
	}

	if (!isValidRedirectUri(redirectUri, client)) {
		throw redirect({
			href: createUrl(ERROR_ENDPOINT, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description:
						"The provided redirect URI is not registered for this client or is otherwise invalid.",
				},
			}).toString(),
		});
	}

	// The client must have passed a valid `redirect_uri`, or the client has only one registered redirect URI
	const safeRedirectUri = redirectUri ?? client.redirect_uris[0];

	/**
	 * Once we have a validated redirect URI, we can inform the client of any error by
	 * redirecting the user-agent to the redirect URI with the relevant error query
	 * parameters (specified by the OAuth spec).
	 */

	const [state, stateError] = getUniqueSearchParam(search, "response_type");
	if (stateError?.reason === "duplicate_param") {
		throw redirect({
			href: createUrl(safeRedirectUri, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description:
						"The `state` query parameter is optional. However, if provided, it must not be included more than once.",
					iss: AUTHORIZATION_SERVER_ID,
				},
			}).toString(),
		});
	}

	const [responseType] = getUniqueSearchParam(search, "response_type");
	if (!responseType) {
		throw redirect({
			href: createUrl(safeRedirectUri, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description:
						"Request URI must include a `response_type` query parameter. It must not be included more than once.",
					// An error_uri can be added as well
					iss: AUTHORIZATION_SERVER_ID,
					state,
				},
			}).toString(),
		});
	}

	if (responseType !== "code") {
		throw redirect({
			href: createUrl(safeRedirectUri, {
				query: {
					error: AuthorizationErrorCodes.UNSUPPORTED_RESPONSE_TYPE,
					error_description:
						"This server can only provide authorization code grants. If you wish to obtain an authorization code, you must set the value of the `response_type` parameter to 'code'.",
					// An error_uri can be added as well
					iss: AUTHORIZATION_SERVER_ID,
					state,
				},
			}).toString(),
		});
	}

	const [codeChallenge] = getUniqueSearchParam(search, "code_challenge");
	if (!codeChallenge) {
		throw redirect({
			href: createUrl(safeRedirectUri, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description:
						"Request URI must include a `code_challenge` query parameter. It must not be included more than once.",
					iss: AUTHORIZATION_SERVER_ID,
					state,
				},
			}).toString(),
		});
	}

	const [codeChallengeMethod] = getUniqueSearchParam(search, "code_challenge_method");
	if (!codeChallengeMethod) {
		throw redirect({
			href: createUrl(safeRedirectUri, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description:
						"Request URI must include a `code_challenge_method` query parameter. It must not be included more than once.",
					iss: AUTHORIZATION_SERVER_ID,
					state,
				},
			}).toString(),
		});
	}

	if (!isValidCodeChallengeMethod(codeChallengeMethod)) {
		throw redirect({
			href: createUrl(safeRedirectUri, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description: "The provided `code_challenge_method` is not valid.",
					iss: AUTHORIZATION_SERVER_ID,
					state,
				},
			}).toString(),
		});
	}

	if (!canRequestAuthorizationCodeGrant(client)) {
		throw redirect({
			href: createUrl(safeRedirectUri, {
				query: {
					error: AuthorizationErrorCodes.UNAUTHORIZED_CLIENT,
					error_description: "This client is not allowed to request an authorization code grant.",
					iss: AUTHORIZATION_SERVER_ID,
					state,
				},
			}).toString(),
		});
	}

	const [scope, error] = getUniqueSearchParam(search, "scope");
	if (error?.reason === "duplicate_param") {
		throw redirect({
			href: createUrl(safeRedirectUri, {
				query: {
					error: AuthorizationErrorCodes.INVALID_REQUEST,
					error_description:
						"The `scope` query parameter is optional. However, if provided, it must not be included more than once.",
					iss: AUTHORIZATION_SERVER_ID,
					state,
				},
			}).toString(),
		});
	}

	// NOTE: The Authorization Server can ignore the scope entirely
	if (scope && !isValidScope(scope)) {
		throw redirect({
			href: createUrl(safeRedirectUri, {
				query: {
					error: AuthorizationErrorCodes.INVALID_SCOPE,
					error_description: "The provided `scope` is not valid",
					iss: AUTHORIZATION_SERVER_ID,
					state,
				},
			}).toString(),
		});
	}

	// At this point we can start the authorization code grant flow
	return next();
});

/**
 * Notes:
 * - We enforce PKCE is across all clients to bolster security.
 */
type AuthorizationRouteParams = {
	client_id: string;
	redirect_uri: string;
	response_type: "code";
	code_challenge: string;
	code_challenge_method: CodeChallengeMethod;
	scope?: Scope;
	state?: string;
};

export const Route = createFileRoute("/authorize/")({
	server: {
		// 1. We run the client validation middleware before the request gets routed
		handlers: ({ createHandlers }) =>
			createHandlers({ GET: { middleware: [authorizationRequestValidation] } }),
	},
	// We already validated the request, but we do a type-check so we can safely work with the search params
	validateSearch: (search: Record<string, unknown>): AuthorizationRouteParams => {
		const { client_id, redirect_uri, response_type, code_challenge, code_challenge_method, scope, state } =
			search;

		if (!isString(client_id)) throw new Error("The `client_id` parameter must be a string.");
		if (!isString(redirect_uri)) throw new Error("The `redirect_uri` parameter must be a string.");
		if (response_type !== "code") throw new Error("The `response_type` parameter must be 'code'");
		if (!isString(code_challenge)) throw new Error("The `code_challenge` parameter must be a string.");
		if (!isString(code_challenge_method) || code_challenge_method.toLowerCase() !== "s256") {
			throw new Error("The `code_challenge_method` parameter must be 'S256'");
		}
		if (state && !isString(state)) throw new Error("The `state` parameter must be a string.");

		return {
			client_id,
			redirect_uri,
			response_type,
			code_challenge,
			code_challenge_method: "S256",
			scope: (scope as string) ?? undefined,
			state: (state as string) ?? undefined,
		};
	},
	beforeLoad: ({ context, location }) => {
		// 2. The user must be authenticated to access this route
		if (!isUserAuthenticated(context)) {
			throw redirect({
				to: "/login",
				search: { redirect: location.href }, // Save current location for redirect after login
			});
		}
	},
	// After login, the user is redirected back and the AuthorizationPage gets rendered
	component: AuthorizationPage,
});

function AuthorizationPage() {
	const {
		client_id,
		code_challenge,
		code_challenge_method,
		redirect_uri,
		scope = DEFAULT_SCOPE,
		state,
	} = Route.useSearch();
	const permissions: Permission[] = getPermissions(scope);
	const selectedPermissions = new Set<PermissionName>(permissions.map((p) => p.name));

	function togglePermission(permission: PermissionName) {
		if (selectedPermissions.has(permission)) {
			selectedPermissions.delete(permission);
		} else selectedPermissions.add(permission);
	}

	function denyAuthorizationRequest() {
		externalRedirect(
			createUrl(redirect_uri, {
				query: {
					error: AuthorizationErrorCodes.ACCESS_DENIED,
					error_description: "The resource owner has denied the authorization code request",
					iss: AUTHORIZATION_SERVER_ID,
					state,
				},
			}).toString(),
		);
	}

	async function approveAuthorizationRequest(e: React.SubmitEvent<HTMLFormElement>) {
		e.preventDefault();

		// Get the granular scope approved by the Resource Owner (user)
		const approvedScope = [...selectedPermissions].join(" ");

		// Generate the authorization code
		const code = generateCode();

		// Store the code, so that it can be verified when the client requests an access token
		await registerAuthorizationCode({
			code,
			scope: approvedScope,
			clientId: client_id,
			redirectUri: redirect_uri,
			codeChallenge: code_challenge,
			codeChallengeMethod: code_challenge_method as CodeChallengeMethod,
			userAgent: getUserAgent(),
			isUsed: false,
			expiresAt: Date.now() + DEFAULT_AUTHORIZATION_CODE_EXPIRATION_S,
		});

		// Success! Redirect the user-agent to the client redirect URI
		externalRedirect(
			createUrl(redirect_uri, {
				query: {
					code,
					state,
					iss: AUTHORIZATION_SERVER_ID,
				},
			}).toString(),
		);
	}

	return (
		<div>
			<h2>Authorize Application</h2>

			<AuthorizationForm onSubmit={approveAuthorizationRequest}>
				<ul>
					{permissions.map(({ id, name, description }) => (
						// 3. Present the requested permissions to the Resource Owner (user) and allow granular approval
						<li key={id}>
							<Checkbox
								label={name}
								description={description}
								checked={selectedPermissions.has(name)}
								onChange={() => togglePermission(name)}
							/>
						</li>
					))}
				</ul>

				<button
					// 4. The Resource Owner (user) denies all permissions
					type="button"
					onClick={denyAuthorizationRequest}
				>
					Deny
				</button>

				<button
					// 4. The Resource Owner (user) has granted some permissions
					type="submit"
				>
					Approve
				</button>
			</AuthorizationForm>
		</div>
	);
}

// Mocked UI
function AuthorizationForm(props: ComponentProps<"form">) {
	return <form {...props} />;
}

function Checkbox(props: ComponentProps<"input"> & { label?: string; description?: string }) {
	return <input type="checkbox" {...props} />;
}

// Utilities
const ERROR_ENDPOINT = "/error/authorization-failure";
const AUTHORIZATION_SERVER_ID = "https://authorization.unit.com";
const DEFAULT_SCOPE = "read";
const DEFAULT_AUTHORIZATION_CODE_EXPIRATION_S = 10 * 60 * 1000; // 10 minutes from now

type Maybe<T> = T | null | undefined;

function createUrl(base: string, opt: { query: Record<string, Maybe<string>> }) {
	const url = new URL(base);
	Object.entries(opt.query).forEach(([key, value]) => {
		if (value !== undefined && value !== null) url.searchParams.set(key, value);
	});

	return url;
}

const externalRedirect = createClientOnlyFn((uri: string) => {
	window.location.href = uri;
});

function getUniqueSearchParam(search: URLSearchParams, paramName: string) {
	const param = search.getAll(paramName);

	if (!param || !Array.isArray(param)) return [undefined, { reason: "missing_param" }] as const;
	if (param.length > 1) return [undefined, { reason: "duplicate_param" }] as const;

	return [param[0], null] as const;
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

function isValidScope(_scope: string | undefined): boolean {
	return true;
}

function canRequestAuthorizationCodeGrant(_client: OAuthClient): boolean {
	return true;
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

function isValidCodeChallengeMethod(method: unknown): method is CodeChallengeMethod {
	return typeof method === "string" && method.toUpperCase() === "S256";
}

function isUserAuthenticated(_context: unknown): boolean {
	return true;
}

function getPermissions(_scope: string): Permission[] {
	return [];
}

function getUserAgent() {
	return "some chromium";
}

function generateCode(): string {
	/**
	 * The authorization code must be bound to the `client_id`, `code_challenge`, and `redirect_uri`.
	 * The `code_challenge` and `code_challenge_method` values may be stored in encrypted form in the code itself.
	 */
	return "secure_code";
}

async function registerAuthorizationCode(_record: AuthorizationCodeRecord): Promise<void> {
	/**
	 * Authorization Server MUST bind the authorization code to the client_id, code_challenge, code_challenge_method, and
	 * redirect_uri
	 *
	 * Because the Authorization Server will not include the scope aggreed upon by the Resource Owner, we bind it to the
	 * authorization code registrtion, and we inform the client at the moment the access token is issued
	 *
	 * The code_challenge and code_challenge_method values may be stored in encrypted form in the code
	 *
	 * The info should be stored (KV/DB), so that the code challenge can be verified later, when the client requests token
	 *
	 */
}
