import * as ErrorCodes from "../../lib/errors/authorization.js";
import type {
	AuthorizationCodeRecord,
	CodeChallengeMethod,
	Permission,
	PermissionName,
} from "../../lib/types.js";

/**
 * Suggestions:
 * - add rate limiting
 */
export const Route = createFileRoute("/authorization-code")({
	beforeLoad: async ({ context, search, location }) => {
		// 1. The user must be authenticated to access this route
		if (!context.auth.isAuthenticated) {
			throw redirect({
				to: "/login",
				// Save current location for redirect after login
				search: { redirect: location.href },
			});
		}

		// After login, the user is redirected back here

		const failure_uri = new URL(search.redirect_uri);
		failure_uri.searchParams.set("iss", AUTHORIZATION_SERVER_ID);

		// 2. Check if this user is allowed to request an authorization code
		if (!canRequestAuthorizationCode(search.client_id)) {
			failure_uri.searchParams.set("error", ErrorCodes.UNAUTHORIZED_CLIENT);
			failure_uri.searchParams.set(
				"error_description",
				"This client is not authorized to request an authorization code",
			);

			throw Route.redirect({ to: failure_uri.toString() });
		}

		// 3. Check if the requested scope is valid
		if (!isValidScope(search.scope)) {
			failure_uri.searchParams.set("error", ErrorCodes.INVALID_SCOPE);
			failure_uri.searchParams.set(
				"error_description",
				"The provided `scope` is not valid",
			);

			throw Route.redirect({ to: failure_uri.toString() });
		}
	},
	component: AuthorizationCodePage,
});

/**
 * Example of successful routing request:
 * ```bash
 * GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
 *     &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
 *     &code_challenge=6fdkQaPm51l13DSukcAH3Mdx7_ntecHYd1vi3n0hMZY
 *     &code_challenge_method=S256 HTTP/1.1
 * Host: server.example.com
 * ```
 */
export default function AuthorizationCodePage() {
	const {
		client_id,
		code_challenge,
		code_challenge_method = "plain",
		redirect_uri,
		scope,
		state,
	} = Route.useSearch();

	const permissions: Permission[] = getPermissions(scope);
	const selectedPermissions = new Set<PermissionName>(
		permissions.map((p) => p.name),
	);

	function togglePermission(permission: PermissionName) {
		if (selectedPermissions.has(permission)) {
			selectedPermissions.delete(permission);
		} else selectedPermissions.add(permission);
	}

	return (
		<div>
			<h2>Authorize Application</h2>

			<AuthorizationForm
				onSubmit={() => {
					// The Resource Owner (user) has granted some permissions

					// 5. Get the granular scope approved by the Resource Owner (user)
					const approvedScope = [...selectedPermissions].join(" ");

					// 6. Generate the authorization code
					const code = generateCode();

					// 7.  Store the code, so that it can be verified when the client requests an access token
					registerAuthorizationCode({
						code,
						scope: approvedScope,
						clientId: client_id,
						redirectUri: redirect_uri,
						codeChallenge: code_challenge,
						codeChallengeMethod: code_challenge_method as CodeChallengeMethod,
						isUsed: false, // only one access token MUST be generated for this code
						expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes from now
					});

					const success_uri = new URL(redirect_uri);
					success_uri.searchParams.set("iss", AUTHORIZATION_SERVER_ID);
					success_uri.searchParams.set("code", code);
					if (state) success_uri.searchParams.set("state", state);

					// 7. Redirect the user agent back to client
					throw Route.redirect({ to: success_uri.toString() });
					/*
					 * For example:
					 * ```http
					 * HTTP/1.1 302 Found
					 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
					 *           &state=xyz&iss=https%3A%2F%2Fauthorization-server.example.com
					 * ```
					 */
				}}
			>
				<ul>
					{permissions.map(({ id, name, description }) => (
						// 4. Present the requested permissions to the Resource Owner (user) and allow granular approval
						<li key={id}>
							<Checkbox
								label={name}
								description={description}
								checked={selectedPermissions.has(name)}
								onChange={togglePermission}
							/>
						</li>
					))}
				</ul>

				<button
					type="button"
					onClick={() => {
						// The Resource Owner (user) denies all permissions
						const failure_uri = new URL(redirect_uri);
						failure_uri.searchParams.set("iss", AUTHORIZATION_SERVER_ID);

						failure_uri.searchParams.set("error", ErrorCodes.ACCESS_DENIED);
						failure_uri.searchParams.set(
							"error_description",
							"The resource owner has denied the authorization code request",
						);

						throw Route.redirect({ to: failure_uri.toString() });
					}}
				>
					Deny
				</button>

				<button type="submit">Approve</button>
			</AuthorizationForm>
		</div>
	);
}

// UI Mock
function AuthorizationForm(_props: Record<string, unknown>) {
	return <div />;
}

function Checkbox(_props: Record<string, unknown>) {
	return <div />;
}

// Functionality Mock
const AUTHORIZATION_SERVER_ID = "https://auth.example.com";

function generateCode(): string {
	// bound to the client_id, code_challenge, and redirect_uri.
	// The code_challenge and code_challenge_method values may be stored in encrypted form in the code itself
	return "secure_code";
}

function registerAuthorizationCode(_record: AuthorizationCodeRecord): void {
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

function isValidScope(_scope: string | undefined): boolean {
	return true;
}

function canRequestAuthorizationCode(_clientId: string): boolean {
	return true;
}

function getPermissions(_scope: string): Permission[] {
	return [];
}

// TanStack Start Mock
type BeforeLoadArgs = {
	context: {
		auth: {
			isAuthenticated: false;
		};
	};
	search: {
		redirect_uri: string;
		client_id: string;
		scope: string;
	};
	location: {
		href: string;
	};
};

function createFileRoute(path: string) {
	return (options: {
		beforeLoad?: (args: BeforeLoadArgs) => unknown | Promise<unknown>;
		component: unknown;
	}) => ({
		path,
		...options,
		useSearch() {
			return {
				response_type: "code",
				client_id: "s6BhdRkqt3",
				code_challenge: "6fdkQaPm51l13DSukcAH3Mdx7_ntecHYd1vi3n0hMZY",
				code_challenge_method: "S256",
				redirect_uri: "https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb",
				scope: "read",
				state: "xyz",
			};
		},
		redirect(..._args: unknown[]) {},
	});
}

function redirect(..._args: unknown[]) {}
