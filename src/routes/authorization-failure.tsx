import { createFileRoute } from "@tanstack/react-router";
import type { AuthorizationErrorCode, TokenErrorCode } from "@/lib/errors/oauth";
import type { OAuthProvider } from "@/lib/types";

type OAuthErrorParams = {
	error: AuthorizationErrorCode | TokenErrorCode;
	/**
	 * Human-readable ASCII text providing additional information, used to assist
	 * the client developer in understanding the error that occurred.
	 *
	 * Note: **MUST NOT** include characters outside the set %x20-21 / %x23-5B / %x5D-7E
	 */
	error_description?: string;
	/**
	 * A URI identifying a human-readable web page, used to provide the client
	 * developer with additional information about the error.
	 *
	 * Note: **MUST NOT** include characters outside the set %x21 / %x23-5B / %x5D-7E.
	 */
	error_uri?: string;
	/**
	 * The exact value received from the client. It is required if a state parameter
	 * was present in the client authorization request.
	 */
	state?: unknown;
	/**
	 * The identifier of the Authorization Server.
	 */
	iss?: OAuthProvider;
};

export const Route = createFileRoute("/authorization-failure")({
	validateSearch: (search: Record<string, unknown>): OAuthErrorParams => {
		return {
			error: search.error,
			error_description: search.error_description,
		}
	},
	component: RouteComponent,
});

function RouteComponent() {
	const { error, error_description } = Route.useSearch();

	return (
		<main className="error">
			<h2>Invalid Authorization Request</h2>
			<p>{error_description}</p>
			<button
				type="button"
				// onClick={() => router.navigate({ to: "/invalid-authorization-request" })}
			>
				Read more
			</button>
		</main>
	)
}
