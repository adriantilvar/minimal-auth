import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/error/authorization-failure")({
	component: RouteComponent,
});

function RouteComponent() {
	return (
		<main className="error">
			<h2>Invalid Authorization Request</h2>
			<p>Something went wrong while trying to authorize the client. Please restart the authorization flow.</p>
			<button type="button">Read more</button>
		</main>
	);
}
