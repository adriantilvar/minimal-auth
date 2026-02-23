import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/")({ component: App });

function App() {
	return (
		<main className="max-w-3xl mx-auto mt-[20%]">
      <h1 className="font-semibold text-2xl text-center">Minimal Auth</h1>
      <p className="bg-olive-300 text-lg pl-2 mt-4 text-center">A study implemenation of OAuth 2.1 and OIDC</p>
		</main>
	);
}
