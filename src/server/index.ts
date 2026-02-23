import { Hono } from "hono";
import authorization from "./authorization.js";
import token from "./token.js";

const app = new Hono();

app.get("/", (c) => {
	return c.html(
		<html lang="en">
			<head>
				<meta charset="utf-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1" />
				<title>Minimal Auth</title>
				<link rel="preconnect" href="https://fonts.googleapis.com" />
				<link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
				<link
					href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
					rel="stylesheet"
				/>
				<style>{`
					*, *::before, *::after {
						margin: 0;
						padding: 0;
						box-sizing: border-box;
					}

					body {
						font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
						background-color: #09090b;
						color: #fafafa;
						min-height: 100vh;
						display: flex;
						align-items: center;
						justify-content: center;
						-webkit-font-smoothing: antialiased;
						-moz-osx-font-smoothing: grayscale;
					}

					main {
						max-width: 40rem;
						padding: 2rem;
						text-align: center;
					}

					h1 {
						font-size: 2.5rem;
						font-weight: 700;
						letter-spacing: -0.025em;
						line-height: 1.2;
						color: #fafafa;
					}

					p {
						margin-top: 1.25rem;
						font-size: 1.125rem;
						line-height: 1.6;
						color: #a1a1aa;
					}
				`}</style>
			</head>
			<body>
				<main>
					<h1>Minimal Auth</h1>
					<p>
						A lightweight OAuth 2.0 authorization server built with Hono. Implements the authorization code grant
						with PKCE, providing secure and standards-compliant authentication for your applications.
					</p>
				</main>
			</body>
		</html>,
	);
});

app.route("/token", token);
app.route("/authorization", authorization);

export default app;
