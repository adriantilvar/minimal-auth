import { Hono } from "hono";
import authorization from "./authorization/route.js";
import token from "./token/route.js";

const app = new Hono();

app.get("/", (c) => {
	return c.text(
		"Hello Hono!\n\nTo learn more about Hono on Vercel, visit https://vercel.com/docs/frameworks/backend/hono",
	);
});

app.route("/token", token);
app.route("/authorization", authorization);

export default app;
