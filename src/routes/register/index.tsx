import { createFileRoute } from "@tanstack/react-router";
import { getRequestHeader } from "@tanstack/react-start/server";
import { BAD_REQUEST } from "@/lib/const/http-response-status";

/**
 * Current implementation does not require authorization (no initial access token in the request)
 */
export const Route = createFileRoute("/register/")({
	server: {
		handlers: {
			POST: async ({ request }) => {
				if (!isSecureConnection(request.url)) {
					return Response.json(
						{
							error: "invalid_request",
							error_description: "The request must be made over HTTPS.",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				const contentType = getRequestHeader("Content-Type");
				if (!contentType) {
					// Automatically sets the Content-Type header to `application/json` and serializes the JSON object
					return Response.json(
						{
							error: "invalid_request",
							error_description: "The request must include `Content-Type` header",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				const [mediaType, encoding] = contentType.split("; ");

				if (mediaType !== "application/json") {
					return Response.json(
						{
							error: "invalid_request",
							error_description: "The request must use `application/json` media type.",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				// If not provided, we assume UTF-8; if another encoding is provided, we reject the request
				if (encoding && encoding.toLowerCase() !== "charset=utf-8") {
					return Response.json(
						{
							error: "invalid_request",
							error_description: "The request must use UTF-8 character encoding.",
						},
						{ status: BAD_REQUEST.code },
					);
				}
			},
		},
	},
});

function isSecureConnection(url: string) {
	/**
	 * This is for illustration purposes-only. In production environment, HTTPS should be enforced at the host level
	 */
	return url.includes("localhost") || url.startsWith("https://");
}
