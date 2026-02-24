import { createFileRoute } from "@tanstack/react-router";
import { getRequestHeader } from "@tanstack/react-start/server";
import { TokenErrorCodes } from "@/lib/errors/oauth";
import { BAD_REQUEST } from "@/lib/http/response-status-codes";
import type { GrantType } from "@/lib/types";

/**
 * Before initiating the protocol, the client must have established an
 * identifier at the Authorization Server.
 */

// NOTE: The fragment component is stripped by the server, but it should also be enforced by client
export const Route = createFileRoute("/token/")({
	server: {
		handlers: {
			POST: async ({ request }) => {
				const contentType = getRequestHeader("Content-Type");
				if (!contentType) {
					// Automatically sets the Content-Type header to `application/json` and serializes the JSON object
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_REQUEST,
							error_description: "Request must include `Content-Type` header",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				const [mediaType, encoding] = contentType.split("; ");

				if (mediaType !== "application/x-www-form-urlencoded") {
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_REQUEST,
							error_description: "Request must use `application/x-www-form-urlencoded` media type.",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				// If not provided, we assume UTF-8; if another encoding is provided, we reject the request
				if (encoding && encoding.toLowerCase() !== "charset=utf-8") {
					return Response.json(
						{
							error: TokenErrorCodes.INVALID_REQUEST,
							error_description: "Request must use UTF-8 character encoding.",
						},
						{ status: BAD_REQUEST.code },
					);
				}

				const body = await request.formData();

				const [grantType] = getUniqueField(body, "grant_type");
				if (!grantType) {
					return Response.json({
						error: TokenErrorCodes.INVALID_REQUEST,
						error_description:
							"Request URI must include a `grant_type` parameter. It must not be included more than once.",
					});
				}

				if (!isValidGrantType(grantType)) {
					return Response.json({
						error: TokenErrorCodes.UNSUPPORTED_GRANT_TYPE,
						error_description: `The '${grantType}' grant type is not a supported.`,
					});
				}

				/**
				 * TODO: Confidential clients MUST authenticate with the Authorization Server
				 *
				 * It is RECOMMENDED to use asymmetric (public-key based) methods for client authentication, such as mTLS [RFC8705] * or using signed JWTs in accordance with [RFC7521], [RFC7523], and their update [I-D.ietf-oauth-rfc7523bis]
				 * (defined in [OpenID] as the client authentication method private_key_jwt).
				 */

				// So, I need to know whether this is a public or confidential client. How?
				// 1. I request the client_id and check the type
				// 2. I provide separate endpoints for public/confidential clients

				/**
				 * TODO: Public clients MUST provide `client_id` and some form of authentication should be enforced
				 * 	if (!client_id) {
				 *  	return ctx.json<ErrorResponse>(
				 *  		{
				 *  			error: TokenErrorCodes.INVALID_REQUEST,
				 *  			error_description: "Request contain the `client_id` parameter",
				 *  		},
				 *  		400,
				 *  	);
				 *  }
				 *
				 *  if (!isString(client_id)) {
				 *  	return ctx.json<ErrorResponse>(
				 *  		{
				 *  			error: TokenErrorCodes.INVALID_REQUEST,
				 *  			error_description: "The value of `client_id` must be a string",
				 *  		},
				 *  		400,
				 *  	);
				 *  }
				 */

				// We strictly require the `client_id` because we want to know if the client is public or confidential
				const [clientId] = getUniqueField(body, "client_id");
				if (!clientId) {
					return Response.json({
						error: TokenErrorCodes.INVALID_REQUEST,
						error_description:
							"Request URI must include a `client_id` parameter. It must not be included more than once.",
					});
				}

				// This grant type represents access on behalf of an end-user
				if (grantType === "authorization_code") {
				}

				// This grant type represents access on behalf of the client itself
				if (grantType === "client_credentials") {
					return Response.json({
						error: "server_error",
						error_description: "Functionality is not yet implemented",
					});
				}

				if (grantType === "refresh_token") {
					return Response.json({
						error: "server_error",
						error_description: "Functionality is not yet implemented",
					});
				}

				// The request should never get here, but in case it does, we handle it
				return Response.json({
					error: "server_error",
					error_description: "Server cannot process the request.",
				});
			},
		},
	},
});

function getUniqueField(formData: FormData, fieldName: string) {
	const field = formData.getAll(fieldName);

	if (!field || !Array.isArray(field)) return [undefined, { reason: "missing_param" }] as const;
	if (field.length > 1) return [undefined, { reason: "duplicate_param" }] as const;

	return [field[0] as string, null] as const;
}

const supportedGrantTypes = new Set(["authorization_code", "refresh_token", "client_credentials"]);

function isValidGrantType(grant: string): grant is GrantType {
	return supportedGrantTypes.has(grant);
}
