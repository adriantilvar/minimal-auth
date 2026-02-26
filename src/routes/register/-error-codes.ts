export const ErrorCodes = {
	/**
	 * The value of one or more redirection URIs is invalid.
	 */
	INVALID_REDIRECT_URI: "invalid_redirect_uri",

	/**
	 * The value of one of the client metadata fields is invalid and the server
	 * has rejected this request.
	 *
	 * Note that an authorization server MAY choose to substitute a valid value
	 * for any requested parameter of a client's metadata.
	 */
	INVALID_CLIENT_METADATA: "invalid_client_metadata",

	/**
	 * The software statement presented is invalid.
	 */
	INVALID_SOFTWARE_STATEMENT: "invalid_software_statement",

	/**
	 * The software statement presented is not approved for use by this
	 * authorization server.
	 */
	UNAPPROVED_SOFTWARE_STATEMENT: "unapproved_software_statement",
} as const;

export type ClientRegistrationErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
