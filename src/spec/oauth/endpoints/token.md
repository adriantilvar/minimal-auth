# Token Endpoint

The **token endpoint** is used by the `client` to obtain an access token using a grant, such as those described in Section 4 and Section 4.3.

> [!NOTE]
> The token endpoint URL **MUST NOT** include a fragment component, and **MAY** include a query string component.

`Authorization Servers` that wish to support browser-based applications (e.g. applications running exclusively in client-side JavaScript without access to a supporting back-end server), will need to ensure the token endpoint supports the necessary CORS [WHATWG.CORS] headers to allow the responses to be visible to the application.

## Token Request

> [!IMPORTANT]
> Confidential clients **MUST** authenticate with the `Authorization Server` when making requests to the token endpoint.

The `client` **MUST** use the HTTP `POST` to make a request to the token endpoint. The request content has to contain the following parameters:

| Parameter  | Optionality | Description                                                                                                                                                                                                       |
| ---------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| grant_type | REQUIRED    | Identifier of the grant type. The allowed values are `authorization_code`, `refresh_token`, and `client_credentials`. The grant type determines the further parameters required or supported by the token request |
| client_id  | OPTIONAL    | The client identifier is needed when a form of client authentication that relies on the parameter is used, or the `grant_type` requires identification of public clients.                                         |

The request must use the `application/x-www-form-urlencoded` media type, with the character encoding of UTF-8.

> [!NOTE]
>
> - The `Authorization Server` **MUST** ignore unrecognized request parameters.
> - Request and response parameters **MUST NOT** be included more than once.
> - Parameters sent without a value **MUST** be treated as if they were omitted from the request.

For example, the `client` makes the following HTTPS request (with extra line breaks for display purposes only):

```http
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
&code_verifier=3641a2d12d66101249cdf7a79c000c1f8c05d214bf146497bed
```

## Success Response

If the access token request is valid and authorized, the `Authorization Server` issues an access token and optionally a refresh token.

The `Authorization Server` sends a response with the following parameters:

| Parameter     | Optionality            | Description                                                                                                                                                                                                                                                                                       |
| ------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| access_token  | REQUIRED               | The access token issued by the `Authorization Server`                                                                                                                                                                                                                                             |
| token_type    | REQUIRED               | The type of the access token issued. Value is case insensitive.                                                                                                                                                                                                                                   |
| expires_in    | RECOMMENDED            | A JSON number that represents the lifetime in seconds of the access token. For example, the value 3600 denotes that the access token will expire in one hour from the time the response was generated.                                                                                            |
| scope         | RECOMMENDED / REQUIRED | Recommended if identical to the scope requested by the `client`, required otherwise                                                                                                                                                                                                               |
| refresh_token | OPTIONAL               | A string representing the the authorization granted to the `client` by the `Resource Owner`, opaque to the `client`, which can be used to obtain new access tokens. It may be an identifier used to retrieve the authorization information or may encode this information into the string itself. |

The parameters are serialized into a JSON structure as described in Appendix C.3.

The response must use the `application/json` media type as defined by [RFC8259] and an `HTTP 200 (OK)` status code.

If `expires_in` is omitted, the `Authorization Server` **SHOULD** provide the lifetime via other means or document the default value.

> [!WARNING]
> The `Authorization Server` may prematurely expire an access token and `clients` **MUST NOT** expect an access token to be valid for the provided lifetime.

If the `Authorization Server` decides not to issue refreshed tokens, the client **MAY** obtain new access tokens by starting the OAuth flow over (for example, initiating a new authorization code request). In such a case, the `Authorization Server` may utilize cookies and persistent grants to optimize the user experience.

If refresh tokens are issued, they **MUST** be bound to the scope and `Resource Servers` as consented by the `Resource Owner`.

> [!IMPORTANT]
> The `Authorization Server` **MUST** include the HTTP `Cache-Control` response header field (Section 5.2 of [RFC9111]) with a value of `'no-store'` in any response containing tokens, credentials, or other sensitive information.

For example:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
	"access_token":"2YotnFZFEjr1zCsicMWpAA",
    "token_type":"Bearer",
    "expires_in":3600,
    "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
    "example_parameter":"example_value"
}
```

The client **MUST** ignore unrecognized value names in the response.

The `client` should avoid making assumptions about the sizes of tokens and other values received from the `Authorization Server`.

## Error Response

If the request client authentication failed or is invalid, the `Authorization Server` returns an error response.

The `Authorization Server` sends a response with the following parameters in the content of the response:

| Parameter         | Optionality | Description                                                                                                                                         |
| ----------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| error             | REQUIRED    | One of the error codes defined below                                                                                                                |
| error_description | OPTIONAL    | Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred. |
| error_uri         | OPTIONAL    | A URI identifying a human-readable web page, used to provide the client developer with additional information about the error.                      |

The response must use the `application/json` media type as defined in Appendix C.3 and an `HTTP 400 (Bad Request)` status code (unless specified otherwise).

> [!NOTE]
>
> - Values for the `error` and `error_description` parameters **MUST NOT** include characters outside the set `%x20-21 / %x23-5B / %x5D-7E`.
> - Values for the `error_uri` parameter **MUST NOT** include characters outside the set `%x21 / %x23-5B / %x5D-7E`.

### Error Codes

| Error Code             | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| invalid_request        | The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the `client`, contains a `code_verifier` although no `code_challenge` was sent in the authorization request, or is otherwise malformed.                                                                                                                                                                                                                 |
| invalid_client         | Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The `Authorization Server` **MAY** return an `HTTP 401 (Unauthorized)` status code to indicate which HTTP authentication schemes are supported. If the client attempted to authenticate via the `Authorization` request header field, the `Authorization Server` **MUST** respond with an `HTTP 401 (Unauthorized)` status code and include the `WWW-Authenticate` response header field matching the authentication scheme used by the client. |
| invalid_grant          | The provided authorization grant (e.g., authorization code, `Resource Owner` credentials) or refresh token is invalid, expired, revoked, does not match the redirect URI used in the authorization request, or was issued to another `client`.                                                                                                                                                                                                                                                                                                                                |
| unauthorized_client    | The authenticated `client` is not authorized to use this authorization grant type.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| unsupported_grant_type | The authorization grant type is not supported by the `Authorization Server`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| invalid_scope          | The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the `Resource Owner`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

For example:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
	"error": "invalid_request"
}
```
