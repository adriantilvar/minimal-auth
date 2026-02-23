# Authorization Code Grant

An authorization code is a temporary credential used by the `client` to obtain an access token and optionally a refresh token.

This is a redirect-based flow, so the `client` must be capable of initiating the flow with the `Resource Owner's` user agent (typically a web browser) and capable of being redirected back to from the `Authorization Server`.

`Authorization Servers` **MUST** support the 'code_challenge' and 'code_verifier' parameters.

```
┌──────────┐
│ Resource │
│  Owner   │
└──────────┘
      ▲
      │
      │
┌─────│─────┐      Client Identifier         +---------------+
| .---+--------(1)-- & Redirect URI --------▶|               |
| |   |     |                                |               |
| |   '-—------(2)-- User authenticates ---->|               |
| | User-   |                                | Authorization |
| | Agent   |                                |    Server     |
| |         |                                |               |
| |    .-------(3)-- Authorization Code ----<|               |
+-|---|-----+                                +---------------+
  |   |                                           ^      v
  |   |                                           |      |
  ^   ▼                                           |      |
+----------+                                      |      |
|          |───(4)-- Authorization Code ---------'      |
|  Client  |          & Redirect URI                     |
|          |                                             |
|          |◀---(5)----- Access Token -------------------'
+----------+       (w/ Optional Refresh Token)
```

(1) The `client` initiates the flow by directing the `Resource Owner's` user agent to the authorization endpoint. The `client` includes its `client_id`, `code_challenge`, other optional fields, and a `redirect_uri` to which the `Authorization Server` will send the user agent back once access is granted (or denied).

(2) The `Authorization Server` authenticates the `Resource Owner` (via the user agent) and establishes whether the `Resource Owner` grants or denies the access request made by the `client`.

(3) Assuming the `Resource Owner` grants access, the `Authorization Server` redirects the user agent back to the `client` using the `redirect_uri` (provided in the request or during client registration). The `redirect_uri` includes an authorization code and any local state provided by the `client` earlier.

(4) The `client` requests an access token from the `Authorization Server's` token endpoint by including the authorization code received in the previous step, its `code_verifier`, and the `redirect_uri` used to obtain the authorization code. When making the request, the `client` authenticates with the `Authorization Server` if it can.

(5) The `Authorization Server` authenticates the `client` (when possible), validates the authorization code, validates the `code_verifier`, and ensures that the `redirect_uri` received matches the URI used to redirect the `client` in step (3). If valid, the `Authorization Server` responds back with an access token and, optionally, a refresh token.

## Code Verifier

`Clients` use a unique secret, called a _code verifier_, per authorization request to protect against authorization code injection and CSRF attacks. The `client` generates the code verifier to store it temporarily, then derives the _code challenge_ to include it in the authorization request. The `client` uses the code verifier when exchanging the authorization code at a token endpoint to prove that it is the same `client` that requested the authorization code.

The code verifier is a unique high-entropy cryptographically random string generated for each authorization request, using the unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "\_" / "~", with a minimum length of 43 characters and a maximum length of 128 characters.

The `client` creates a code challenge derived from the code verifier by using one of the following transformations on the code verifier:

- `S256`: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
- `plain`: code_challenge = code_verifier

> [!IMPORTANT]
>
> - Currently, `S256` is the only method that does not expose the code verifier in the authorization request. If the client is capable of using `S256`, it **MUST** use it, as `S256` is Mandatory To Implement (MTI) on the server. Clients are permitted to use `plain` only if they cannot support `S256` for some technical reason,
> - It is **RECOMMENDED** that the output of a suitable random number generator be used to create a 32-octet sequence. The octet sequence is then base64url-encoded to produce a 43-octet URL-safe string to use as the code verifier.

The properties `'code_challenge'` and `'code_verifier'` are adopted from the OAuth 2.0 extension known as _Proof-Key for Code Exchange_ (PKCE) [RFC7636], where this technique was originally developed.

## Authorization Request

The `client` builds the authorization request URI by adding the following parameters to the query component of the `/authorization` endpoint URI: (TODO: Check Appendix C.1)

| Parameter             | Optionality | Description                                                                                                                                                                                   |
| --------------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| response_type         | REQUIRED    | A value code that signals which type of flow the `client` wants to use.                                                                                                                       |
| client_id             | REQUIRED    | The `client` identifier.                                                                                                                                                                      |
| code_challenge        | REQUIRED    | Code challenge derived from the code verifier. It can be omitted only if specific requirements are met (Section 7.5.1).                                                                       |
| code_challenge_method | OPTIONAL    | Code verifier transformation method is `'S256'` or `'plain'`. Defaults to `'plain'`.                                                                                                          |
| redirect_uri          | OPTIONAL    | The redirect URI registered for this `client`. If multiple redirect URIs are registered for this `client`, it is **required**.                                                                |
| scope                 | OPTIONAL    | The scope of the access, expressed as a list of space-delimited, case-sensitive strings. If the value contains multiple spaced-delimited strings, their order does not matter request.        |
| state                 | OPTIONAL    | An opaque value used by the `client` to maintain state between the request and callback. The `Authorization Server` includes this value when redirecting the user agent back to the `client`. |

> [!Warning]
> The `state` and `scope` parameters **SHOULD NOT** include sensitive client or `Resource Owner` information in plain text, as they can be transmitted over insecure channels or stored insecurely.

The `client` directs the `Resource Owner` to the constructed URI using an HTTP redirection, or by other means available to it via the user agent.

For example, the `client` directs the user agent to make the following HTTPS request (with extra line breaks for display purposes only):

```bash
GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
    &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
    &code_challenge=6fdkQaPm51l13DSukcAH3Mdx7_ntecHYd1vi3n0hMZY
    &code_challenge_method=S256 HTTP/1.1
Host: server.example.com
```

The `Authorization Server` validates the request to ensure that all required parameters are present and valid.

In particular, the `Authorization Server` **MUST** validate the `redirect_uri` in the request if present, ensuring that it matches one of the registered redirect URIs previously established during client registration.

When comparing the two URIs the `Authorization Server` **MUST** ensure that the two URIs are equal (see Section 6.2.1 of [RFC3986] for details).

The only exception is native apps using a localhost URI: In this case, the `Authorization Server` **MUST** allow variable port numbers as described in Section 7.3 of [RFC8252].

If the request is valid, the `Authorization Server` authenticates the `Resource Owner` and obtains an authorization decision (by asking the `Resource Owner` or by establishing approval via other means).

When a decision is established, the `Authorization Server` directs the user agent to the provided `client` redirect URI using an HTTP redirection response, or by other means available to it via the user agent.

## Success Response

If the `Resource Owner` grants the access request, the `Authorization Server` issues an authorization code and delivers it to the `client` by adding the following parameters to the query component of the redirect URI:

| Parameter | Optionality | Description                                                                                                                                                                                                                                                                                  |
| --------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| code      | REQUIRED    | The authorization code generated by the `Authorization Server`, opaque to the `client` and bound to the `client_id`, `code_challenge`, and `redirect_uri`. It **MUST** expire shortly after it is issued to mitigate the risk of leaks. A maximum lifetime of 10 minutes is **RECOMMENDED**. |
| state     | OPTIONAL    | The exact value received from the client. It is required only if the `state` parameter was present in the `client` authorization request.                                                                                                                                                    |
| iss       | OPTIONAL    | The identifier of the `Authorization Server`, if the `client` interacts with more than one.                                                                                                                                                                                                  |

> [!NOTE]
> The `client` can use the `iss` field to prevent mix-up attacks. See Section 7.14 and RFC9207 for additional details on when this parameter is necessary and how the client can use it.

For example, the `Authorization Server` redirects the user agent by sending the following HTTP response:

```bash
 HTTP/1.1 302 Found
 Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
           &state=xyz&iss=https%3A%2F%2Fauthorization-server.example.com
```

> [!NOTE]
>
> - The `client` **MUST** ignore unrecognized response parameters.
> - The `client` should avoid making assumptions about `code` value sizes.
> - The `Authorization Server` **SHOULD** document the size of any value it issues.

> [!IMPORTANT]
> The `Authorization Server` **MUST** associate the `code_challenge` and `code_challenge_method` values with the issued authorization code so the code challenge can be verified later. The exact method that the server uses is out of scope of the OAuth spec.

The `code_challenge` and `code_challenge_method` values may be stored in encrypted form in the `code` itself, but the server **MUST NOT** include the `code_challenge` value in a response parameter in a form that entities other than the `Authorization Server` can extract.

## Error Response

If the request fails due to a missing, invalid, or mismatching `redirect_uri`, or if the `client_id` is missing or invalid, the the `Authorization Server` **SHOULD** inform the `Resource Owner` of the error and **MUST NOT** automatically redirect the user agent to the invalid redirect URI.

An `Authorization Server` **MUST** reject requests without a `code_challenge` from public clients, and **MUST** reject such requests from other clients unless here is reasonable assurance that the client mitigates authorization code injection in other ways. See Section 7.5.1 for details.

If the server does not support the requested `code_challenge_method` transformation, the authorization endpoint **MUST** return the authorization error response with error value set to `'invalid_request'`.

If the `Resource Owner` denies the access request or if the request fails for reasons other than a missing or invalid `redirect_uri`, the `Authorization Server` informs the `client` by adding the following parameters to the query component of the redirect URI:

| Parameter         | Optionality | Description                                                                                                                                         |
| ----------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| error             | REQUIRED    | One of the error codes defined below                                                                                                                |
| error_description | OPTIONAL    | Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred. |
| error_uri         | OPTIONAL    | A URI identifying a human-readable web page, used to provide the client developer with additional information about the error.                      |
| state             | OPTIONAL    | The exact value received from the client. It is required if a state parameter was present in the client authorization request.                      |
| iss               | OPTIONAL    | The identifier of the `Authorization Server`.                                                                                                       |

> [!NOTE]
>
> - Values for the `error` and `error_description` parameters **MUST NOT** include characters outside the set `%x20-21 / %x23-5B / %x5D-7E`.
> - Values for the `error_uri` parameter **MUST NOT** include characters outside the set `%x21 / %x23-5B / %x5D-7E`.

### Error Codes

| Error Code                  | Description                                                                                                                                                                                                                                           |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid_request`           | The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.                                                                                                     |
| `unauthorized_client`       | The client is not authorized to request an authorization code using this method.                                                                                                                                                                      |
| `access_denied`             | The `Resource Owner` or `Authorization Server` denied the request.                                                                                                                                                                                    |
| `unsupported_response_type` | The `Authorization Server` does not support obtaining an authorization code using this method.                                                                                                                                                        |
| `invalid_scope`             | The requested scope is invalid, unknown, or malformed.                                                                                                                                                                                                |
| `server_error`              | The `Authorization Server` encountered an unexpected condition that prevented it from fulfilling the request. (needed because a `500 Internal Server Error` HTTP status code cannot be returned to the `client` via an HTTP redirect).                |
| `temporarily_unavailable`   | The `Authorization Server` is currently unable to handle the request due to temporary overloading or maintenance of the server (needed because a `503 Service Unavailable` HTTP status code cannot be returned to the `client` via an HTTP redirect). |

For example, the `Authorization Server` redirects the user agent by sending the following HTTP response:

```bash
 HTTP/1.1 302 Found
 Location: https://client.example.com/cb?error=access_denied
           &state=xyz&iss=https%3A%2F%2Fauthorization-server.example.com
```

## Token Endpoint Extension

If the `grant_type` with a value of `authorization_code` is identified at the `/token` endpoint, the following additional token request parameters (beyond Section 3.2.2) are supported:

| Parameter     | Optionality | Description                                                                                                                                                          |
| ------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| code          | REQUIRED    | The authorization code received from the `Authorization Server`.                                                                                                     |
| redirect_uri | REQUIRED | The same redirect URI that was provided in the associated authorization request. Although not necessary in OAuth 2.1, it is enforced for backwards compatibility with OAuth 2.0 |
| code_verifier | OPTIONAL    | The original code verifier string. **MUST** be included if the `code_challenge` parameter was included in the authorization request; **MUST NOT** be used otherwise. |
| client_id     | OPTIONAL    | REQUIRED if the `client` is not authenticating with the `Authorization Server` as described in Section 3.2.1.                                                        |

> [!IMPORTANT]
> The `Authorization Server` **MUST** return an access token only once for a given authorization code.
>
> If a second valid token request is made with the same authorization code as a previously successful token request, the `Authorization Server` **MUST** deny the request and **SHOULD** revoke (when possible) all access tokens and refresh tokens previously issued based on that authorization code.

For example, the `client` makes the following HTTPS request (with extra line breaks for display purposes only):

```bash
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&code_verifier=3641a2d12d66101249cdf7a79c000c1f8c05d2aafcf14bf146497bed
```

In addition to the processing rules for the `/token` endpoint request, the `Authorization Server` **MUST**:

- ensure that the authorization code was issued to the authenticated confidential `client`, or if the `client` is public, ensure that the code was issued to `client_id` in the request,
- verify that the authorization code is valid,
- verify that the `code_verifier` parameter is present if and only if a `code_challenge` parameter was present in the authorization request,
- if a `code_verifier` is present, verify the `code_verifier` by calculating the code challenge received from it and comparing it with the previously associated `code_challenge`, after transforming it according to the `code_challenge_method` method specified by the `client`,
- if there was no `code_challenge` in the authorization request associated with the authorization code in the token request, the `Authorization Server` **MUST** reject the token request.
