# Refresh Token

A refresh token is a credential issued by the `Authorization Server` to a `client`, which can be used to obtain new (fresh) access tokens based on an existing grant.

> [!IMPORTANT]
> Confidential clients **MUST** authenticate with the `Authorization Server`.

The `client` uses this option either to obtain a new access token when the current access token becomes invalid or expires, or to obtain additional access tokens with identical or narrower scope (access tokens may have a shorter lifetime and fewer privileges than authorized by the `Resource Owner`).

> [!NOTE]
> Issuing a refresh token is optional at the discretion of the `Authorization Server`.
>
> If the `Authorization Server` issues a refresh token, it is included when issuing an access token (i.e., step (2) below). The `client` **MUST** discard any old refresh token and replace it with the new one.
>
> The lifetime of the refresh token is also at the discretion of the `Authorization Server`. Refresh tokens **SHOULD** expire if the `client` has been inactive for some time (i.e. the refresh token has not been used to obtain new access tokens for some time).

```
+--------+                                           +---------------+
|        |--(1)------- Authorization Grant ------>   |               |
|        |                                           |               |
|        |<-(2)----------- Access Token ----------   |               |
|        |               & Refresh Token             |               |
|        |                                           |               |
|        |                            +----------+   |               |
|        |--(3)---- Access Token ---->|          |   |               |
|        |                            |          |   |               |
|        |<-(4)- Protected Resource --| Resource |   | Authorization |
| Client |                            |  Server  |   |     Server    |
|        |--(5)---- Access Token ---->|          |   |               |
|        |                            |          |   |               |
|        |<-(6)- Invalid Token Error -|          |   |               |
|        |                            +----------+   |               |
|        |                                           |               |
|        |--(7)----------- Refresh Token ----------->|               |
|        |                                           |               |
|        |<-(8)----------- Access Token -------------|               |
+--------+           & Optional Refresh Token        +---------------+
```

    		Figure 2: Refreshing an Expired Access Token

(1) The `client` requests an access token by authenticating with the `Authorization Server` and presenting an authorization grant.

(2) The `Authorization Server` authenticates the client and validates the authorization grant, and if valid, issues an access token and optionally a refresh token.

(3) The `client` makes a protected resource request to the `Resource Server` by presenting the access token.

(4) The `Resource Server` validates the access token, and if valid, serves the request.

(5) Steps (3) and (4) repeat until the access token expires. If the `client` knows the access token expired, it skips to step (7); otherwise, it makes another protected resource request.

(6) Since the access token is invalid, the `Resource Server` returns an invalid token error.

(7) The `client` requests a new access token from the `Authorization Server` by presenting the refresh token and providing client authentication if it has been issued credentials.

(8) The `Authorization Server`authenticates the `client` and validates the refresh token, and if valid, issues a new access token (and, optionally, a new refresh token).

Refresh tokens **MUST** be kept confidential in transit and storage, and shared only among the `Authorization Server` and the `client` to whom the refresh tokens were issued. Unlike access tokens, refresh tokens are never sent to`Resource Servers`.

Because refresh tokens are typically long-lasting credentials used to request additional access tokens, the refresh token is bound to the `client` to which it was issued.

The `Authorization Server` **MUST** maintain the binding between a refresh token and the client to whom it was issued.

The `Authorization Server` **MUST** also verify the binding between the refresh token and `client_id` whenever the client identity can be authenticated. When client authentication is not possible, the `Authorization Server` **SHOULD** issue sender-constrained refresh tokens or use refresh token rotation as described in Section 4.3.1.

> [!NOTE]
> There is no need to communicate the lifetime of the refresh token to the `client`, because the client can't do anything different with this knowledge.
>
> Additionally, the `Authorization Server` might choose to use dynamic lifetimes (e.g. the refresh token expiry is extended as long as the refresh token is used at least once every 7 days), or it might revoke the refresh token before its scheduled expiration date for any reason (e.g. in case of a security event such as password change or logout).
>
> Regardless of why or when the refresh token expires, the `client` has only one path to obtain new tokens, which is to start a new OAuth flow from the beginning.

## Token Endpoint Extension

If the `grant_type` with a value of `refresh_token` is identified at the `/token` endpoint, the following additional token request parameters (beyond Section 3.2.2) are supported:

| Parameter     | Optionality | Description                                                                                                                                                                            |
| ------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| refresh_token | REQUIRED    | The refresh token issued to the `client`.                                                                                                                                              |
| scope         | OPTIONAL    | The scope of the access, expressed as a list of space-delimited, case-sensitive strings. If the value contains multiple spaced-delimited strings, their order does not matter request. |

The requested scope **MUST NOT** include any scope not originally granted by the `Resource Owner`, and if omitted is treated as equal to the scope originally granted by the `Resource Owner`.

For example, the `client` makes the following HTTP request using TLS (with extra line breaks for display purposes only):

```bash
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
```
