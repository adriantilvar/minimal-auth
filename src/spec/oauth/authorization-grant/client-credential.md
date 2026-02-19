# Client Credentials

The `client` can request an access token using only its client credentials (or other supported means of authentication) when the `client` is requesting access to the protected resources under its control, or those of another `Resource Owner` that have been previously arranged with the `Authorization Server`.

Though beyond the scope of this spec, an example includes a private key used to sign a JWT, as described in [RFC7523] and its update [I-D.ietf-oauth-rfc7523bis]).

> [!IMPORTANT]
> The client credentials grant type **MUST** only be used by confidential clients.
>
> The `Authorization Server` **MUST** authenticate the client.

```
+---------+                                  +---------------+
|         |                                  |               |
|         |>--(1)- Client Authentication --->| Authorization |
| Client  |                                  |     Server    |
|         |<--(2)---- Access Token ---------<|               |
|         |                                  |               |
+---------+                                  +---------------+
```

                     Figure 4: Client Credentials Grant

(1) The `client` authenticates with the `Authorization Server` and requests an access token from the token endpoint.

(2) The `Authorization Server` authenticates the `client`, and if valid, issues an access token.

## Token Endpoint Extension

If the `grant_type` with a value of `client_credentials` is identified at the `/token` endpoint, the following additional token request parameters (beyond Section 3.2.2) are supported:

| Parameter | Optionality | Description                      |
| --------- | ----------- | -------------------------------- |
| scope     | OPTIONAL    | The scope of the access request. |

For example, the `client` makes the following HTTP request using TLS (with extra line breaks for display purposes only):

```bash
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```
