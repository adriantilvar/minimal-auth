# OAuth 2.1 (based on draft)

OAuth introduces an authorization layer to the client-server authentication model by separating the role of the _client_ from that of the _resource owner_.

> [!NOTE]
> OAuth is NOT an authentication protocol. If the goal is to authenticate users, an authentication protocol, like OpenID Connect (OIDC), is necessary.

The client requests access to resources controlled by the resource owner and hosted by the _resource server_. For the request to be served, the client needs to provide a valid _access token_, which was issued by the _authorization server_, with the approval of the resource owner.

Example: An end user (resource owner) grants a financial management service (client) access to their transaction history stored at a banking service (resource server) without sharing their credentials with the financial management service. They authenticate directly with their financial institution's server (authorization server), which issues the financial management service specific credentials (access token).

The spec is designed for use with HTTP. The use of OAuth over any protocol other than HTTP is out of scope.

## Roles

OAuth defines four roles:

- `"resource owner" (RO)`:
  An entity capable of granting access to a protected resource. When the resource owner is a person, it is referred to as an 'end user'.

- `"resource server" (RS)`:
  The server hosting the protected resources, capable of accepting and responding to protected resource requests using access tokens. The resource server is often accessible via an API.

- `"client"`:
  An application making protected resource requests on behalf of the resource owner and with its authorization. The term "client" does not imply any particular implementation characteristics (e.g., whether the application executes on a server, a desktop, or other devices).

- `"authorization server" (AS)`:
The server issuing access tokens to the client after successfully authenticating the resource owner and obtaining authorization.
The `Authorization Server` may be the same server as the `Resource Server` or a separate entity.
A single `Authorization Server` may issue access tokens accepted by multiple `Resource Servers`.

## Protocol Flow

```
+--------+                               +---------------+
|        |--(1)- Authorization Request ->|   Resource    |
|        |                               |     Owner     |
|        |<-(2)-- Authorization Grant ---|               |
|        |                               +---------------+
|        |
|        |                               +---------------+
|        |--(3)-- Authorization Grant -->| Authorization |
| Client |                               |     Server    |
|        |<-(4)----- Access Token -------|               |
|        |                               +---------------+
|        |
|        |                               +---------------+
|        |--(5)----- Access Token ------>|    Resource   |
|        |                               |     Server    |
|        |<-(6)--- Protected Resource ---|               |
+--------+                               +---------------+
```

(1) The `client` requests authorization from the `Resource Owner`. The authorization request can be made directly to the `Resource Owner` (as shown), or preferably indirectly via the `Authorization Server` as an intermediary.

(2) The `client` receives an authorization grant, which is a credential representing the `Resource Owner's` authorization. The authorization grant type depends on the method used by the `client` to request authorization and the types supported by the `Authorization Server`.

(3) The `client` requests an access token by authenticating with the `Authorization Server` and presenting the authorization grant.

(4) The `Authorization Server` authenticates the `client` and validates the authorization grant, and if valid, issues an access token.

(5) The `client` requests the protected resource from the `Resource Server` and authenticates by presenting the access token.

(6) The `Resource Server` validates the access token, and if valid, serves the request.

## Access Token

An access token represents an authorization issued to a `client` that allows it to access specific protected resources.

> [!NOTE]
> The access token (a string) is considered opaque to the `client`. Therefore, the `client` **MUST NOT** expect to be able to parse the access token value.

Access tokens are short-lived to reduce the blast radius of a leak. The expiration of the access token is set by the `Authorization Server`.

The `Resource Server` may use the token to retrieve authorization info, or the token may self-contain the
authorization info in a verifiable manner (i.e. a token string consisting of a signed data payload).

One example of a token retrieval mechanism is _Token Introspection_ [RFC7662], in which the `Resource Server` calls the endpoint on the `Authorization Server` to validate the token presented by the `client`.

One example of a structured token format is a _JWT Profile for Access Tokens_ [RFC9068], a method of encoding and signing access token data as a JSON web token (JWT) [RFC7519].

Access tokens can have different formats, structures and methods of utilization. No consistent encoding or format is required, other than what is expected by the `Resource Server`

### Limited-Scope Access Token

A 'limited-scope' access token is issued to `clients` with less privileges than the user granted the access has.

The `Authorization Server` and `Resource Server` can use the scope mechanism to limit what type of resources or
level of access a particular `client` can have. For example, a `client` may request a read-only scope if it only needs to read a user’s resources, ensuring the issued access token cannot be used to modify them.

> [!NOTE]
> Scopes are defined by `Authorization Server` or by extensions or profiles of OAuth (e.g. OpenID). It is recommended to avoid defining custom scopes that conflict with scopes from known extensions.

To request a limited-scope access token, the `client` uses the `scope` request parameter at the `/authorization` or
`/token` endpoints, depending on the grant type used.

The `Authorization Server` provides the `client` the ability to request specific scopes and associates those scopes with the access token issued to it.

The `Resource Server` is responsible for enforcing scopes when presented with a limited-scope access token.

The `Authorization Server` **MAY** fully or partially ignore the scope requested by the client, based on its policy or the `Resource Server's` instructions.

The `Authorization Server` **SHOULD** document its scope requirements and default value (if defined).

> [!IMPORTANT]
> If the `client` omits the `scope` parameter when requesting authorization, the `Authorization Server` **MUST** either process the request using a pre-defined default value or fail the request indicating an invalid scope.

### Bearer Tokens

A 'bearer token' is a security token with the property that any party in possession of the token (a "bearer") can
use it in any way that any other party in possession of it can.

Using a bearer token does not require a bearer to prove possession of cryptographic key material (proof-of-possession). They may, however, be enhanced with proof-of-possession specs such as _DPoP_ [RFC9449] and _mTLS_ [RFC8705].

If a bearer token uses an encoding mechanism to contain the authorization info in the token itself, it **MUST** use integrity protection sufficient to prevent the token from being modified (an example is the _JSON Web Token Profile for Access Tokens_ [RFC9068]).

### Sender-Constrained Access Tokens

A 'sender-constrained' access token binds its use to a specific sender. The sender is obliged to demonstrate
knowledge of a certain secret as a prerequisite for the acceptance of that access token at the recipient (e.g. a
`Resource Server`).

`Authorization Servers` and `Resource Servers` **SHOULD** use mechanisms for sender constraining access tokens such as DPoP [RFC 9449], or mTLS [RFC 8705]

It is **RECOMMENDED** to use end-to-end TLS between the `client` and the `Resource Server`.

## Client Registration

Client registration does not require direct interaction between the `client` and the `Authorization Server`.

> [!IMPORTANT]
> Before initiating OAuth, the `client` must have established an identifier at the `Authorization Server`.
> This is beyond the scope of the OAuth spec.

Client registrations **MUST** include:

- client type,
- client details needed by the grant type in use (such as redirect URIs), and
- any other info required by the `Authorization Server` (e.g. application name, website description, etc.)

_Dynamic Client Registration_ [RFC7591] defines a common general data model for clients that may be used even with manual client registration.

### Client Types

Client types are defined based on their ability to authenticate securely with the `Authorization Server`:

- `"confidential"`: clients that have credentials with the `Authorization Server`
- `"public"`: clients without credentials

Client authentication allows an `Authorization Server` to ensure it's interacting with a certain `client` (identified by its `client_id`) in an OAuth flow.

> [!NOTE]
> A single `client_id` **SHOULD NOT** be treated as more than one type of client.

The OAuth spec has been designed around the following _client profiles_:

- `"web application"`: A `client` running on a web server. The client credentials, as well as any access tokens issued to the `client`, are stored on the web server and are not exposed to or accessible by the `Resource Owner`.

- `"browser-based application"`: A `client` in which the client code is downloaded from a web server and executes within a user agent (e.g. web browser) on a device used by the `Resource Owner`. Protocol data and credentials are easily accessible to the `Resource Owner`. If such applications wish to use client credentials, it is recommended to utilize the back-end for front-end pattern.

- `"native application"`: A `client` installed and executed on a device used by the `Resource Owner`. Protocol data and credentials are accessible to the `Resource Owner`. It is assumed that any client authentication credentials included in the app can be extracted. If such applications wish to use client credentials, it is recommended to utilize the back-end for front-end pattern, or issue the credentials at runtime using Dynamic Client Registration [RFC7591].

### Client Identifier

Every `client` is identified in the context of an `Authorization Server` by a _client identifier_ (`client_id`)-- a unique, opaque string representing the registration info provided by the `client`.

While the `Authorization Server` typically issues the client identifier itself, it may also serve clients whose client identifier was created by a party other than the `Authorization Server`.

> [!IMPORTANT]
> The client identifier is not a secret; it is exposed to the `Resource Owner` and **MUST NOT** be used alone for client authentication.

The `Authorization Servers` **SHOULD** document the size of any identifier it issues. However, the `client` should avoid making assumptions about the identifier size.

### Client Redirection Endpoint

The _client redirection endpoint_ (or "redirect endpoint") is the URI of the `client` that the `Authorization Server` redirects the user agent back to after completing its interaction with the `Resource Owner`.

The redirect endpoints are established with the `Authorization Servers` during the client registration process.

> [!NOTE]
>
> - The redirect URI **MUST** be an absolute URI as defined by Section 4.3 of [RFC3986].
> - The redirect URI **MAY** include a query string component, which **MUST** be retained when adding additional query parameters.
> - The redirect URI **MUST NOT** include a fragment component.

### Registration Requirements

`Authorization Servers` **MUST** require `clients` to register their complete redirect URI, including the path component. The `Authorization Servers` **MAY** allow the client to register multiple redirect URIs.

`Authorization Servers` **MUST** reject authorization requests that specify a redirect URI that doesn't exactly match one that was registered. An exception is made for loopback redirects, where an exact match is required except for the port URI component (see Section 4.1.1 for details).

For private-use URI scheme-based redirect URIs, `Authorization Servers` **SHOULD** enforce the requirement that `clients` use schemes that are reverse domain name based. At a minimum, any private-use URI scheme that doesn't contain a period character (.) should be rejected.

`Clients` **MUST** not expose URLs that forward the user's browser to arbitrary URIs obtained from a query parameter ("open redirector").

> [!NOTE]
> Open redirectors can enable exfiltration of authorization codes and access tokens. Without requiring registration of redirect URIs, attackers can use the authorization endpoint as an open redirector.

The `client` **MAY** use the `state` request parameter to achieve per-request customization if needed rather than varying the redirect URI per request.

### Client Endpoint Content

The redirection request to the `client`'s endpoint typically results in an HTML document response processed by the user agent.

If the HTML responses serve directly as the result of the redirection request, any script included in the HTML document will execute with full access to the redirect URI and the artifacts (e.g. authorization code) it contains.

Additionally, the request URL containing the authorization code may be sent in the `HTTP Referrer` header to any embedded images, stylesheets, and other elements loaded in the page.

> [!NOTE]
> The `client` **SHOULD NOT** include any third-party scripts (e.g. third-party analytics, social plugins, ad networks) in the redirect URI endpoint response. Instead, it **SHOULD** extract the artifacts from the URI and redirect the user agent again to another endpoint without exposing the artifacts (in the URI or elsewhere).
>
> If third-party scripts are included, the client MUST ensure that its own scripts (used to extract and remove the credentials from the URI) will execute first.

## Client Authentication

The `Authorization Server` **MUST** only rely on the client authentication if the process of issuance/registration and distribution of the underlying credentials ensures their confidentiality.

For confidential clients, the `Authorization Server` **MAY** accept any form of client authentication meeting its security requirements (e.g. client secret, public-private key pair).

> [!NOTE]
> It is **RECOMMENDED** to use asymmetric (public-key based) methods for client authentication, such as mTLS [RFC8705] or using signed JWTs in accordance with [RFC7521], [RFC7523], and their update [I-D.ietf-oauth-rfc7523bis] (defined in [OpenID] as the client authentication method private_key_jwt).

When client authentication is not possible, the `Authorization Server` **SHOULD** employ other means to validate the client's identity. For example, the `Authorization Server` could require the registration of the `client` redirect URI or enlisting the `Resource Owner` to confirm identity.

A valid redirect URI is not sufficient to verify the `client's` identity when asking for `Resource Owner` authorization. It can, however, be used to prevent delivering credentials to a counterfeit `client` after obtaining `Resource Owner` authorization.

> [!IMPORTANT]
> The `client` **MUST NOT** use more than one authentication method in each request to prevent the conflict of which authentication mechanism is authoritative for the request

## Client Secret

### Client Secret Post

To support confidential clients in possession of a client secret, the `Authorization Server` **MUST** support client credentials in a client request body content using the following parameters:

| Parameter     | Optionality | Description                                                                |
| ------------- | ----------- | -------------------------------------------------------------------------- |
| client_id     | REQUIRED    | The client identifier issued to the client during the registration process |
| client_secret | REQUIRED    | The client secret.                                                         |

! [!IMPORTANT]

> The parameters can only be transmitted in the request content and MUST NOT be included in the request URI.

This is also known as `client_secret_post` as defined in Section 2 of [RFC7591].

For example, a request to refresh an access token using the content parameters (with extra line breaks for display purposes only):

```bash
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
&client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw
```

### Client Secret Basic

The `Authorization Server` **MAY** support the _HTTP Basic authentication scheme_ for authenticating `clients` that were issued a client secret.

When using the HTTP Basic authentication scheme, as defined in Section 11 of [RFC9110], to authenticate with the `Authorization Server`, the `client_id` is encoded using the `application/x-www-form-urlencoded` encoding algorithm. The encoded value is used as the `username` and the `client_secret` is encoded using the same algorithm and used as the `password`.

This is also known as `client_secret_basic` as defined in Section 2 of [RFC7591].

For example (with extra line breaks for display purposes only):

```bash
Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
```

> [!NOTE]
> This method of initially form-encoding the client identifier and secret, and then using the encoded values as the HTTP Basic authentication username and password has led to many interoperability problems in the past. Including the credentials in the request body content avoids the encoding issues and leads to more interoperable implementations.

> [!IMPORTANT]
> Since the client's secret authentication method involves a password, the `Authorization Server` **MUST** protect any endpoint utilizing it against brute force attacks.

## Unregistered Clients

The use of unregistered clients is beyond the scope of the OAuth spec.
