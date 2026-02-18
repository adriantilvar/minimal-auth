# Client Registration

Before initiating OAuth, the `client` must have established an identifier at the `AS`. (beyond the scope of this spec)

Client registration does not require direct interaction between the `client` and the `AS`.

Client registrations **MUST** include:

- client type as described in section 2.1,
- client details needed by the grant type in use, such as redirect URIs as described in section 2.3, and
- any other info required by the `AS` (e.g. application name, website description, the acceptance of legal terms)

_Dynamic Client Registration_ [RFC7591] defines a common general data model for clients that may be used even with manual client registration.

## Client Types

Client types are defined based on their ability to authenticate securely with the `AS`:

- `"confidential"`-- `clients` that have credentials with the `AS`
- `"public"`: `clients` without credentials

Client authentication allows an `AS` to ensure it's interacting with a certain `client` (identified by its `client_id`) in an OAuth flow.

A single `client_id` **SHOULD NOT** be treated as more than one type of client.

The OAuth spec has been designed around the following _client profiles_: -`"web application"`: A `client` running on a web server. The client credentials, as well as any access tokens issued to the `client`, are stored on the web server and are not exposed to or accessible by the `RO`. -`"browser-based application"`: A `client` in which the client code is downloaded from a web server and executes within a user agent (e.g. web browser) on a device used by the `RO`. Protocol data and credentials are easily accessible to the `RO`. If such applications wish to use client credentials, it is recommended to utilize the back-end for front-end pattern.

- `"native application"`: A `client` installed and executed on a device used by the `RO`. Protocol data and credentials are accessible to the `RO`. It is assumed that any client authentication credentials included in the app can be extracted. Dynamically issued access tokens and refresh tokens can receive an acceptable level of protection. If such applications wish to use client credentials, it is recommended to utilize the back-end for front-end pattern, or issue the credentials at runtime using Dynamic Client Registration [RFC7591].

## Client Identifier

Every `client` is identified in the context of an `AS` by a _client identifier_ (`client_id`)-- a unique, opaque string representing the registration info provided by the `client`. While the `AS` typically issues the client identifier itself, it may also serve clients whose client identifier was created by a party other than the `AS`.

The client identifier is not a secret; it is exposed to the `RO` and **MUST NOT** be used alone for client authentication.

The `AS` **SHOULD** document the size of any identifier it issues. However, the `client` should avoid making assumptions about the identifier size.

## Client Redirection Endpoint

The _client redirection endpoint_ (or "redirect endpoint") is the URI of the `client` that the `AS` redirects the user agent back to after completing its interaction with the `RO`.

The redirect endpoints are established with the `AS` during the client registration process.

The redirect URI **MUST** be an absolute URI as defined by Section 4.3 of [RFC3986].

The redirect URI **MAY** include a query string component, which **MUST** be retained when adding additional query parameters.

The redirect URI **MUST NOT** include a fragment component.

### Registration Requirements

`ASs` **MUST** require `clients` to register their complete redirect URI, including the path component.

ASs **MUST** reject authorization requests that specify a redirect URI that doesn't exactly match one that was registered. An exception is made for loopback redirects, where an exact match is required except for the port URI component (see Section 4.1.1 for details).

The `AS` **MAY** allow the client to register multiple redirect URIs.
