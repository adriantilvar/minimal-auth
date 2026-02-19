# Authorization Endpoint

The **authorization endpoint** is used to interact with the `Resource Owner` and obtain an _authorization grant_.

> [!IMPORTANT]
> The `Authorization Server` must first authenticate the `Resource Owner`.

The way in which the `Authorization Server` authenticates the `Resource Owner` (e.g. username and password login, passkey, or by using established session) is beyond the scope of OAuth.

The authorization endpoint URL **MUST NOT** include a fragment component. It **MAY** include a query string component, which **MUST** be retained when adding additional query parameters.

The `Authorization Server` **MUST** support the use of the HTTP `GET` method (Section 9.3.1 of [RFC9110]) for the authorization endpoint and **MAY** support the `POST` method (Section 9.3.3 of [RFC9110]) as well.

The `Authorization Server` **MUST** ignore unrecognized request parameters sent to the authorization endpoint.

Request and response parameters **MUST NOT** be included more than once.

Parameters sent without a value **MUST** be treated as if they were omitted from the request.

An `Authorization Server` that redirects a request potentially containing user credentials **MUST** avoid forwarding these user credentials accidentally (see Section 7.5.4 for details).

_Cross-Origin Resource Sharing_ [WHATWG.CORS] **MUST NOT** be supported at the authorization endpoint, as the `client` does not access this endpoint directly. Instead, the `client` redirects the user agent to it.
