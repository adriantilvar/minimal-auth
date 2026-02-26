# Register Endpoint

The OAuth 2.0 client registration endpoint is designed to allow a client to be registered with the authorization server.

The client registration endpoint MUST accept HTTP POST messages with request parameters encoded in the entity body using the "application/json" format.

The client registration endpoint MUST be protected by a transport-layer security mechanism.

The client registration endpoint MAY be an OAuth 2.0 [RFC6749] protected resource and it MAY accept an initial access token in the form of an OAuth 2.0 access token to limit registration to only previously authorized parties. The method by which the initial access token is obtained by the client or developer is out of out of scope for this spec. The method by which the initial access token is verified and validated by the client registration endpoint is out of scope for this spec.

To support open registration and facilitate wider interoperability, the client registration endpoint SHOULD allow registration requests with no authorization (no initial access token in the request). These requests MAY be rate-limited or otherwise limited to prevent a denial-of-service attack on the client registration endpoint.

## Client Registration Request

This operation registers a client with the authorization server. The authorization server assigns this client a unique client ID, optionally assigns a client secret, and associates the metadata provided in the request with the issued client ID.

The request includes any client metadata parameters being specified for the client during the registration. The authorization server MAY provision default values for any items omitted in the client metadata.

To register, the client or developer sends an `HTTP POST` to the client registration endpoint with a content type of `"application/json"`. The `HTTP Entity Payload` is a JSON object and with all client metadata values as top-level members.

For example, if the server supports open registration (with no initial access token), the client could send the following registration request to the client registration endpoint:

```http
POST /register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: server.example.com

{
	"redirect_uris": [
		"https://client.example.org/callback",
	    "https://client.example.org/callback2"],
    "client_name": "My Example Client",
    "client_name#ja-Jpan-JP":
         "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
    "token_endpoint_auth_method": "client_secret_basic",
    "logo_uri": "https://client.example.org/logo.png",
    "jwks_uri": "https://client.example.org/my_public_keys.jwks",
    "example_extension_parameter": "example_value"
}
```

Alternatively, if the server supports authorized registration, the developer or the client will be provisioned with an initial access token (out of scope for this spec). The developer or client sends the following authorized registration request to the client registration endpoint:

```http
POST /register HTTP/1.1
Content-Type: application/json
Accept: application/json
Authorization: Bearer ey23f2.adfj230.af32-developer321
Host: server.example.com

{
    "redirect_uris": ["https://client.example.org/callback",
	    "https://client.example.org/callback2"],
    "client_name": "My Example Client",
    "client_name#ja-Jpan-JP":
         "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
    "token_endpoint_auth_method": "client_secret_basic",
    "policy_uri": "https://client.example.org/policy.html",
    "jwks": {"keys": [{
		"e": "AQAB",
		"n": "nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfG
    HrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyk
    lBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70p
    RM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe
    2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKve
    qXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
         "kty": "RSA"
      }]},
    "example_extension_parameter": "example_value"
}
```

The initial access token sent in this example as an OAuth 2.0 Bearer Token [RFC6750], but any OAuth 2.0 token type could be used.

### Client Registration using Software Statements

In addition to JSON elements, client metadata values MAY also be provided in a software statement.

The authorization server MAY ignore the software statement if it does not support this feature.

If the server supports software statements, client metadata values conveyed in the software statement MUST take precedence over those conveyed using plain JSON elements.

Software statements are included in the requesting JSON object using this OPTIONAL member:

| Parameter          | Optionality | Description                                                                                                                     |
| ------------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------- |
| software_statement | OPTIONAL    | A signed JWT string that represents a software statement containing client metadata values about the client software as claims. |

In the following example, some registration parameters are conveyed as claims in a software statement, while some values specific to the client instance are conveyed as regular parameters (with line breaks within values for display purposes only):

```http
POST /register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: server.example.com

{
	"redirect_uris": [
	"https://client.example.org/callback",
	"https://client.example.org/callback2"
    ],
    "software_statement": "eyJhbGciOiJSUzI1NiJ9.
   eyJzb2Z0d2FyZV9pZCI6IjROUkIxLTBYWkFCWkk5RTYtNVNNM1IiLCJjbGll
   bnRfbmFtZSI6IkV4YW1wbGUgU3RhdGVtZW50LWJhc2VkIENsaWVudCIsImNs
   aWVudF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLm5ldC8ifQ.
   GHfL4QNIrQwL18BSRdE595T9jbzqa06R9BT8w409x9oIcKaZo_mt15riEXHa
   zdISUvDIZhtiyNrSHQ8K4TvqWxH6uJgcmoodZdPwmWRIEYbQDLqPNxREtYn0
   5X3AR7ia4FRjQ2ojZjk5fJqJdQ-JcfxyhK-P8BAWBd6I2LLA77IG32xtbhxY
   fHX7VhuU5ProJO8uvu3Ayv4XRhLZJY4yKfmyjiiKiPNe-Ia4SMy_d_QSWxsk
   U5XIQl5Sa2YRPMbDRXttm2TfnZM1xx70DoYi8g6czz-CPGRi4SW_S2RKHIJf
   IjoI3zTJ0Y2oe0_EJAiXbL6OyF9S5tKxDXV8JIndSA",
    "scope": "read write",
    "example_extension_parameter": "example_value"
}
```

## Success Response

Upon a successful registration request, the authorization server responds with an `HTTP 201 Created` status code with a body of type `"application/json"` consisting of a single JSON object that includes the following fields:

| Parameter                  | Optionality                           | Description                                                                                                                                                                                                                                                                                |
| -------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `client_id`                | **REQUIRED**                          | The client ID string. It **SHOULD NOT** be valid for any other registered client, though the authorization server **MAY** issue the same ID to multiple instances of a registered client at its discretion.                                                                                |
| `client_secret`            | OPTIONAL                              | The client secret string, if the client is a confidential client. If issued, it **MUST** be unique for each `client_id` and **SHOULD** be unique across multiple instances using the same `client_id`. It is used by confidential clients to authenticate to the OAuth 2.0 token endpoint. |
| `client_id_issued_at`      | OPTIONAL                              | Time at which the `client_id` was issued. Represented as the number of seconds since Unix epoch time (UTC).                                                                                                                                                                                |
| `client_secret_expires_at` | REQUIRED if `client_secret` is issued | Time at which the `client_secret` expires, or `0` if it will not expire. Represented as the number of seconds since UTC.                                                                                                                                                                   |

Additionally, the authorization server MUST return all registered metadata about this client, including any fields provisioned by the authorization server itself.

The authorization server MAY reject or replace any of the client's requested metadata values submitted during the registration and substitute them with suitable values

If a software statement was used as part of the registration, its value MUST be returned unmodified in the response along with other metadata using the "software_statement" member name. Client metadata elements used from the software statement MUST also be returned directly as top-level client metadata values in the registration response (possibly with different values, since the values requested and the values used may differ). The following is a non-normative example response of a successful registration:

```http
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
    "client_id": "s6BhdRkqt3",
    "client_secret": "cf136dc3c1fc93f31185e5885805d",
    "client_id_issued_at": 2893256800,
    "client_secret_expires_at": 2893276800,
    "redirect_uris": [
	    "https://client.example.org/callback",
        "https://client.example.org/callback2"],
    "grant_types": ["authorization_code", "refresh_token"],
    "client_name": "My Example Client",
    "client_name#ja-Jpan-JP":
         "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
    "token_endpoint_auth_method": "client_secret_basic",
    "logo_uri": "https://client.example.org/logo.png",
    "jwks_uri": "https://client.example.org/my_public_keys.jwks",
    "example_extension_parameter": "example_value"
}
```

> [!NOTE]
> The client or developer can check the values in the response to determine if the registration is sufficient for use (e.g., the registered `token_endpoint_auth_method` is supported by the client software) and determine a course of action appropriate for the client software. The response to such a situation is out of scope for this spec. This process could also be aided by a service discovery protocol, such as [OpenID.Discovery], which can list a server's capabilities, allowing a client to make a more informed registration request. The use of any such system is optional and outside the scope of this spec.

## Error Response

When a registration error condition occurs, the authorization server returns an `HTTP 400` status code (unless otherwise specified) with content type `"application/json"` consisting of a JSON object describing the error in the response body.

Two members are defined for inclusion in the JSON object:

| Parameter         | Optionality | Description                                                            |
| ----------------- | ----------- | ---------------------------------------------------------------------- |
| error             | REQUIRED    | One of the error codes defined below.                                  |
| error_description | OPTIONAL    | Human-readable ASCII text description of the error used for debugging. |

Other members MAY also be included and, if they are not understood, they MUST be ignored.

### Error Codes

| Error Code                    | Description                                                                                                                                                                                                                      |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| invalid_redirect_uri          | The value of one or more redirection URIs is invalid.                                                                                                                                                                            |
| invalid_client_metadata       | The value of one of the client metadata fields is invalid and the server has rejected this request. Note that an authorization server MAY choose to substitute a valid value for any requested parameter of a client's metadata. |
| invalid_software_statement    | The software statement presented is invalid.                                                                                                                                                                                     |
| unapproved_software_statement | The software statement presented is not approved for use by this authorization server.                                                                                                                                           |

The following is a non-normative example of an error response resulting from a redirection URI that has been blacklisted by the authorization server (with line breaks within values for display purposes only):

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
    "error": "invalid_redirect_uri",
    "error_description": "The redirection URI
        http://sketchy.example.com is not allowed by this server."
}
```

The following is a non-normative example of an error response resulting from an inconsistent combination of "response_types" and "grant_types" values (with line breaks within values for display purposes only):

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
    "error": "invalid_client_metadata",
    "error_description": "The grant type 'authorization_code' must be
        registered along with the response type 'code' but found only
       'implicit' instead."
}
```
