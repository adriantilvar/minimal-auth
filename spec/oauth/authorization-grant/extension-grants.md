# Extension Grants

The `client` uses an extension grant type by specifying an absolute URI (defined by the `Authorization Server`) as the value of the `grant_type` parameter of the `/token` endpoint, and by adding any additional parameters necessary.

For example, to request an access token using the *Device Authorization Grant *as defined by [RFC8628] after the user has authorized the `client` on a separate device, the `client` makes the following HTTPS request (with extra line breaks for display purposes only):

```bash
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
&device_code=GmRhmhcxhwEzkoEqiMEg_DnyEysNkuNhszIySk9eS
&client_id=C409020731
```

If the access token request is valid and authorized, the `Authorization Server` issues an access token and optional refresh token. If the request failed client authentication or is invalid, the `Authorization Server` returns an error response.
