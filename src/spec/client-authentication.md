# Client Authentication

**Client authentication** is used for:

- Enforcing the binding of refresh tokens and authorization codes to the `client` they were issued to. It adds an additional layer of security when authorization code is transmitted to the redirection endpoint over an insecure channel.
- Recovering from a compromised `client` by disabling the `client` or changing its credentials, thus preventing an attacker from abusing stolen refreshed tokens. Changing a single set of client credentials is significantly faster than revoking an entire set of refresh tokens.
- Implementing authentication management best practices, which require _periodic credential rotation_. Rotation of an entire set of refresh tokens can be challenging, while rotation of a single set of client credentials is significantly easier.
