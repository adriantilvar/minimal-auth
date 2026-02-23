# Protocol Endpoints

The authorization process utilizes two `Authorization Server` endpoints (HTTP resources):

- **Authorization endpoint**—used by the `client` to obtain authorization from the `Resource Owner` via user agent redirection
- **Token endpoint**—used by the `client` to exchange an authorization grant for an access token, typically with client authentication

As well as one client endpoint:

- **Redirection endpoint**—used by the `Authorization Server` to return responses containing authorization credentials to the `client` via the `Resource Owner` user agent

> [!NOTE]
> Not every authorization grant type utilizes both endpoints. Extension grant types **MAY** define additional endpoints as needed.
