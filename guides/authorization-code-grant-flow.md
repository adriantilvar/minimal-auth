# Authorization Code Grant Flow

An authorization code is a temporary credential used by the client to obtain an access token and optionally a refresh token.

This is a redirect-based flow, so the client must be capable of initiating the flow with the Resource Owner's user agent (typically a web browser) and capable of being redirected back to from the Authorization Server.

> [!NOTE] Notes
> The OAuth 2.1 spec draft supports only this method for obtaining an authorization grant.
> The Authorization Server MUST support the use of the HTTP GET method (Section 9.3.1 of [RFC9110]) for the authorization endpoint and MAY support the POST method (Section 9.3.3 of [RFC9110]) as well.
> Cross-Origin Resource Sharing [WHATWG.CORS] MUST NOT be supported at the `/authorize` endpoint, as the client does not access this endpoint directly. Instead, the client redirects the user agent to it.

1. We start by validating the HTTP request. It's not mandated how this should be done in the OAuth spec, so the Authorization Server can choose to do it either server-side or client-side. In our case, we do it before routing the user-agent to the `/authorize` endpoint, through a middleware function:

```ts
// routes/authorize/index.tsx

// NOTE: The fragment component is stripped by the server, so it cannot end up to our route
const authorizationRequestValidation = createMiddleware().server(async ({ next, request }) => {
  const search = new URL(request.url).searchParams; // search params are always strings

  /**
   * If the `client_id` is missing or invalid (no client with that id exists), we
   * cannot validate the `redirect_uri`. We must inform the Resource Owner of the
   * error, but we cannot redirect the user-agent to an untrusted redirect URI.
   *
   * The OAuth spec does not mandate how the Resource Owner should be informed in
   * this case, so the implementation is up to the Authorization Server. In our
   * case, we redirect the user-agent to an error page that we host.
   */

  const [clientId] = getUniqueSearchParam(search, "client_id");
  if (!clientId) {
    throw redirect({
      href: createUrl(ERROR_ENDPOINT, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description:
            "Request URI must include a `client_id` query parameter. It must not be included more than once.",
          // An error_uri can be added as well
        },
      }).toString(),
    });
  }

  const client = await findOAuthClientById(clientId);
  if (!client) {
    throw redirect({
      href: createUrl(ERROR_ENDPOINT, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description:
            "No client is registered with the provided `client_id`. You need to register the client before requesting an authorization grant.",
        },
      }).toString(),
    });
  }

  const [redirectUri] = getUniqueSearchParam(search, "redirect_uri");
  if (!redirectUri) {
    // NOTE: Can allow the client to omit `redirect_uri` if it has only one redirect URI registered with the AS
    throw redirect({
      href: createUrl(ERROR_ENDPOINT, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description:
            "The request URI must include a `redirect_uri` query parameter. It must not be included more than once.",
        },
      }).toString(),
    });
  }

  if (!isValidRedirectUri(redirectUri, client)) {
    throw redirect({
      href: createUrl(ERROR_ENDPOINT, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description: "The provided redirect URI is not registered for this client or is otherwise invalid.",
        },
      }).toString(),
    });
  }

  // The client must have passed a valid `redirect_uri`, or the client has only one registered redirect URI
  const safeRedirectUri = redirectUri ?? client.redirectUris[0];

  /**
   * Once we have a validated redirect URI, we can inform the client of any error by
   * redirecting the user-agent to the redirect URI with the relevant error query
   * parameters (specified by the OAuth spec).
   */

  const [state, stateError] = getUniqueSearchParam(search, "response_type");
  if (stateError?.reason === "duplicate_param") {
    throw redirect({
      href: createUrl(safeRedirectUri, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description:
            "The `state` query parameter is optional. However, if provided, it must not be included more than once.",
          iss: AUTHORIZATION_SERVER_ID,
        },
      }).toString(),
    });
  }

  const [responseType] = getUniqueSearchParam(search, "response_type");
  if (!responseType) {
    throw redirect({
      href: createUrl(safeRedirectUri, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description:
            "Request URI must include a `response_type` query parameter. It must not be included more than once.",
          iss: AUTHORIZATION_SERVER_ID,
          state,
        },
      }).toString(),
    });
  }

  if (responseType !== "code") {
    throw redirect({
      href: createUrl(safeRedirectUri, {
        query: {
          error: AuthorizationErrorCodes.UNSUPPORTED_RESPONSE_TYPE,
          error_description:
            "This server can only provide authorization code grants. If you wish to obtain an authorization code, you must set the value of the `response_type` parameter to 'code'.",
          iss: AUTHORIZATION_SERVER_ID,
          state,
        },
      }).toString(),
    });
  }

  const [codeChallenge] = getUniqueSearchParam(search, "code_challenge");
  if (!codeChallenge) {
    throw redirect({
      href: createUrl(safeRedirectUri, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description:
            "Request URI must include a `code_challenge` query parameter. It must not be included more than once.",
          iss: AUTHORIZATION_SERVER_ID,
          state,
        },
      }).toString(),
    });
  }

  const [codeChallengeMethod] = getUniqueSearchParam(search, "code_challenge_method");
  if (!codeChallengeMethod) {
    throw redirect({
      href: createUrl(safeRedirectUri, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description:
            "Request URI must include a `code_challenge_method` query parameter. It must not be included more than once.",
          iss: AUTHORIZATION_SERVER_ID,
          state,
        },
      }).toString(),
    });
  }

  if (!isValidCodeChallengeMethod(codeChallengeMethod)) {
    throw redirect({
      href: createUrl(safeRedirectUri, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description: "The provided `code_challenge_method` is not valid.",
          iss: AUTHORIZATION_SERVER_ID,
          state,
        },
      }).toString(),
    });
  }

  if (!canRequestAuthorizationCodeGrant(client)) {
    throw redirect({
      href: createUrl(safeRedirectUri, {
        query: {
          error: AuthorizationErrorCodes.UNAUTHORIZED_CLIENT,
          error_description: "This client is not allowed to request an authorization code grant.",
          iss: AUTHORIZATION_SERVER_ID,
          state,
        },
      }).toString(),
    });
  }

  const [scope, error] = getUniqueSearchParam(search, "scope");
  if (error?.reason === "duplicate_param") {
    throw redirect({
      href: createUrl(safeRedirectUri, {
        query: {
          error: AuthorizationErrorCodes.INVALID_REQUEST,
          error_description:
            "The `scope` query parameter is optional. However, if provided, it must not be included more than once.",
          iss: AUTHORIZATION_SERVER_ID,
          state,
        },
      }).toString(),
    });
  }

  // NOTE: The Authorization Server can ignore the scope entirely
  if (scope && !isValidScope(scope)) {
    throw redirect({
      href: createUrl(safeRedirectUri, {
        query: {
          error: AuthorizationErrorCodes.INVALID_SCOPE,
          error_description: "The provided `scope` is not valid",
          iss: AUTHORIZATION_SERVER_ID,
          state,
        },
      }).toString(),
    });
  }

  // At this point we can start the authorization code grant flow
  return next();
});
```

2. We have to make sure the middleware runs before the user-agent gets routed. In TanStack Start, this is one way of doing it:

```tsx
// routes/authorize/index.tsx

// We enforce PKCE is across all clients to bolster security
type AuthorizationRouteParams = {
  client_id: string;
  redirect_uri: string;
  response_type: "code";
  code_challenge: string;
  code_challenge_method: CodeChallengeMethod;
  scope?: Scope;
  state?: string;
};

export const Route = createFileRoute("/authorize/")({
  server: {
    // We run the client validation middleware before the request gets routed
    handlers: ({ createHandlers }) => createHandlers({ GET: { middleware: [authorizationRequestValidation] } }),
  },
  // The request is already validated, but we do this to work with type-safe search params
  validateSearch: (search: Record<string, unknown>): AuthorizationRouteParams => {
    /* manual validation or use Zod, Valibot, etc. */
  },
  component: AuthorizationPage,
});
```

3. At this point the request is validated and the user-agent is routed to the `/authorize` endpoint. The first thing we need to do is to make sure the Resource Owner is authenticated, otherwise we authenticate them:

```ts
// routes/authorize/index.tsx

export const Route = createFileRoute("/authorize/")({
  server: {
    handlers: ({ createHandlers }) => createHandlers({ GET: { middleware: [authorizationRequestValidation] } }),
  },
  validateSearch: (search: Record<string, unknown>): AuthorizationRouteParams => {
    /* manual validation or use Zod, Valibot, etc. */
  },
  beforeLoad: ({ context, location }) => {
    // The user must be authenticated to access this route
    if (!isUserAuthenticated(context)) {
      throw redirect({
        to: "/login",
        search: { redirect: location.href }, // Save current location for redirect after login
      });
    }
  },
  // After login, the user is redirected back and the AuthorizationPage gets rendered
  component: AuthorizationPage,
});
```

4. Now that the Resource Owner is authenticated, we ask them for (granular) consent:

```tsx
function AuthorizationPage() {
  const {
    client_id,
    code_challenge,
    code_challenge_method,
    redirect_uri,
    scope = DEFAULT_SCOPE,
    state,
  } = Route.useSearch();
  const permissions: Permission[] = getPermissions(scope);
  const selectedPermissions = new Set<PermissionName>(permissions.map((p) => p.name));

  function togglePermission(permission: PermissionName) {
    if (selectedPermissions.has(permission)) selectedPermissions.delete(permission);
    else selectedPermissions.add(permission);
  }

  // The user-agent gets redirected to the provided redirect URI, which contains information about the error
  function denyAuthorizationRequest() {
    externalRedirect(
      createUrl(redirect_uri, {
        query: {
          error: AuthorizationErrorCodes.ACCESS_DENIED,
          error_description: "The resource owner has denied the authorization code request",
          iss: AUTHORIZATION_SERVER_ID,
          state,
        },
      }).toString(),
    );
  }

  // The user-agent gets redirected to the provided redirect URI, which contains the authorization code
  async function approveAuthorizationRequest(e: React.SubmitEvent<HTMLFormElement>) {
    e.preventDefault();

    // Get the granular scope approved by the Resource Owner (user)
    const approvedScope = [...selectedPermissions].join(" ");

    // Generate the authorization code
    const code = generateCode();

    // Store the code, so that it can be verified when the client requests an access token
    await registerAuthorizationCode({
      code,
      scope: approvedScope,
      clientId: client_id,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method as CodeChallengeMethod,
      userAgent: getUserAgent(),
      isUsed: false,
      expiresAt: Date.now() + DEFAULT_AUTHORIZATION_CODE_EXPIRATION_S,
    });

    // Success! Redirect the user-agent to the client redirect URI
    externalRedirect(
      createUrl(redirect_uri, {
        query: {
          code,
          state,
          iss: AUTHORIZATION_SERVER_ID,
        },
      }).toString(),
    );
  }

  return (
    <div>
      <h2>Authorize Application</h2>

      <AuthorizationForm onSubmit={approveAuthorizationRequest}>
        <ul>
          {permissions.map(({ id, name, description }) => (
            // Present the requested permissions to the Resource Owner (user) and allow granular approval
            <li key={id}>
              <Checkbox
                label={name}
                description={description}
                checked={selectedPermissions.has(name)}
                onChange={() => togglePermission(name)}
              />
            </li>
          ))}
        </ul>

        <button
          // The Resource Owner (user) denies all permissions
          type="button"
          onClick={denyAuthorizationRequest}
        >
          Deny
        </button>

        <button
          // The Resource Owner (user) has granted some permissions
          type="submit"
        >
          Approve
        </button>
      </AuthorizationForm>
    </div>
  );
}
```

These are all the steps that you need to implement an authorization endpoint for an OAuth Authorization Server. What might differ is how you choose to inform the Resource Owner of some errors, how thorough you are with the validation, and any other interactions with your system that are beyond the scope of OAuth.
