import { Router } from "express";
import { 
  createAuthorizationCode, 
  deleteAuthorizationCode, 
  deleteRefreshToken, 
  getAuthorizationCode, 
  getRefreshToken, 
  oauthClients, 
  saveAuthorizationCode, 
  saveRefreshToken, 
  users 
} from "./storage";
import crypto from "crypto";
import { generateS256Challenge } from "./pkce";
import { escapeHtml, randomToken } from "./utils";
import { getJwks, issueAccessToken, verifyAccessToken } from "./jwt";
import { authenticateClient } from "./clientAuth";

export const oauthRouter = Router();

/**
 * RFC 9728 OAuth Protected Resource Metadata
 */
oauthRouter.get(
  "/.well-known/oauth-protected-resource",
  (req, res) => {
    const issuer =
      "http://localhost:3000";
    res.json({
      resource:
        `${issuer}/mcp`,
      authorization_servers: [
        issuer,
      ],
    });
  }
);

/**
 * RFC 8414 OAuth Authorization Server Metadata
 */
oauthRouter.get(
  "/.well-known/oauth-authorization-server",
  (req, res) => {
    const issuer = "http://localhost:3000";
    res.json({
      issuer,
      authorization_endpoint:
        `${issuer}/oauth/authorize`,
      token_endpoint:
        `${issuer}/oauth/token`,
      registration_endpoint:
        `${issuer}/oauth/register`,
      revocation_endpoint:
        `${issuer}/oauth/revoke`,
      introspection_endpoint:
        `${issuer}/oauth/introspect`,
      jwks_uri:
        `${issuer}/.well-known/jwks.json`,
      response_types_supported: [
        "code",
      ],
      grant_types_supported: [
        "authorization_code",
        "refresh_token",
      ],
      code_challenge_methods_supported: [
        "S256",
      ],
      token_endpoint_auth_methods_supported: [
        "none",
      ],
      scopes_supported: [
        "mcp",
      ],
      response_modes_supported: [
        "query",
      ],
    });
  }
);

oauthRouter.post("/oauth/register", (req, res) => {
  const {
      client_name,
      redirect_uris,
      grant_types,
      response_types,
      token_endpoint_auth_method,
    } = req.body;

    if (!client_name) {
      return res.status(400).json({
        error: "invalid_client_metadata",
      });
    }

    if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      return res.status(400).json({
        error: "invalid_redirect_uri",
      });
    }

    const client_id = crypto.randomUUID();

    const authMethod = token_endpoint_auth_method ?? "none";

    const client = {
      client_id,
      client_name,
      redirect_uris,
      grant_types,
      response_types,
      token_endpoint_auth_method:
        authMethod,
      client_secret:
        authMethod === "none"
          ? undefined
          : crypto.randomUUID()
    };

    oauthClients.set(client_id, client);

    console.log(client);

    res.status(201).json({
      client_id: client.client_id,
      client_secret: client.client_secret,
      client_name: client.client_name,
      redirect_uris: client.redirect_uris
    });
});


oauthRouter.get("/oauth/authorize", (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    state,
    scope,
    code_challenge,
    code_challenge_method,
  } = req.query as Record<string, string>;

  //
  // Validate request
  //

  if (response_type !== "code") {
    return res.status(400).json({
      error: "unsupported_response_type",
    });
  }

  if (!client_id) {
    return res.status(400).json({
      error: "invalid_client",
    });
  }

  const client = oauthClients.get(client_id);

  if (!client) {
    return res.status(400).json({
      error: "invalid_client",
    });
  }

  if (!redirect_uri) {
    return res.status(400).json({
      error: "invalid_request",
    });
  }

  if (
    !client.redirect_uris.includes(
      redirect_uri
    )
  ) {
    return res.status(400).json({
      error: "invalid_redirect_uri",
    });
  }

  //
  // PKCE Required
  //

  if (!code_challenge) {
    return res.status(400).json({
      error: "invalid_request",
      error_description:
        "Missing code_challenge",
    });
  }

  if (code_challenge_method !== "S256") {
    return res.status(400).json({
      error: "invalid_request",
      error_description:
        "Only S256 is supported",
    });
  }

  //
  // Fake Login
  //

  if (!req.session.userId) {
    const next =
      encodeURIComponent(
        req.originalUrl
      );

    return res.redirect(
      `/oauth/login?next=${next}`
    );
  }

  const user = users.get(
    req.session.userId
  );

  if (!user) {
    req.session.destroy(() => {});
    return res.redirect(
      `/oauth/login`
    );
  }

  //
  // Generate Code
  //

  const code = createAuthorizationCode()

  saveAuthorizationCode({
    code,
    clientId: client.client_id,
    userId: user.id,
    redirectUri: redirect_uri,
    scope: scope ?? "mcp",
    codeChallenge: code_challenge,
    codeChallengeMethod: "S256",
    expiresAt:
      Date.now() + 5 * 60 * 1000,
  });

  console.log(
    "Authorization Code:",
    code
  );

  //
  // Redirect
  //

  const redirect = new URL(
    redirect_uri
  );

  redirect.searchParams.set(
    "code",
    code
  );

  if (state) {
    redirect.searchParams.set(
      "state",
      state
    );
  }

  return res.redirect(
    redirect.toString()
  );
});

oauthRouter.post(
    "/oauth/token",
    async (req, res) => {

      const client = authenticateClient(req);

      if (!client) {
        return res.status(401)
          .json({
            error: "invalid_client"
          })
      }

      const grantType = req.body.grant_type;

      switch (grantType) {
        case "authorization_code":
          return await exchangeAuthorizationCode(req, res);

        case "refresh_token":
          return await exchangeRefreshToken(req, res);

        default:
          return res.status(400).json({
            error: "unsupported_grant_type",
          });
      }
    }
);

async function exchangeAuthorizationCode(req: any, res: any) {
  const {
        grant_type,
        code,
        redirect_uri,
        client_id,
        code_verifier,
  } = req.body;

  if (
      grant_type !==
      "authorization_code"
  ) {
      return res.status(400).json({
          error:
              "unsupported_grant_type",
      });
  }

  const authCode =
      getAuthorizationCode(code);

  if (!authCode) {
      return res.status(400).json({
          error: "invalid_grant",
      });
  }

  if (
      authCode.expiresAt <
      Date.now()
  ) {
      deleteAuthorizationCode(
          code
      );

      return res.status(400).json({
          error: "invalid_grant",
      });
  }

  if (
      authCode.clientId !==
      client_id
  ) {
      return res.status(400).json({
          error: "invalid_client",
      });
  }

  if (
      authCode.redirectUri !==
      redirect_uri
  ) {
      return res.status(400).json({
          error: "invalid_grant",
      });
  }

  if (!code_verifier) {
      return res.status(400).json({
          error: "invalid_request",
      });
  }

  const expectedChallenge =
      generateS256Challenge(
          code_verifier
      );

  if (
      expectedChallenge !==
      authCode.codeChallenge
  ) {
      return res.status(400).json({
          error: "invalid_grant",
      });
  }

  deleteAuthorizationCode(
      code
  );

  const accessToken = await issueAccessToken(
    authCode.userId,
    authCode.clientId,
    authCode.scope
  );

  const refreshToken =
      randomToken(32);

  saveRefreshToken({
      token: refreshToken,
      userId: authCode.userId,
      clientId:
          authCode.clientId,
      scope: authCode.scope,
      expiresAt: Date.now() + 30 * 24 * 3600 * 1000,
      revoked: false
  });

  return res.json({
      token_type: "Bearer",
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      scope: authCode.scope,
  });
}

async function exchangeRefreshToken(req: any, res: any) {

  const {
    refresh_token,
    client_id,
  } = req.body;

  if (!refresh_token) {
    return res.status(400).json({
      error: "invalid_request",
    });
  }

  const stored = getRefreshToken(refresh_token);

  if (!stored) {
    return res.status(400).json({
      error: "invalid_grant",
    });
  }

  if (stored.revoked) {
    return res.status(400).json({
      error:"invalid_grant"
    });
  }

  if (stored.expiresAt < Date.now()) {
    stored.revoked = true;
    return res.status(400).json({
      error: "invalid_grant",
    });
  }

  if (stored.clientId !== client_id) {
    return res.status(400).json({
      error: "invalid_client",
    });
  }

  //
  // Refresh Token Rotation
  //

  stored.revoked = true;

  const newAccessToken = await issueAccessToken(
    stored.userId,
    stored.clientId,
    stored.scope
  )

  const newRefreshToken = randomToken();

  saveRefreshToken({
    token: newRefreshToken,
    userId: stored.userId,
    clientId: stored.clientId,
    scope: stored.scope,
    expiresAt: Date.now() + 30 * 24 * 3600 * 1000,
    revoked: false
  });

  return res.json({
    token_type: "Bearer",
    access_token: newAccessToken,
    refresh_token: newRefreshToken,
    expires_in: 3600,
    scope: stored.scope,
  });
}

oauthRouter.get(
  "/.well-known/jwks.json",
  async (req, res) => {
    const jwks = await getJwks();
    res.json(jwks);
  }
);


oauthRouter.get("/oauth/login", (req, res) => {
  const next = escapeHtml(
    (req.query.next as string) ?? "/"
  );

  res.send(`
    <html>
    <body>
      <h2>Simple MCP Login</h2>
      <form method="POST" action="/login">
        <input type="hidden" name="next" value="${next}" />
        <input
          name="username"
          placeholder="Username"
        />
        <br/>
        <input
          name="password"
          type="password"
          placeholder="Password"
        />
        <br/><br/>
        <button>
          Login
        </button>
      </form>
    </body>
    </html>
  `);
});

oauthRouter.post("/login", (req, res) => {
  const {
    username,
    password,
  } = req.body;

  const user =
    Array.from(users.values())
      .find(u =>
        u.username === username
      );

  if (!user) {
    return res.status(401)
      .send("Invalid user");
  }

  if (password !== "password") {
    return res.status(401)
      .send("Invalid password");
  }

  const next =
    req.body.next ??
    "/";

  console.log(`Next: ${next}`);

  req.session.regenerate((err) => {
    if (err) {
      return res.status(500)
        .send("Session error");
    }

    req.session.userId = user.id;

    req.session.save((err) => {
      if (err) {
        return res.status(500)
          .send("Session save error");
      }

      res.redirect(next as string);
    });
  });
});


oauthRouter.get("/oauth/consent", (req, res) => {

  res.send(`
    <html>
      <body>
        <h2>Application Access</h2>
        <p>
          Application:
          ${req.query.client_id}
        </p>
        <p>
          Scope:
          ${req.query.scope}
        </p>
        <form
        method="POST"
        action="/oauth/consent"
        >
          <input
          type="hidden"
          name="client_id"
          value="${req.query.client_id}"
          />
          <input
          type="hidden"
          name="scope"
          value="${req.query.scope}"
          />
          <button
          name="action"
          value="approve"
          >
            Approve
          </button>
          <button
          name="action"
          value="deny"
          >
            Deny
          </button>
        </form>
      </body>
    </html>
    `);
});

oauthRouter.post("/oauth/revoke", (req, res) => {
  const { token, token_type_hint } = req.body;

  if (!token) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "token is required",
    });
  }

  // RFC 7009: Unknown tokens should still return 200 OK.
  if (
    !token_type_hint ||
    token_type_hint === "refresh_token"
  ) {
    deleteRefreshToken(token);
  }

  // JWT access tokens cannot be revoked unless
  // you maintain a deny-list.

  return res.status(200).end();
});


oauthRouter.post(
  "/oauth/introspect",
  async (req, res) => {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "token is required",
      });
    }
    try {
      const { payload } =
        await verifyAccessToken(token);

      return res.json({
        active: true,
        scope: payload.scope,
        client_id: payload.aud,
        sub: payload.sub,
        iss: payload.iss,
        exp: payload.exp,
        iat: payload.iat,
        token_type: "Bearer",
      });
    } catch {
      return res.json({
        active: false,
      });
    }
  }
);

oauthRouter.post(
  "/logout",
  (req, res) => {

    req.session.destroy((err) => {

      if (err) {
        return res.status(500)
          .send("Logout failed");
      }


      res.clearCookie(
        "connect.sid"
      );


      res.redirect(
        "/oauth/login"
      );

    });

  }
);