```text
                     MCP Client
                (ChatGPT / Claude)
                         |
                         |
                         | 1. Connect to MCP Server
                         |
                         v
              +----------------------+
              |      MCP Server      |
              |      /mcp endpoint   |
              +----------------------+
                         |
                         |
                         | 2. No valid Access Token
                         |
                         v
        +--------------------------------------+
        | OAuth Protected Resource Metadata    |
        | /.well-known/oauth-protected-resource|
        +--------------------------------------+
                         |
                         v
        +--------------------------------------+
        | OAuth Authorization Server Metadata  |
        | /.well-known/oauth-authorization...  |
        +--------------------------------------+
                         |
                         v
              +----------------------+
              | OAuth Authorization  |
              | Server               |
              +----------------------+
                         |
                         |
                         | 3. Dynamic Client Registration
                         |
                         v
              POST /oauth/register
                         |
                         |
                         v
              Client ID Created
                         |
                         |
                         | 4. Authorization Request
                         |
                         v
              GET /oauth/authorize
                         |
                         |
                         v
              +----------------------+
              | Login UI             |
              +----------------------+
                         |
                         |
                         | username/password
                         |
                         v
              sessionMiddleware
                         |
                         |
                         | Create User Session
                         |
                         v
              +----------------------+
              | Consent UI            |
              +----------------------+
                         |
                         |
                         | Approve scopes
                         |
                         v
              Generate Authorization Code
                         |
                         |
                         | Store:
                         | hash(code)
                         | userId
                         | clientId
                         | PKCE challenge
                         |
                         v
              Redirect to Client
                         |
                         |
                         | code=xyz
                         |
                         v
              +----------------------+
              | MCP Client           |
              +----------------------+
                         |
                         |
                         | 5. Exchange Code
                         |
                         v
              POST /oauth/token
                         |
                         |
                         | code
                         | code_verifier
                         |
                         v
              Validate:
              - client
              - redirect_uri
              - PKCE
              - authorization code
                         |
                         v
              Issue Tokens
                         |
                         |
        +----------------+----------------+
        |                                 |
        v                                 v

 JWT Access Token                 Refresh Token
 (RS256 signed)                  (rotating)

        |                                 |
        |                                 |
        |                                 |
        v                                 v

   MCP Client Stores             Store:
                                  hash(refresh_token)
                                  userId
                                  clientId


                         |
                         |
                         | 6. Call MCP Tool
                         |
                         v

              POST /mcp
              Authorization:
              Bearer <JWT>


                         |
                         |
                         v

              MCP Server JWT Verify
                         |
                         |
                         v

              Fetch JWKS
              /.well-known/jwks.json
                         |
                         |
                         v

              Verify:
              - Signature
              - exp
              - issuer
              - audience


                         |
                         |
                         v

              Execute MCP Tool
                         |
                         |
                         v

              Return MCP Response


================================================


          Refresh Token Flow

MCP Client
    |
    |
    | refresh_token = R1
    |
    v

POST /oauth/token

grant_type=refresh_token


    |
    v

OAuth Server

    |
    | lookup hash(R1)
    |
    v

Validate:
- exists
- not revoked
- not expired


    |
    v

Revoke R1


    |
    v

Generate:

Access Token A2
Refresh Token R2


    |
    v

Return:

{
 access_token: A2,
 refresh_token: R2
}


================================================


          Token Revocation Flow


Client
  |
  |
  | POST /oauth/revoke
  |
  v

OAuth Server

  |
  | revoke refresh token
  |
  v

Token marked revoked


================================================


          Token Introspection Flow


Resource Server
       |
       |
       | POST /oauth/introspect
       |
       v

OAuth Server

       |
       | Validate token
       |
       v

{
 active: true,
 client_id,
 user_id,
 scope
}
```
