import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Request } from "express";

export interface Session {
  transport: StreamableHTTPServerTransport;
}

export interface User {
  id: string;
  username: string;
}

export interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method:
    "none" |
    "client_secret_basic" |
    "client_secret_post";
  client_secret?: string;
}

export interface AuthorizationCode {
  code: string;
  clientId: string;
  redirectUri: string;
  userId: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  expiresAt: number;
}

export interface RefreshToken {
  token: string;
  userId: string;
  clientId: string;
  scope: string;
  expiresAt: number;
  revoked: boolean;
}

export interface AuthenticatedUser {
  id: string;
  username: string;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}