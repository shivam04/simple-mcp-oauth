import {
  Session,
  User,
  OAuthClient,
  AuthorizationCode,
  RefreshToken,
} from "./types.js";
import crypto from "crypto";
import { hashToken } from "./utils.js";

export const sessions = new Map<string, Session>();

export const users = new Map<string, User>();

export const oauthClients = new Map<string, OAuthClient>();

export const authorizationCodes = new Map<string, AuthorizationCode>();

export const refreshTokens = new Map<string, RefreshToken>();


export function createAuthorizationCode() {
  return crypto.randomBytes(32).toString("hex");
}

export function saveAuthorizationCode(
  code: AuthorizationCode
) {
  const hash = hashToken(code.code);
  authorizationCodes.set(hash, code);
}

export function getAuthorizationCode(code: string) {
  const hash = hashToken(code);
  return authorizationCodes.get(hash);
}

export function deleteAuthorizationCode(code: string) {
  const hash = hashToken(code);
  authorizationCodes.delete(hash);
}

export function saveRefreshToken(
    token: RefreshToken
) {
    const hash = hashToken(token.token);
    refreshTokens.set(hash, token);
}

export function getRefreshToken(token: string) {
  const hash = hashToken(token);
  return refreshTokens.get(hash);
}

export function deleteRefreshToken(token: string) {
  refreshTokens.delete(hashToken(token));
}

export function revokeRefreshToken(tokenId: string) {
  const hash = hashToken(tokenId);
  const token = refreshTokens.get(hash);
  if (!token) {
    return false;
  }
  token.revoked = true;
  return true;
}

export function getClient(clientId: string) {
  return oauthClients.get(clientId);
}

users.set("1", {
  id: "1",
  username: "shivam",
});


users.set("2", {
  id: "2",
  username: "pragya",
});



users.set("3", {
  id: "3",
  username: "shubham",
});



users.set("4", {
  id: "4",
  username: "pratik",
});