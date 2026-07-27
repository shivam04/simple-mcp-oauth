import { getClient } from "./storage";

export function authenticateClient(
  req: any
) {

  const auth =
    req.headers.authorization;

  let clientId;
  let clientSecret;

  // client_secret_basic

  if (auth?.startsWith("Basic ")) {
    const encoded =
      auth.substring(6);
    const decoded =
      Buffer
        .from(encoded, "base64")
        .toString();
    [
      clientId,
      clientSecret
    ] =
      decoded.split(":");
  }

  // client_secret_post

  if (!clientId) {
    clientId =
      req.body.client_id;
    clientSecret =
      req.body.client_secret;
  }
  if (!clientId) {
    return null;
  }
  const client =
    getClient(clientId);
  if (!client) {
    return null;
  }
  if (
    client.token_endpoint_auth_method ===
    "none"
  ) {
    return client;
  }
  if (
    client.client_secret !==
    clientSecret
  ) {
    return null;
  }
  return client;
}