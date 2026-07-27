import { NextFunction, Response } from "express";
import { AuthenticatedRequest } from "./types.js";
import { users } from "./storage.js";
import { verifyAccessToken } from "./jwt.js";

const RESOURCE_METADATA = `${process.env.ISSUER ?? "http://localhost:3000"}/.well-known/oauth-protected-resource`

export async function requireBearer(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const auth = req.header("Authorization");

  //
  // No Authorization header
  //
  if (!auth) {
    res.setHeader(
      "WWW-Authenticate",
      `Bearer resource_metadata="${RESOURCE_METADATA}"`
    );

    return res.sendStatus(401);
  }

  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "invalid_token",
    });
  }

  const token = auth.substring(7);
  try {
    const { payload } = await verifyAccessToken(token);

    const user = users.get(payload.sub as string);

    if (!user) {
      return res.sendStatus(401);
    }

    req.user = user;

    next();
  } catch (err) {
    console.error("JWT verification failed:", err);

    res.setHeader(
      "WWW-Authenticate",
      'Bearer error="invalid_token"'
    );

    return res.sendStatus(401);
  }
}