import { readFile } from "node:fs/promises";
import {
  SignJWT,
  jwtVerify,
  exportJWK,
  type JWK,
  importPKCS8,
  importSPKI,
} from "jose";
import path from "path";

const ISSUER = process.env.ISSUER ?? "http://localhost:3000";
const KEY_ID = "simple-mcp-key-1";

// jose v6 returns CryptoKey
let privateKey: CryptoKey;
let publicKey: CryptoKey;

export async function initializeJwt() {
  const privatePem = await readFile(
    path.join(process.cwd(), "keys", "private.pem"),
    "utf8"
  );
  const publicPem = await readFile(
    path.join(process.cwd(), "keys", "public.pem"),
    "utf8"
  );

  privateKey = await importPKCS8(
    privatePem,
    "RS256"
  );

  publicKey = await importSPKI(
    publicPem,
    "RS256"
  );

  console.log("Loaded RSA signing keys");

}

export async function issueAccessToken(
  userId: string,
  clientId: string,
  scope: string
) {
  console.log(`process env ISSUER ${ISSUER}`)
  return await new SignJWT({ scope })
    .setProtectedHeader({
      alg: "RS256",
      kid: KEY_ID,
    })
    .setIssuer(ISSUER)
    .setAudience(clientId)
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
}

export async function verifyAccessToken(token: string) {
  return jwtVerify(token, publicKey, {
    issuer: ISSUER,
  });
}

export async function getJwks() {
  const jwk: JWK = await exportJWK(publicKey);

  return {
    keys: [
      {
        ...jwk,
        kid: KEY_ID,
        alg: "RS256",
        use: "sig",
      },
    ],
  };
}