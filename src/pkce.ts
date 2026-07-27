import crypto from "crypto";

export function generateS256Challenge(
    verifier: string
) {
    return crypto
        .createHash("sha256")
        .update(verifier)
        .digest("base64url");
}