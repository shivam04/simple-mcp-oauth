import crypto from "crypto";

export function randomToken(
    bytes = 32
) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

export function hashToken(value: string): string {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
