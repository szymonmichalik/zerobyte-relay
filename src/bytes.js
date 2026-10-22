// Byte helpers shared by the protocol core, push and ICE. Web APIs only, so the
// same code runs on Workers and on Node.

export const utf8 = new TextEncoder();

export function fromBase64(text) {
  const binary = atob(text);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function toBase64(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Unpadded base64url (RFC 4648 §5). */
export function fromBase64url(text) {
  const padded = text.replaceAll("-", "+").replaceAll("_", "/");
  return fromBase64(padded + "=".repeat((4 - (padded.length % 4)) % 4));
}

export function toBase64url(bytes) {
  return toBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function toHex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
