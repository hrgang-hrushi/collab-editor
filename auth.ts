import { SessionToken, CryptographicProof } from "./types";

/**
 * Zero-knowledge token attestation layer.
 * Validates Ed25519 signatures with subtle WebCrypto API.
 */
export async function verifyAttestation(token: SessionToken): Promise<boolean> {
  if (!token || !token.sig) {
    return false;
  }

  const verified = await crypto.subtle.verify(
    { name: "Ed25519" },
    token.publicKey,
    token.sig,
    token.payload
  );

  if (!verified) {
    throw new Error("Unauthorized peer signature: cryptographic attestation failed");
  }

  return true;
}

export function createSessionHeader(token: SessionToken): Record<string, string> {
  return {
    "X-Crux-Attestation": token.sigHex,
    "X-Crux-Peer-Id": token.payload.peerId,
  };
}

console.log("[Auth] Cryptographic attestation engine loaded. WebCrypto Ed25519 subsystem online.");
