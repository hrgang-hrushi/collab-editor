export interface MeshPeer {
  id: string;
  name: string;
  isAttested: boolean;
  latencyMs: number;
}

export interface LockTicket {
  ticketId: string;
  expiresAt: number;
  peerOrigin: string;
}

export interface SessionToken {
  publicKey: CryptoKey;
  sig: ArrayBuffer;
  sigHex: string;
  payload: {
    peerId: string;
    issuedAt: number;
  };
}

export interface SyncVector {
  clock: Record<string, number>;
  documentId: string;
}
