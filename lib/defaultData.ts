import { FileNode, ArchitecturalEdge, InlineSuggestion, ContextualThread, User } from "./types";

export const CURRENT_USER: User = {
  id: "user-self",
  name: "You",
  role: "Principal Engineer",
  avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80",
  color: "#6366f1",
  isSelf: true,
};

export const MOCK_USERS: User[] = [
  {
    id: "user-1",
    name: "Sarah Lin",
    role: "Staff Infrastructure",
    avatar: "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=100&auto=format&fit=crop&q=80",
    color: "#06b6d4", // Cyan
  },
  {
    id: "user-2",
    name: "CruxAI",
    role: "Speculative Co-Pilot",
    avatar: "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=100&auto=format&fit=crop&q=80",
    color: "#8b5cf6", // Violet
  },
  {
    id: "user-3",
    name: "Marcus Vance",
    role: "Systems Architect",
    avatar: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=100&auto=format&fit=crop&q=80",
    color: "#f59e0b", // Amber
  },
];

export const INITIAL_FILES: FileNode[] = [
  {
    id: "file-auth",
    name: "auth.ts",
    path: "src/auth/auth.ts",
    language: "typescript",
    x: 60,
    y: 70,
    width: 480,
    height: 440,
    zIndex: 10,
    activePeerIds: ["user-1"],
    contributorColor: "#06b6d4",
    contributorName: "Sarah Lin",
    content: `import { SessionToken, CryptographicProof } from "./types";

/**
 * Zero-knowledge token attestation layer.
 * Validates Ed25519 signatures with subtle WebCrypto API.
 */
export async function verifyAttestation(token: SessionToken): Promise<boolean> {
  if (!token || !token.sig) {
    return false;
  }

  // Sarah L. is actively profiling signature verification latency here
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
`,
  },
  {
    id: "file-stream-syncer",
    name: "stream_syncer.ts",
    path: "src/daemon/stream_syncer.ts",
    language: "typescript",
    x: 780,
    y: 50,
    width: 580,
    height: 480,
    zIndex: 12,
    activePeerIds: ["user-self"],
    contributorColor: "#5e6ad2",
    contributorName: "Principal",
    content: `import { LocalDaemonClient, CryptographicFault } from "@crux/daemon";
import { MeshPeer, StreamFrame, SyncVector, LockTicket } from "./types";

/**
 * Crux Hybrid Stream Syncer
 * Bridges zero-latency daemon IPC memory with edge WebRTC peers.
 */
export class StreamSyncer {
  private daemon = new LocalDaemonClient({ port: 7447 });
  private activePeers = new Map<string, MeshPeer>();
  private retryAttempts = 0;

  /**
   * Acquires a distributed lock fence across active mesh participants.
   * Leverages CRDT relative positions for conflict-free state resolution.
   */
  public async acquireStreamLock(peerId: string): Promise<LockTicket> {
    const lockTimestamp = Date.now();

    // Suggestion pending below: dynamic backoff calculation
    const timeout = Math.min(this.retryAttempts * 1000, 30000);
    const fence = await this.daemon.reserveFence(timeout);

    // Synchronize peer attestation with local neural cache
    const peer = this.activePeers.get(peerId);
    if (peer && !peer.isAttested) {
      throw new CryptographicFault("Untrusted peer handshake rejected");
    }

    return {
      ticketId: fence.id,
      expiresAt: fence.expiry,
      peerOrigin: peerId,
    };
  }

  public registerPeer(peer: MeshPeer): void {
    this.activePeers.set(peer.id, peer);
  }
}
`,
  },
  {
    id: "file-database",
    name: "database.ts",
    path: "src/db/database.ts",
    language: "typescript",
    x: 1600,
    y: 70,
    width: 480,
    height: 440,
    zIndex: 11,
    activePeerIds: ["user-2"],
    contributorColor: "#8b5cf6",
    contributorName: "CruxAI",
    content: `import { LocalWriteAheadLog } from "@crux/wal";
import { SyncVector } from "./types";

// Monotonic local-first persistent write-ahead store
export const wal = new LocalWriteAheadLog({
  path: "/var/crux/wal.bin",
  fsyncIntervalMs: 50,
});

/**
 * Commits a state vector change directly to the memory-mapped ring buffer.
 * Automatically replicated to all subscribed edge workers.
 */
export async function persistStateVector(docId: string, bytes: Uint8Array): Promise<number> {
  const monotonicSequence = await wal.append({
    docId,
    payload: bytes,
    timestamp: Date.now(),
  });

  return monotonicSequence;
}

export async function replayFromSequence(fromSeq: number): Promise<AsyncIterable<Uint8Array>> {
  return wal.createStream({ startAt: fromSeq });
}
`,
  },
  {
    id: "file-types",
    name: "types.ts",
    path: "src/types.ts",
    language: "typescript",
    x: 60,
    y: 640,
    width: 480,
    height: 380,
    zIndex: 8,
    activePeerIds: ["user-1"],
    contributorColor: "#10b981",
    contributorName: "Contracts",
    content: `export interface MeshPeer {
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
`,
  },
  {
    id: "file-spatial",
    name: "spatialEngine.ts",
    path: "src/canvas/spatialEngine.ts",
    language: "typescript",
    x: 780,
    y: 640,
    width: 580,
    height: 390,
    zIndex: 9,
    activePeerIds: ["user-3"],
    contributorColor: "#f59e0b",
    contributorName: "Marcus Vance",
    content: `/**
 * Physics-based 120Hz smooth cursor lerping engine.
 * Damped harmonic oscillation prevents discrete step jumping.
 */
export class SpatialPhysicsEngine {
  private stiffness = 340;
  private damping = 30;

  calculateNextPosition(
    curr: { x: number; y: number },
    target: { x: number; y: number },
    vel: { x: number; y: number },
    dt: number
  ) {
    const ax = (target.x - curr.x) * this.stiffness - vel.x * this.damping;
    const ay = (target.y - curr.y) * this.stiffness - vel.y * this.damping;

    const nextVx = vel.x + ax * dt;
    const nextVy = vel.y + ay * dt;

    return {
      pos: { x: curr.x + nextVx * dt, y: curr.y + nextVy * dt },
      vel: { x: nextVx, y: nextVy },
    };
  }
}
`,
  },
];

export const INITIAL_EDGES: ArchitecturalEdge[] = [
  {
    id: "edge-auth-to-syncer",
    sourceNodeId: "file-auth",
    targetNodeId: "file-stream-syncer",
    label: "verifyAttestation()",
    type: "import",
    color: "#06b6d4",
    codeSymbol: "verifyAttestation()",
    changeCode: "+ verifyAttestation(token)",
    originalSnippet: "- checkToken(token: any)",
    targetSnippet: "acquireStreamLock()",
    sourceLine: 107,
    targetLine: 64,
    flowSpeed: "7.2s",
    payloadDescription: "Zero-Knowledge Ed25519 token attestation proof streamed to daemon lock ticket",
  },
  {
    id: "edge-syncer-to-db",
    sourceNodeId: "file-stream-syncer",
    targetNodeId: "file-database",
    label: "persistStateVector()",
    type: "data-flow",
    color: "#8b5cf6",
    codeSymbol: "persistStateVector()",
    changeCode: "+ persistStateVector(bytes)",
    originalSnippet: "- wal.flushSync()",
    targetSnippet: "wal.append()",
    sourceLine: 69,
    targetLine: 159,
    flowSpeed: "6.8s",
    payloadDescription: "Lock fence confirmed; state vector appended to local persistent write-ahead ring buffer",
  },
  {
    id: "edge-syncer-to-spatial",
    sourceNodeId: "file-stream-syncer",
    targetNodeId: "file-spatial",
    label: "calculateNextPosition()",
    type: "call",
    color: "#f59e0b",
    codeSymbol: "calculateNextPosition()",
    changeCode: "+ calculateNextPosition(dt)",
    originalSnippet: "- updateLinearPosition(pos)",
    targetSnippet: "120Hz lerp",
    sourceLine: 73,
    targetLine: 188,
    flowSpeed: "7.6s",
    payloadDescription: "Real-time peer position vectors stream into 120Hz damped harmonic physics engine",
  },
  {
    id: "edge-types-to-auth",
    sourceNodeId: "file-types",
    targetNodeId: "file-auth",
    label: "SessionToken",
    type: "import",
    color: "#10b981",
    codeSymbol: "SessionToken",
    changeCode: "+ export type SessionToken",
    originalSnippet: "- type RawToken = string",
    targetSnippet: "verifyAttestation()",
    sourceLine: 197,
    targetLine: 48,
    flowSpeed: "8.2s",
    payloadDescription: "Cryptographic attestation schema definition streamed to auth guard",
  },
  {
    id: "edge-types-to-syncer",
    sourceNodeId: "file-types",
    targetNodeId: "file-stream-syncer",
    label: "SyncVector",
    type: "import",
    color: "#5e6ad2",
    codeSymbol: "SyncVector",
    changeCode: "+ export interface SyncVector",
    originalSnippet: "- interface StateClock",
    targetSnippet: "acquireStreamLock()",
    sourceLine: 207,
    targetLine: 94,
    flowSpeed: "7.4s",
    payloadDescription: "Distributed logical clock schema streamed into daemon IPC engine",
  },
];

export const INITIAL_SUGGESTIONS: InlineSuggestion[] = [
  {
    id: "sug-backoff",
    fileId: "file-stream-syncer",
    author: MOCK_USERS[0], // Sarah Lin
    createdAt: Date.now() - 1000 * 60 * 12,
    from: 560,
    to: 615,
    originalText: "const timeout = 5000;",
    suggestedText: "const timeout = Math.min(this.retryAttempts * 1000, 30000);",
    description: "Replace fixed 5000ms delay with dynamic exponential backoff to avoid hammering daemon IPC socket during reconnection storms.",
    status: "pending",
  },
  {
    id: "sug-wal-fsync",
    fileId: "file-database",
    author: MOCK_USERS[1], // CruxAI
    createdAt: Date.now() - 1000 * 60 * 5,
    from: 140,
    to: 210,
    originalText: "fsyncIntervalMs: 50,",
    suggestedText: "fsyncIntervalMs: 16, // ProMotion frame-synced persistence",
    description: "Sync WAL flushes with 60Hz/120Hz display refresh intervals to guarantee zero torn frames on peer disconnect.",
    status: "pending",
  },
];

export const INITIAL_COMMENTS: ContextualThread[] = [
  {
    id: "thread-1",
    fileId: "file-stream-syncer",
    lineNumber: 17,
    charOffset: 450,
    anchorSnippet: "public async acquireStreamLock(peerId: string): Promise<LockTicket>",
    author: MOCK_USERS[0], // Sarah Lin
    createdAt: Date.now() - 1000 * 60 * 25,
    resolved: false,
    messages: [
      {
        id: "msg-1",
        author: MOCK_USERS[0],
        text: "Are we guaranteeing that `acquireStreamLock` releases the fence if a peer drops WebRTC carrier midway through the handshake?",
        createdAt: Date.now() - 1000 * 60 * 25,
        reactions: { "👀": ["user-self"], "👍": ["user-3"] },
      },
      {
        id: "msg-2",
        author: CURRENT_USER,
        text: "Yes, the daemon automatically tears down unacknowledged fences after the expiry lease (30s max). Check line 29.",
        createdAt: Date.now() - 1000 * 60 * 14,
      },
    ],
  },
  {
    id: "thread-2",
    fileId: "file-auth",
    lineNumber: 14,
    charOffset: 310,
    anchorSnippet: "const verified = await crypto.subtle.verify(",
    author: MOCK_USERS[2], // Marcus
    createdAt: Date.now() - 1000 * 60 * 45,
    resolved: false,
    messages: [
      {
        id: "msg-2-1",
        author: MOCK_USERS[2],
        text: "SubtleCrypto runs off-main-thread in Chromium & Safari. Verified benchmarks show < 0.18ms per signature verification.",
        createdAt: Date.now() - 1000 * 60 * 45,
        reactions: { "⚡": ["user-1"] },
      },
    ],
  },
];
