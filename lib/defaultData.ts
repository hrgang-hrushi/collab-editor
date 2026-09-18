import { FileNode, ArchitecturalEdge, InlineSuggestion, ContextualThread, User, ShareInvite } from "./types";

export const CURRENT_USER: User = {
  id: "user-self",
  name: "Hrushikesh Gangala",
  email: "hrushi@crux.dev",
  uid: "CRX-7447-HG",
  role: "Principal Engineer",
  avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80",
  color: "#007AFF", // Crux Blue (Accent 1)
  isSelf: true,
  accessLevel: "full",
};

export const MOCK_USERS: User[] = [
  {
    id: "user-1",
    name: "Sarah Lin",
    email: "sarah@crux.dev",
    uid: "CRX-9941-SL",
    role: "Staff Infrastructure",
    avatar: "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=100&auto=format&fit=crop&q=80",
    color: "#38b6ff", // Canva Blue (3.svg)
    accessLevel: "full",
  },
  {
    id: "user-2",
    name: "CruxAI",
    email: "copilot@crux.ai",
    uid: "CRX-0001-AI",
    role: "Speculative Co-Pilot",
    avatar: "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=100&auto=format&fit=crop&q=80",
    color: "#ff5757", // Canva Coral Crimson (5.svg)
    accessLevel: "full",
  },
  {
    id: "user-3",
    name: "Marcus Vance",
    email: "marcus@crux.dev",
    uid: "CRX-5520-MV",
    role: "Systems Architect",
    avatar: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=100&auto=format&fit=crop&q=80",
    color: "#ff914d", // Canva Orange (8.svg)
    accessLevel: "limited",
    allowedFiles: ["database.ts"],
  },
];

export const INITIAL_INVITES: ShareInvite[] = [
  {
    id: "inv-1",
    senderName: "Sarah Lin",
    senderUid: "CRX-9941-SL",
    senderEmail: "sarah@crux.dev",
    recipientUidOrEmail: "CRX-7447-HG",
    workspaceName: "crux-stream-sync",
    accessLevel: "full",
    viewerLock: false,
    timestamp: Date.now() - 1000 * 60 * 12,
    status: "pending",
  },
  {
    id: "inv-2",
    senderName: "CruxAI Copilot",
    senderUid: "CRX-0001-AI",
    senderEmail: "copilot@crux.ai",
    recipientUidOrEmail: "hrushi@crux.dev",
    workspaceName: "speculative-distributed-wal",
    accessLevel: "limited",
    allowedFiles: ["stream_syncer.ts", "database.ts"],
    allowedLineRange: { start: 1, end: 35 },
    viewerLock: false,
    timestamp: Date.now() - 1000 * 60 * 45,
    status: "pending",
  },
];

export const INITIAL_FILES: FileNode[] = [
  {
    id: "file-stream-syncer",
    name: "stream_syncer.ts",
    path: "stream_syncer.ts",
    language: "typescript",
    x: 60,
    y: 50,
    width: 580,
    height: 480,
    zIndex: 12,
    activePeerIds: ["user-self", "user-1", "user-2"],
    contributorColor: "#007AFF",
    contributorName: "Sarah L.",
    content: `import { LocalDaemonClient } from "@crux/daemon";

export class StreamSyncer {
  const timeout = 5000;
  async acquireLock() {
    await this.daemon.
  }
}
`,
  },
  {
    id: "file-database",
    name: "database.ts",
    path: "database.ts",
    language: "typescript",
    x: 720,
    y: 50,
    width: 480,
    height: 440,
    zIndex: 11,
    activePeerIds: ["user-2"],
    contributorColor: "#FF453A",
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
`,
  },
  {
    id: "file-auth",
    name: "auth.ts",
    path: "auth.ts",
    language: "typescript",
    x: 1280,
    y: 50,
    width: 480,
    height: 440,
    zIndex: 10,
    activePeerIds: ["user-1"],
    contributorColor: "#007AFF",
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
    contributorColor: "#64748b",
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
    contributorColor: "#7e889b",
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
    color: "#007AFF",
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
    color: "#FF453A",
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
    color: "#222222",
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
    color: "#007AFF",
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
    color: "#222222",
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
