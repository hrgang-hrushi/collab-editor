import { FileNode, ArchitecturalEdge, InlineSuggestion, ContextualThread, User, ShareInvite, LibraryPackage, WorkspaceTemplate, FileRevision } from "./types";

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
    y: 60,
    width: 560,
    height: 460,
    zIndex: 12,
    activePeerIds: ["user-self", "user-2"],
    contributorColor: "#007AFF",
    contributorName: "Sarah L.",
    content: `import { LocalDaemonClient } from "@crux/daemon";

export class StreamSyncer {
  timeout = 5000;
  daemon = new LocalDaemonClient({ port: 7447 });

  async acquireLock(channel = "stream-mesh-primary") {
    console.log(\`[StreamSyncer] Requesting mutual exclusion lock for: \${channel}...\`);
    const ticket = await this.daemon.acquireLock(channel);
    console.log(\`[StreamSyncer] Lock acquired successfully! Ticket: \${ticket.ticketId}\`);
    return ticket;
  }
}

const syncer = new StreamSyncer();
syncer.acquireLock().then((ticket) => {
  console.log(\`[StreamSyncer] Mesh channel ready on origin: \${ticket.origin}\`);
});
`,
  },
  {
    id: "file-database",
    name: "database.ts",
    path: "database.ts",
    language: "typescript",
    x: 780,
    y: 60,
    width: 500,
    height: 460,
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

// Verification write
persistStateVector("doc-primary", new Uint8Array([1, 0, 1])).then((seq) => {
  console.log(\`[WAL] Committed frame sequence #\${seq} to ring buffer\`);
});
`,
  },
  {
    id: "file-auth",
    name: "auth.ts",
    path: "auth.ts",
    language: "typescript",
    x: 1440,
    y: 60,
    width: 500,
    height: 460,
    zIndex: 10,
    activePeerIds: ["user-1"],
    contributorColor: "#38b6ff",
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

console.log("[Auth] Cryptographic attestation engine loaded. WebCrypto Ed25519 subsystem online.");
`,
  },
  {
    id: "file-types",
    name: "types.ts",
    path: "src/types.ts",
    language: "typescript",
    x: 60,
    y: 640,
    width: 500,
    height: 400,
    zIndex: 8,
    activePeerIds: ["user-1"],
    contributorColor: "#00E5FF",
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
    width: 560,
    height: 400,
    zIndex: 9,
    activePeerIds: ["user-3"],
    contributorColor: "#ff914d",
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

const engine = new SpatialPhysicsEngine();
const step = engine.calculateNextPosition({ x: 0, y: 0 }, { x: 100, y: 100 }, { x: 0, y: 0 }, 0.016);
console.log(\`[SpatialPhysicsEngine] 120Hz lerp initialized. Next vector: (\${step.pos.x.toFixed(2)}, \${step.pos.y.toFixed(2)})\`);
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
    color: "#ff914d",
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
    color: "#00E5FF",
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
    color: "#00E5FF",
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
    lineNumber: 5,
    charOffset: 120,
    anchorSnippet: "async acquireLock() {",
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

export const INITIAL_LIBRARIES: LibraryPackage[] = [
  {
    id: "lib-crux-daemon",
    name: "@crux/daemon",
    version: "2.4.0",
    description: "Crux distributed mesh daemon SDK for peer synchronization & edge compute",
    importSnippet: 'import { LocalDaemonClient, CruxCluster, broadcastMesh } from "@crux/daemon";',
    category: "core",
    isInstalled: true,
    exports: ["LocalDaemonClient", "CruxCluster", "broadcastMesh", "subscribeChannel", "dispatchSignal", "createSyncStream"],
  },
  {
    id: "lib-yjs",
    name: "yjs",
    version: "13.6.14",
    description: "Shared types and CRDT framework for real-time collaborative editing",
    importSnippet: 'import * as Y from "yjs";',
    category: "crdt",
    isInstalled: true,
    exports: ["Doc", "Text", "Array", "Map", "applyUpdate", "encodeStateAsUpdate", "UndoManager"],
  },
  {
    id: "lib-lodash",
    name: "lodash",
    version: "4.17.21",
    description: "Modern JavaScript utility library delivering modularity, performance & extras",
    importSnippet: 'import { debounce, throttle, cloneDeep } from "lodash";',
    category: "utility",
    isInstalled: true,
    exports: ["debounce", "throttle", "cloneDeep", "merge", "groupBy", "keyBy", "uniq", "chunk"],
  },
  {
    id: "lib-framer-motion",
    name: "framer-motion",
    version: "11.2.10",
    description: "Production-ready declarative motion and gesture library for React",
    importSnippet: 'import { motion, AnimatePresence } from "framer-motion";',
    category: "ui",
    isInstalled: true,
    exports: ["motion", "AnimatePresence", "useAnimation", "useMotionValue", "useSpring"],
  },
  {
    id: "lib-lucide-react",
    name: "lucide-react",
    version: "0.395.0",
    description: "Beautiful & consistent icon toolkit designed for brutalist interfaces",
    importSnippet: 'import { Terminal, Cpu, Sparkles, Folder } from "lucide-react";',
    category: "ui",
    isInstalled: true,
    exports: ["Terminal", "Cpu", "Sparkles", "Folder", "Play", "Share2", "Users", "Layers"],
  },
  {
    id: "lib-zod",
    name: "zod",
    version: "3.23.8",
    description: "TypeScript-first schema validation with static type inference",
    importSnippet: 'import { z } from "zod";',
    category: "utility",
    isInstalled: false,
    exports: ["z", "infer", "ZodType", "ZodSchema"],
  },
  {
    id: "lib-axios",
    name: "axios",
    version: "1.7.2",
    description: "Promise based HTTP client for browser and node runtimes",
    importSnippet: 'import axios from "axios";',
    category: "utility",
    isInstalled: false,
    exports: ["axios", "AxiosResponse", "AxiosError", "AxiosRequestConfig"],
  },
];

export const WORKSPACE_TEMPLATES: Record<string, WorkspaceTemplate> = {
  mesh: {
    id: "mesh",
    name: "Collaborative Mesh Core",
    description: "Multi-file distributed CRDT architecture with stream synchronization, WAL persistence, and Ed25519 auth.",
    iconName: "Share2",
    tag: "PRODUCTION DEFAULT",
    files: INITIAL_FILES,
    activeFileId: "file-stream-syncer",
  },
  systems: {
    id: "systems",
    name: "Bare-Metal Systems Kernel",
    description: "Low-latency systems architecture with memory page pools, raw byte vector buffers, and lock-free rings.",
    iconName: "Cpu",
    tag: "HIGH PERFORMANCE",
    files: [
      {
        id: "file-kernel",
        name: "kernel.ts",
        path: "kernel.ts",
        language: "typescript",
        x: 60,
        y: 60,
        width: 560,
        height: 460,
        zIndex: 12,
        activePeerIds: ["user-self"],
        contributorColor: "#FFFFFF",
        contributorName: "Operator",
        content: `/**
 * Crux Bare-Metal Kernel
 * Hardware-level memory ring buffer & event dispatch
 */
export class HardwareKernel {
  private memoryPages: SharedArrayBuffer;
  private ringHead: Int32Array;

  constructor(pageSizeKb = 64) {
    this.memoryPages = new SharedArrayBuffer(pageSizeKb * 1024);
    this.ringHead = new Int32Array(this.memoryPages, 0, 1);
    console.log("[Kernel] Allocated memory pages:", pageSizeKb, "KB");
  }

  public dispatch(eventCode: number): void {
    Atomics.add(this.ringHead, 0, 1);
    console.log("[Kernel] Event dispatched:", eventCode, "Ring Sequence:", Atomics.load(this.ringHead, 0));
  }
}

const kernel = new HardwareKernel();
kernel.dispatch(0x7447);
`,
      },
      {
        id: "file-mempool",
        name: "memory_pool.ts",
        path: "memory_pool.ts",
        language: "typescript",
        x: 780,
        y: 60,
        width: 500,
        height: 460,
        zIndex: 11,
        activePeerIds: [],
        contributorColor: "#888888",
        contributorName: "Allocator",
        content: `/**
 * Lock-free zero-copy memory pool allocator
 */
export class MemoryPool {
  private chunks: Uint8Array[] = [];

  allocate(sizeBytes: number): Uint8Array {
    const chunk = new Uint8Array(sizeBytes);
    this.chunks.push(chunk);
    return chunk;
  }

  releaseAll(): void {
    this.chunks.length = 0;
  }
}
`,
      },
    ],
    activeFileId: "file-kernel",
  },
  blank: {
    id: "blank",
    name: "Vacuum Enclave (Clean Slate)",
    description: "Pristine empty project enclave ready for scratch code, new algorithms, and isolated development.",
    iconName: "Terminal",
    tag: "MINIMALIST",
    files: [
      {
        id: "file-main",
        name: "main.ts",
        path: "main.ts",
        language: "typescript",
        x: 60,
        y: 60,
        width: 560,
        height: 460,
        zIndex: 12,
        activePeerIds: ["user-self"],
        contributorColor: "#FFFFFF",
        contributorName: "Operator",
        content: `// Crux Bare-Metal Enclave Initialized
// Press Cmd+P to execute commands or search files

console.log("Crux Kernel online. Ready for execution.");
`,
      },
      {
        id: "file-readme",
        name: "README.md",
        path: "README.md",
        language: "markdown",
        x: 780,
        y: 60,
        width: 500,
        height: 460,
        zIndex: 11,
        activePeerIds: [],
        contributorColor: "#888888",
        contributorName: "Docs",
        content: `# Crux Enclave

Welcome to Crux v1.0 (General Availability).

- **Mode Switch**: Press \`Cmd+1\` for Canvas, \`Cmd+2\` for Editor.
- **Command Palette**: Press \`Cmd+P\` or click the Omnibar.
- **Terminal**: Press \`^\`\` or click Terminal in the bottom dock.
- **Peer Share**: Click the Share button in the top bar to collaborate in real-time.
`,
      },
    ],
    activeFileId: "file-main",
  },
};

export function getCalendarGroupTitle(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();

  const isToday =
    date.getDate() === now.getDate() &&
    date.getMonth() === now.getMonth() &&
    date.getFullYear() === now.getFullYear();

  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  const isYesterday =
    date.getDate() === yesterday.getDate() &&
    date.getMonth() === yesterday.getMonth() &&
    date.getFullYear() === yesterday.getFullYear();

  const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const formattedDate = `${monthNames[date.getMonth()]} ${date.getDate()}, ${date.getFullYear()}`;

  if (isToday) return `Today — ${formattedDate}`;
  if (isYesterday) return `Yesterday — ${formattedDate}`;
  return formattedDate;
}

export const INITIAL_REVISIONS: FileRevision[] = [
  {
    id: "rev-init-stream",
    fileId: "file-stream-syncer",
    fileName: "stream_syncer.ts",
    timestamp: Date.now() - 1000 * 60 * 42,
    dateString: new Date().toISOString().split("T")[0],
    calendarGroup: getCalendarGroupTitle(Date.now() - 1000 * 60 * 42),
    timeString: "5:48 PM",
    summary: "Base checkpoint initialized: Mutual exclusion lock daemon client",
    author: "Operator [CRX-7447-HG]",
    content: INITIAL_FILES[0].content,
    linesCount: INITIAL_FILES[0].content.split("\n").length,
    charsCount: INITIAL_FILES[0].content.length,
    changeType: "checkpoint",
    diffSummary: { added: 18, removed: 0 },
  },
  {
    id: "rev-init-db",
    fileId: "file-database",
    fileName: "database.ts",
    timestamp: Date.now() - 1000 * 60 * 95,
    dateString: new Date().toISOString().split("T")[0],
    calendarGroup: getCalendarGroupTitle(Date.now() - 1000 * 60 * 95),
    timeString: "4:55 PM",
    summary: "WAL persistence baseline: Monotonic vector clock ring buffer",
    author: "CruxAI [CRX-0001-AI]",
    content: INITIAL_FILES[1].content,
    linesCount: INITIAL_FILES[1].content.split("\n").length,
    charsCount: INITIAL_FILES[1].content.length,
    changeType: "checkpoint",
    diffSummary: { added: 24, removed: 0 },
  },
  {
    id: "rev-init-auth",
    fileId: "file-auth",
    fileName: "auth.ts",
    timestamp: Date.now() - 1000 * 60 * 60 * 25,
    dateString: new Date(Date.now() - 1000 * 60 * 60 * 25).toISOString().split("T")[0],
    calendarGroup: getCalendarGroupTitle(Date.now() - 1000 * 60 * 60 * 25),
    timeString: "5:05 PM",
    summary: "Initial commit: Ed25519 subtle WebCrypto attestation subsystem",
    author: "Sarah Lin [CRX-9941-SL]",
    content: INITIAL_FILES[2].content,
    linesCount: INITIAL_FILES[2].content.split("\n").length,
    charsCount: INITIAL_FILES[2].content.length,
    changeType: "create",
    diffSummary: { added: 32, removed: 0 },
  },
];


