/**
 * Crex Collaborative CRDT Engine (Yjs + y-webrtc)
 * 
 * Hardware Brutalism Network Transport:
 * - Direct WebRTC DataChannels between peers for sub-10ms keystroke sync.
 * - Local Bun signaling broker fallback on ws://localhost:4444 + public fallbacks.
 * - Deterministic Y.Doc & Y.Text bindings with zero-auth hash room routing.
 * - y-protocols/awareness integration for remote cursor & selection replication.
 */

import * as Y from "yjs";
import { WebrtcProvider } from "y-webrtc";
import { Awareness } from "y-protocols/awareness";

export interface CrexPeerUser {
  name: string;
  color: string;
  uid: string;
  isTyping?: boolean;
  lastActive?: number;
}

export interface CrexSessionConfig {
  roomName: string;
  initialContent?: string;
  user: CrexPeerUser;
}

export interface CrexCRDTSession {
  ydoc: Y.Doc;
  ytext: Y.Text;
  provider: WebrtcProvider;
  awareness: Awareness;
  destroy: () => void;
}

// Default signaling brokers (Local fast Bun broker prioritized, followed by public fallbacks)
const DEFAULT_SIGNALING = [
  "ws://localhost:4444",
  "wss://signaling.yjs.dev",
  "wss://y-webrtc-signaling-eu.herokuapp.com",
  "wss://y-webrtc-signaling-us.herokuapp.com",
];

// Active sessions cache indexed by fileId/room
const sessionCache = new Map<string, CrexCRDTSession>();

/**
 * Generates or extracts a deterministic room hash from URL or file ID.
 */
export function getDeterministicRoomName(fileId: string, customHash?: string): string {
  if (typeof window !== "undefined") {
    const hash = window.location.hash.replace(/^#/, "").trim();
    if (hash && hash.startsWith("session-")) {
      return `${hash}-${fileId}`;
    }
  }
  return `crex-mesh-${fileId}`;
}

/**
 * Returns current active CRDT session for a file if initialized.
 */
export function getActiveCrexCRDTSession(fileId: string): CrexCRDTSession | undefined {
  const roomName = getDeterministicRoomName(fileId);
  return sessionCache.get(roomName);
}

/**
 * Initializes or returns an existing CRDT Yjs session with WebRTC peer-to-peer sync.
 */
export function initCrexCRDTSession(
  fileId: string,
  initialContent: string,
  user: CrexPeerUser
): CrexCRDTSession {
  const roomName = getDeterministicRoomName(fileId);

  if (sessionCache.has(roomName)) {
    const existing = sessionCache.get(roomName)!;
    // Update local awareness state with current user
    existing.awareness.setLocalStateField("user", {
      name: user.name,
      color: user.color,
      uid: user.uid,
      isTyping: false,
      lastActive: Date.now(),
    });
    return existing;
  }

  const ydoc = new Y.Doc();
  const ytext = ydoc.getText("codemirror");

  // If local document is empty and we have initial content, populate it
  if (ytext.length === 0 && initialContent) {
    ytext.insert(0, initialContent);
  }

  const provider = new WebrtcProvider(roomName, ydoc, {
    signaling: DEFAULT_SIGNALING,
    awareness: new Awareness(ydoc),
    maxConns: 20 + Math.floor(Math.random() * 15),
    filterBcConns: true,
    peerOpts: {},
  });

  const awareness = provider.awareness;

  awareness.setLocalStateField("user", {
    name: user.name,
    color: user.color,
    uid: user.uid,
    isTyping: false,
    lastActive: Date.now(),
  });

  const session: CrexCRDTSession = {
    ydoc,
    ytext,
    provider,
    awareness,
    destroy: () => {
      try {
        provider.destroy();
        ydoc.destroy();
      } catch {
        // ignore
      }
      sessionCache.delete(roomName);
    },
  };

  sessionCache.set(roomName, session);
  return session;
}

/**
 * Peer Color Assignment Palette (Strict Hardware Brutalism):
 * Peer 1: #FFFFFF (White silk, text inverts to black)
 * Peer 2: #888888 (Silicon mid-tone)
 * Peer 3: #444444 (Muted machine gray)
 */
export const CREX_PEER_COLORS = ["#FFFFFF", "#888888", "#444444", "#AAAAAA", "#666666"];

export function getPeerColorByIndex(index: number): string {
  return CREX_PEER_COLORS[index % CREX_PEER_COLORS.length];
}
