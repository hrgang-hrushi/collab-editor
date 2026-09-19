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
import { useWorkspaceStore } from "@/lib/store";
import { User } from "@/lib/types";

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

/**
 * Active, reliable WebRTC signaling broker endpoints.
 * In HTTPS environments (e.g. Vercel deployment), browser blocks insecure ws:// endpoints.
 * In local development, the local Bun/Node signaling broker (:4444) is prioritized,
 * backed by the official Yjs community broker on Fly.io (wss://y-webrtc-eu.fly.dev).
 */
export function getSignalingUrls(): string[] {
  if (typeof window !== "undefined") {
    const isLocal =
      window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1";

    if (isLocal) {
      return ["ws://localhost:4444", "wss://y-webrtc-eu.fly.dev", "wss://y-webrtc.fly.dev"];
    }
  }

  return ["wss://y-webrtc-eu.fly.dev", "wss://y-webrtc.fly.dev"];
}

export const DEFAULT_SIGNALING = ["wss://y-webrtc-eu.fly.dev", "wss://y-webrtc.fly.dev"];

// Active sessions cache indexed by fileId/room
const sessionCache = new Map<string, CrexCRDTSession>();
// Track rooms that have been initialized with initial template content to avoid re-inserting into empty buffers
const initializedRooms = new Set<string>();

/**
 * Generates or extracts a deterministic room hash from URL or file ID.
 */
export function getDeterministicRoomName(fileId: string, customHash?: string): string {
  if (customHash) {
    const clean = customHash.replace(/^#/, "").split("?")[0].trim();
    if (clean) return `${clean}-${fileId}`;
  }

  // 0. Check store activeSessionId first
  try {
    const storeSession = useWorkspaceStore.getState().activeSessionId;
    if (storeSession && storeSession.trim()) {
      return `session-${storeSession.trim()}-${fileId}`;
    }
  } catch {
    // ignore
  }

  if (typeof window !== "undefined") {
    // 1. Check URL query params for ?session=... or ?room=...
    const params = new URLSearchParams(window.location.search);
    const querySession = params.get("session") || params.get("room");
    if (querySession && querySession.trim()) {
      return `session-${querySession.trim()}-${fileId}`;
    }

    // 2. Check URL hash for #session-...
    const hash = window.location.hash.replace(/^#/, "").trim();
    if (hash && hash.startsWith("session-")) {
      const cleanHash = hash.split("?")[0].trim();
      return `${cleanHash}-${fileId}`;
    }
  }

  return `crux-mesh-${fileId}`;
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
      activeFileId: fileId,
    });
    return existing;
  }

  const ydoc = new Y.Doc();
  const ytext = ydoc.getText("codemirror");

  const isJoiningSession = (() => {
    if (typeof window === "undefined") return false;
    const params = new URLSearchParams(window.location.search);
    return (
      params.has("session") ||
      params.has("room") ||
      window.location.hash.startsWith("#session-")
    );
  })();

  // Only populate initial template content on the very first creation of this room.
  // If the room has been initialized, do not re-insert initial content into an emptied file buffer.
  const hasBeenInitialized = initializedRooms.has(roomName);
  if (!hasBeenInitialized) {
    initializedRooms.add(roomName);
    if (!isJoiningSession && ytext.length === 0 && initialContent) {
      ytext.insert(0, initialContent);
    } else if (isJoiningSession && ytext.length === 0 && initialContent) {
      const fallbackTimer = setTimeout(() => {
        if (ytext.length === 0 && initialContent) {
          ytext.insert(0, initialContent);
        }
      }, 600);

      const onFirstSync = () => {
        if (ytext.length > 0) {
          clearTimeout(fallbackTimer);
          ytext.unobserve(onFirstSync);
        }
      };
      ytext.observe(onFirstSync);
    }
  }

  const provider = new WebrtcProvider(roomName, ydoc, {
    signaling: getSignalingUrls(),
    awareness: new Awareness(ydoc),
    maxConns: 30,
    filterBcConns: false,
    peerOpts: {},
  });

  const awareness = provider.awareness;

  awareness.setLocalStateField("user", {
    name: user.name,
    color: user.color,
    uid: user.uid,
    isTyping: false,
    lastActive: Date.now(),
    activeFileId: fileId,
  });

  const updateConnectedUsers = () => {
    try {
      const states = awareness.getStates();
      const liveUsers: User[] = [];
      states.forEach((state: any, clientID: number) => {
        if (!state || !state.user) return;
        const u = state.user;
        liveUsers.push({
          id: u.uid || `client-${clientID}`,
          name: u.name || `Peer-${clientID.toString().slice(-4)}`,
          email: `${(u.name || "peer").toLowerCase().replace(/\s+/g, "")}@mesh.local`,
          color: u.color || "#FFFFFF",
          avatar: "",
          status: clientID === ydoc.clientID ? "active" : "idle",
          uid: u.uid || `CRX-${clientID.toString().slice(-4)}`,
          activeFileId: u.activeFileId || fileId,
          isSelf: clientID === ydoc.clientID,
        });
      });
      if (liveUsers.length > 0) {
        useWorkspaceStore.getState().setActiveUsers(liveUsers);
      }
    } catch {
      // ignore
    }
  };

  awareness.on("change", updateConnectedUsers);
  updateConnectedUsers();

  const session: CrexCRDTSession = {
    ydoc,
    ytext,
    provider,
    awareness,
    destroy: () => {
      try {
        awareness.off("change", updateConnectedUsers);
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
 * Generates deterministic room name for the real-time shared Canvas session.
 */
export function getDeterministicCanvasRoomName(): string {
  try {
    const storeSession = useWorkspaceStore.getState().activeSessionId;
    if (storeSession && storeSession.trim()) {
      return `session-${storeSession.trim()}-canvas`;
    }
  } catch {
    // ignore
  }

  if (typeof window !== "undefined") {
    const params = new URLSearchParams(window.location.search);
    const querySession = params.get("session") || params.get("room");
    if (querySession && querySession.trim()) {
      return `session-${querySession.trim()}-canvas`;
    }

    const hash = window.location.hash.replace(/^#/, "").trim();
    if (hash && hash.startsWith("session-")) {
      const cleanHash = hash.split("?")[0].trim();
      return `${cleanHash}-canvas`;
    }
  }

  return "crux-canvas-nexus";
}

/**
 * Initializes or retrieves existing CRDT session specifically for the real-time Spatial Canvas.
 */
export function initCrexCanvasSession(user: CrexPeerUser): CrexCRDTSession {
  const roomName = getDeterministicCanvasRoomName();

  if (sessionCache.has(roomName)) {
    const existing = sessionCache.get(roomName)!;
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
  const ytext = ydoc.getText("canvas-meta");

  const provider = new WebrtcProvider(roomName, ydoc, {
    signaling: getSignalingUrls(),
    awareness: new Awareness(ydoc),
    maxConns: 30,
    filterBcConns: false,
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
