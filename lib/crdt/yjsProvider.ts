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
import { INITIAL_FILES } from "@/lib/defaultData";

export interface CrexPeerUser {
  name: string;
  color: string;
  uid: string;
  avatarType?: User["avatarType"];
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
  release?: () => void;
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

// Active sessions cache indexed by fileId/room (persisted across Next.js Fast Refresh)
const globalScope = typeof window !== "undefined" ? (window as any) : (globalThis as any);
if (!globalScope.__CREX_CRDT_SESSIONS__) {
  globalScope.__CREX_CRDT_SESSIONS__ = new Map<string, CrexCRDTSession>();
}
if (!globalScope.__CREX_INITIALIZED_ROOMS__) {
  globalScope.__CREX_INITIALIZED_ROOMS__ = new Set<string>();
}
if (!globalScope.__CREX_SESSION_USERS__) {
  globalScope.__CREX_SESSION_USERS__ = new Map<string, number>();
}
const sessionCache: Map<string, CrexCRDTSession> = globalScope.__CREX_CRDT_SESSIONS__;
const initializedRooms: Set<string> = globalScope.__CREX_INITIALIZED_ROOMS__;
const sessionUsers: Map<string, number> = globalScope.__CREX_SESSION_USERS__;
const hostedSessions = new Set<string>();
const documentStoragePrefix = "crux_yjs_room_v1:";

export function markCrexSessionAsHost(sessionId: string) {
  hostedSessions.add(sessionId.trim());
}

function restoreRoomDocument(roomName: string, ydoc: Y.Doc): boolean {
  if (typeof window === "undefined") return false;
  try {
    const encoded = localStorage.getItem(`${documentStoragePrefix}${roomName}`);
    if (!encoded) return false;
    const binary = atob(encoded);
    const update = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    Y.applyUpdate(ydoc, update);
    return true;
  } catch (error) {
    console.warn("[CRUX_SYNC]: Could not restore local CRDT state", error);
    return false;
  }
}

function persistRoomDocument(roomName: string, ydoc: Y.Doc) {
  if (typeof window === "undefined") return;
  try {
    const update = Y.encodeStateAsUpdate(ydoc);
    let binary = "";
    for (let offset = 0; offset < update.length; offset += 32768) {
      binary += String.fromCharCode(...update.subarray(offset, offset + 32768));
    }
    localStorage.setItem(`${documentStoragePrefix}${roomName}`, btoa(binary));
  } catch (error) {
    console.warn("[CRUX_SYNC]: Could not persist local CRDT state", error);
  }
}

function seedInitialText(ydoc: Y.Doc, roomName: string, content: string) {
  if (!content) return;
  // Every peer applies the same seed update for the same starter file. Yjs
  // deduplicates its item IDs instead of inserting the template twice.
  let clientId = 2166136261;
  const key = `${roomName}\0${content}`;
  for (let index = 0; index < key.length; index++) {
    clientId = Math.imul(clientId ^ key.charCodeAt(index), 16777619);
  }
  const seedDoc = new Y.Doc();
  seedDoc.clientID = (clientId >>> 0) || 1;
  seedDoc.getText("codemirror").insert(0, content);
  Y.applyUpdate(ydoc, Y.encodeStateAsUpdate(seedDoc));
  seedDoc.destroy();
}

export function replaceCrexYTextContent(ytext: Y.Text, content: string) {
  const current = ytext.toString();
  if (current === content) return;
  let start = 0;
  while (start < current.length && start < content.length && current[start] === content[start]) start++;
  let oldEnd = current.length;
  let newEnd = content.length;
  while (oldEnd > start && newEnd > start && current[oldEnd - 1] === content[newEnd - 1]) {
    oldEnd--;
    newEnd--;
  }
  ytext.doc?.transact(() => {
    if (oldEnd > start) ytext.delete(start, oldEnd - start);
    if (newEnd > start) ytext.insert(start, content.slice(start, newEnd));
  });
}

export function updateLocalAvatarAwareness(avatarType: User["avatarType"]) {
  sessionCache.forEach((session) => {
    const user = session.awareness.getLocalState()?.user;
    if (user) session.awareness.setLocalStateField("user", { ...user, avatarType });
  });
}

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

  // The 2026-09-29 recovery starts these six files in fresh rooms. Existing
  // corrupted Yjs updates stay in the old rooms for recovery and cannot merge
  // back into the clean checkpoint text.
  if (["file-stream-syncer", "file-database", "file-auth", "file-types", "file-spatial", "file-practice-checkpoint"].includes(fileId)) {
    return `crux-mesh-clean-20260929-${fileId}`;
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
    sessionUsers.set(roomName, (sessionUsers.get(roomName) || 0) + 1);
    // Update local awareness state with current user
    existing.awareness.setLocalStateField("user", {
      name: user.name,
      color: user.color,
      uid: user.uid,
      avatarType: user.avatarType,
      isTyping: false,
      lastActive: Date.now(),
      activeFileId: fileId,
    });
    return existing;
  }

  const ydoc = new Y.Doc();
  const ytext = ydoc.getText("codemirror");
  const restored = restoreRoomDocument(roomName, ydoc);

  const sessionId = (() => {
    const storeSession = useWorkspaceStore.getState().activeSessionId;
    if (storeSession) return storeSession;
    if (typeof window === "undefined") return null;
    const params = new URLSearchParams(window.location.search);
    return params.get("session") || params.get("room") ||
      (window.location.hash.startsWith("#session-") ? window.location.hash.slice(1) : null);
  })();
  const isJoiningSession = Boolean(sessionId && !hostedSessions.has(sessionId));

  // Only populate initial template content on the very first creation of this room.
  // If the room has been initialized, do not re-insert initial content into an emptied file buffer.
  const hasBeenInitialized = initializedRooms.has(roomName);
  if (!hasBeenInitialized && !restored) {
    initializedRooms.add(roomName);
    if (!isJoiningSession && ytext.length === 0 && initialContent) {
      const starter = INITIAL_FILES.find((file) => file.id === fileId)?.content;
      seedInitialText(ydoc, roomName, starter ?? initialContent);
      if (starter && starter !== initialContent) {
        replaceCrexYTextContent(ytext, initialContent);
      }
    }
  }

  let persistTimer: ReturnType<typeof setTimeout> | null = null;
  const queuePersistence = () => {
    if (persistTimer) clearTimeout(persistTimer);
    persistTimer = setTimeout(() => {
      persistTimer = null;
      persistRoomDocument(roomName, ydoc);
    }, 250);
  };
  ydoc.on("update", queuePersistence);
  if (ytext.length > 0) queuePersistence();

  let provider: WebrtcProvider;
  try {
    provider = new WebrtcProvider(roomName, ydoc, {
      signaling: getSignalingUrls(),
      awareness: new Awareness(ydoc),
      maxConns: 30,
      filterBcConns: false,
      peerOpts: {},
    });
  } catch (err: any) {
    if (err?.message?.includes("already exists")) {
      const cached = sessionCache.get(roomName);
      if (cached) {
        cached.awareness.setLocalStateField("user", {
          name: user.name,
          color: user.color,
          uid: user.uid,
          avatarType: user.avatarType,
          isTyping: false,
          lastActive: Date.now(),
          activeFileId: fileId,
        });
        return cached;
      }
      const uniqueRoomName = `${roomName}-${Math.random().toString(36).slice(2, 7)}`;
      provider = new WebrtcProvider(uniqueRoomName, ydoc, {
        signaling: getSignalingUrls(),
        awareness: new Awareness(ydoc),
        maxConns: 30,
        filterBcConns: false,
        peerOpts: {},
      });
    } else {
      throw err;
    }
  }

  const awareness = provider.awareness;

  awareness.setLocalStateField("user", {
    name: user.name,
    color: user.color,
    uid: user.uid,
    avatarType: user.avatarType,
    isTyping: false,
    lastActive: Date.now(),
    activeFileId: fileId,
  });

  const updateConnectedUsers = () => {
    try {
      if (getDeterministicRoomName(fileId) !== roomName) return;
      const states = awareness.getStates();
      const liveUsers: User[] = [];
      states.forEach((state: any, clientID: number) => {
        if (!state || !state.user) return;
        const u = state.user;
        liveUsers.push({
          id: `client-${clientID}`,
          name: u.name || `Peer-${clientID.toString().slice(-4)}`,
          email: `${(u.name || "peer").toLowerCase().replace(/\s+/g, "")}@mesh.local`,
          color: u.color || "#FFFFFF",
          avatar: "",
          avatarType: u.avatarType,
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
        if (persistTimer) clearTimeout(persistTimer);
        persistRoomDocument(roomName, ydoc);
        ydoc.off("update", queuePersistence);
        awareness.off("change", updateConnectedUsers);
        provider.destroy();
        ydoc.destroy();
      } catch {
        // ignore
      }
      sessionCache.delete(roomName);
      sessionUsers.delete(roomName);
    },
    release: () => {
      const remaining = (sessionUsers.get(roomName) || 1) - 1;
      if (remaining > 0) sessionUsers.set(roomName, remaining);
      else session.destroy();
    },
  };

  sessionCache.set(roomName, session);
  sessionUsers.set(roomName, 1);
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
      avatarType: user.avatarType,
      isTyping: false,
      lastActive: Date.now(),
    });
    return existing;
  }

  const ydoc = new Y.Doc();
  const ytext = ydoc.getText("canvas-meta");

  let provider: WebrtcProvider;
  try {
    provider = new WebrtcProvider(roomName, ydoc, {
      signaling: getSignalingUrls(),
      awareness: new Awareness(ydoc),
      maxConns: 30,
      filterBcConns: false,
      peerOpts: {},
    });
  } catch (err: any) {
    if (err?.message?.includes("already exists")) {
      const cached = sessionCache.get(roomName);
      if (cached) {
        cached.awareness.setLocalStateField("user", {
          name: user.name,
          color: user.color,
          uid: user.uid,
          avatarType: user.avatarType,
          isTyping: false,
          lastActive: Date.now(),
        });
        return cached;
      }
      const uniqueRoomName = `${roomName}-${Math.random().toString(36).slice(2, 7)}`;
      provider = new WebrtcProvider(uniqueRoomName, ydoc, {
        signaling: getSignalingUrls(),
        awareness: new Awareness(ydoc),
        maxConns: 30,
        filterBcConns: false,
        peerOpts: {},
      });
    } else {
      throw err;
    }
  }

  const awareness = provider.awareness;

  awareness.setLocalStateField("user", {
    name: user.name,
    color: user.color,
    uid: user.uid,
    avatarType: user.avatarType,
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
