export interface User {
  id: string;
  name: string;
  avatar: string;
  color: string;
  role?: string;
  isSelf?: boolean;
  email?: string;
  uid?: string;
  accessLevel?: "full" | "limited" | "viewer";
  allowedFiles?: string[];
  allowedLineRange?: { start: number; end: number };
}

export interface ShareInvite {
  id: string;
  senderName: string;
  senderUid: string;
  senderEmail: string;
  recipientUidOrEmail: string;
  workspaceName: string;
  accessLevel: "full" | "limited" | "viewer";
  allowedFiles?: string[];
  allowedLineRange?: { start: number; end: number };
  viewerLock: boolean;
  timestamp: number;
  status: "pending" | "accepted" | "declined";
}

export interface SpatialCursor {
  userId: string;
  userName: string;
  userColor: string;
  userUid?: string;
  x: number;
  y: number;
  targetX: number;
  targetY: number;
  offsetX?: number;
  offsetY?: number;
  activeFileId?: string;
  lastUpdated: number;
  selection?: {
    from: number;
    to: number;
    text?: string;
  };
}

export interface FileNode {
  id: string;
  name: string;
  path: string;
  language: "typescript" | "javascript" | "html" | "css" | "json" | "python" | "markdown" | "plaintext";
  content: string;
  x: number;
  y: number;
  width: number;
  height: number;
  zIndex: number;
  isMinimized?: boolean;
  isDirty?: boolean;
  status?: "clean" | "modified" | "suggesting";
  activePeerIds?: string[];
  contributorColor?: string;
  contributorName?: string;
  handle?: any; // FileSystemFileHandle for saving back to local disk
}

export interface ArchitecturalEdge {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  label?: string;
  type: "import" | "data-flow" | "call";
  color?: string;
  codeSymbol?: string;
  changeCode?: string;
  originalSnippet?: string;
  targetSnippet?: string;
  sourceLine?: number;
  targetLine?: number;
  flowSpeed?: string;
  payloadDescription?: string;
}

export interface InlineSuggestion {
  id: string;
  fileId: string;
  author: User;
  createdAt: number;
  from: number;
  to: number;
  originalText: string;
  suggestedText: string;
  description: string;
  status: "pending" | "accepted" | "rejected";
}

export interface CommentMessage {
  id: string;
  author: User;
  text: string;
  createdAt: number;
  reactions?: Record<string, string[]>;
}

export interface ContextualThread {
  id: string;
  fileId: string;
  lineNumber: number;
  charOffset: number;
  anchorSnippet: string;
  author: User;
  createdAt: number;
  resolved: boolean;
  messages: CommentMessage[];
}

export type EditorInteractionMode = "edit" | "suggest" | "comment" | "canvas";

export interface ExecutionResult {
  stdout: string[];
  stderr: string[];
  returnValue?: string;
  durationMs: number;
  success: boolean;
  timestamp: number;
  fileName?: string;
}

export interface GitCommit {
  id: string;
  message: string;
  timestamp: number;
  author: string;
  filesChanged: number;
}

export interface LibraryPackage {
  id: string;
  name: string;
  version: string;
  description: string;
  importSnippet: string;
  category: "core" | "crdt" | "ui" | "utility" | "npm";
  isInstalled: boolean;
  exports: string[];
}

export interface TerminalPeerInput {
  userId: string;
  userName: string;
  userColor: string;
  cursorCol: number;
  lastActive: number;
}

export interface TerminalSession {
  id: string;
  name: string;
  type: "sh" | "server" | "ai" | "output";
  cwd: string;
  lines: import("./ansiParser").AnsiLine[];
  history: string[];
  historyIndex: number;
  inputVal: string;
  isStreaming: boolean;
  activePid: number | null;
  lastExitCode: number | null;
  peerInputs?: Record<string, TerminalPeerInput>;
  lastDiagnosis?: {
    summary: string;
    suggestedCommand?: string;
    suggestedDiff?: string;
  } | null;
}
