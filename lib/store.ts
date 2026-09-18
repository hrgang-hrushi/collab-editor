import { create } from "zustand";
import {
  FileNode,
  ArchitecturalEdge,
  InlineSuggestion,
  ContextualThread,
  User,
  SpatialCursor,
  EditorInteractionMode,
  ExecutionResult,
  GitCommit,
  ShareInvite,
} from "./types";
import { executeCode } from "./codeRunner";
import { detectLanguage, saveFileToDisk } from "./fileUtils";
import {
  INITIAL_FILES,
  INITIAL_EDGES,
  INITIAL_SUGGESTIONS,
  INITIAL_COMMENTS,
  CURRENT_USER,
  MOCK_USERS,
  INITIAL_INVITES,
} from "./defaultData";

interface WorkspaceState {
  // Active User & Teammates
  currentUser: User;
  activeUsers: User[];
  remoteCursors: Record<string, SpatialCursor>;

  // Files & Tabs
  projectName: string;
  files: FileNode[];
  activeFileId: string;
  openTabIds: string[];
  edges: ArchitecturalEdge[];
  canvasTransform: { panX: number; panY: number; zoom: number };

  // Collaborative Mechanics
  mode: EditorInteractionMode;
  suggestions: InlineSuggestion[];
  comments: ContextualThread[];
  activeCommentThreadId: string | null;

  // Visual & HUD layout states
  isCommandPaletteOpen: boolean;
  isSidebarOpen: boolean;
  isTerminalOpen: boolean;
  activeTerminalTab: "terminal" | "daemon" | "ai" | "output" | "repl";
  isConnectingNodes: boolean;
  connectionSourceId: string | null;
  cursorPos: { line: number; col: number };

  // Live Code Execution & Terminal
  isExecuting: boolean;
  lastExecutionResult: ExecutionResult | null;
  terminalHistory: Array<{ cmd: string; output?: string[]; type?: "info" | "ok" | "err" | "warn" }>;
  terminalCwd: string;
  gitCommits: GitCommit[];

  // Live Flow & Pipeline Tracking
  flowSpeedFactor: number;
  isFlowPaused: boolean;
  focusedEdgeId: string | null;
  isPipelineTrackerOpen: boolean;

  // AI Co-Pilot State
  isAiPromptOpen: boolean;
  isAiGenerating: boolean;

  // Onboarding & Identity
  isOnboarded: boolean;
  isIdentityDrawerOpen: boolean;

  // Workspace Sharing, Access & Permissions
  isShareModalOpen: boolean;
  viewerLock: boolean;
  accessLevel: "full" | "limited" | "viewer";
  allowedFiles: string[];
  allowedLineRange?: { start: number; end: number };

  // Collaborative Inbox
  isInboxOpen: boolean;
  inboxInvites: ShareInvite[];

  // Actions
  setProjectName: (name: string) => void;
  setActiveFile: (id: string) => void;
  openTab: (id: string) => void;
  closeTab: (id: string) => void;
  createFile: (name: string, content?: string) => void;
  createFileInPath: (path: string, content?: string) => void;
  deletePath: (path: string) => void;
  renamePath: (oldPath: string, newPath: string) => void;
  importFiles: (
    files: Array<{ name: string; path: string; content: string; language?: string; handle?: any }>
  ) => void;
  importProject: (
    name: string,
    files: Array<{ name: string; path: string; content: string; handle?: any }>,
    dirHandle?: any
  ) => void;
  clearWorkspace: () => void;
  deleteFile: (id: string) => void;
  renameFile: (id: string, newName: string) => void;
  updateFileContent: (id: string, content: string) => void;
  updateFilePosition: (id: string, x: number, y: number) => void;
  bringToFront: (id: string) => void;
  saveActiveFile: () => Promise<boolean>;

  // Code Execution & Terminal Actions
  runActiveFile: () => Promise<ExecutionResult | null>;
  runFileById: (fileId: string) => Promise<ExecutionResult | null>;
  setTerminalCwd: (cwd: string) => void;
  addTerminalEntry: (entry: { cmd: string; output?: string[]; type?: "info" | "ok" | "err" | "warn" }) => void;
  clearTerminal: () => void;
  addGitCommit: (message: string) => void;

  setMode: (mode: EditorInteractionMode) => void;
  setCanvasTransform: (transform: { panX: number; panY: number; zoom: number }) => void;
  zoomBy: (delta: number) => void;
  resetView: () => void;

  // Architecture Edge Connections
  startConnection: (sourceNodeId: string) => void;
  completeConnection: (targetNodeId: string) => void;
  cancelConnection: () => void;
  removeEdge: (edgeId: string) => void;

  // Suggestion Engine
  addSuggestion: (suggestion: Omit<InlineSuggestion, "id" | "createdAt" | "status">) => void;
  acceptSuggestion: (suggestionId: string) => void;
  rejectSuggestion: (suggestionId: string) => void;

  // Contextual Comments
  addComment: (fileId: string, lineNumber: number, snippet: string, initialMessage: string) => void;
  addCommentReply: (threadId: string, text: string) => void;
  resolveComment: (threadId: string) => void;
  setActiveCommentThread: (threadId: string | null) => void;

  // Layout Toggles
  toggleSidebar: () => void;
  toggleTerminal: () => void;
  setTerminalOpen: (open: boolean) => void;
  setActiveTerminalTab: (tab: "terminal" | "daemon" | "ai" | "output" | "repl") => void;
  setCommandPaletteOpen: (open: boolean) => void;
  setCursorPos: (pos: { line: number; col: number }) => void;
  setAiPromptOpen: (open: boolean) => void;
  triggerAiGenerate: (prompt: string) => Promise<void>;
  updateRemoteCursor: (userId: string, data: Partial<SpatialCursor>) => void;

  // Live Flow & Pipeline Tracking Actions
  setFlowSpeedFactor: (factor: number) => void;
  toggleFlowPause: () => void;
  setFocusedEdgeId: (id: string | null) => void;
  togglePipelineTracker: () => void;
  setPipelineTrackerOpen: (open: boolean) => void;

  // Onboarding & Identity Actions
  setOnboarded: (onboarded: boolean) => void;
  setUserProfile: (profile: Partial<User> & { password?: string }) => void;
  setIdentityDrawerOpen: (open: boolean) => void;

  // Sharing & Access Actions
  setShareModalOpen: (open: boolean) => void;
  toggleViewerLock: () => void;
  setViewerLock: (lock: boolean) => void;
  setAccessLevel: (level: "full" | "limited" | "viewer") => void;
  setAllowedFiles: (files: string[]) => void;
  setAllowedLineRange: (range?: { start: number; end: number }) => void;

  // Collaborative Inbox Actions
  setInboxOpen: (open: boolean) => void;
  sendInvite: (invite: Omit<ShareInvite, "id" | "timestamp" | "status">) => void;
  acceptInvite: (inviteId: string) => void;
  declineInvite: (inviteId: string) => void;
}

export const useWorkspaceStore = create<WorkspaceState>((set, get) => ({
  currentUser: CURRENT_USER,
  activeUsers: [CURRENT_USER, ...MOCK_USERS],
  isOnboarded: typeof window !== "undefined" ? localStorage.getItem("crux_onboarded") === "true" : false,
  isIdentityDrawerOpen: false,
  isShareModalOpen: false,
  isInboxOpen: false,
  viewerLock: false,
  accessLevel: "full",
  allowedFiles: ["stream_syncer.ts", "database.ts", "auth.ts"],
  allowedLineRange: undefined,
  inboxInvites: INITIAL_INVITES,
  remoteCursors: {
    "user-1": {
      userId: "user-1",
      userName: "Sarah Lin",
      userColor: "#007AFF",
      x: 180,
      y: 190,
      targetX: 180,
      targetY: 190,
      offsetX: 180,
      offsetY: 190,
      activeFileId: "file-stream-syncer",
      lastUpdated: Date.now(),
    },
    "user-2": {
      userId: "user-2",
      userName: "CruxAI",
      userColor: "#FF453A",
      x: 220,
      y: 170,
      targetX: 220,
      targetY: 170,
      offsetX: 220,
      offsetY: 170,
      activeFileId: "file-stream-syncer",
      lastUpdated: Date.now(),
    },
    "user-3": {
      userId: "user-3",
      userName: "Marcus Vance",
      userColor: "#888888",
      x: 200,
      y: 160,
      targetX: 200,
      targetY: 160,
      offsetX: 200,
      offsetY: 160,
      activeFileId: "file-database",
      lastUpdated: Date.now(),
    },
  },

  projectName: "crux-core",
  files: INITIAL_FILES,
  activeFileId: "file-stream-syncer",
  openTabIds: ["file-stream-syncer", "file-auth", "file-database"],
  edges: INITIAL_EDGES,
  canvasTransform: { panX: 80, panY: 60, zoom: 0.52 },

  mode: "edit",
  suggestions: INITIAL_SUGGESTIONS,
  comments: INITIAL_COMMENTS,
  activeCommentThreadId: null,

  isCommandPaletteOpen: false,
  isSidebarOpen: true,
  isTerminalOpen: true,
  activeTerminalTab: "terminal",
  isConnectingNodes: false,
  connectionSourceId: null,
  cursorPos: { line: 1, col: 1 },

  isExecuting: false,
  lastExecutionResult: null,
  terminalHistory: [
    {
      cmd: "crux status",
      output: [
        "● Crux Daemon: v1.2.0 on localhost:7447 (IPC: 0.08ms)",
        "● Engine: CodeMirror 6 + Metal Acceleration",
        "● Workspace: ~/crux-core (3 peers in-sync)",
      ],
      type: "ok",
    },
  ],
  terminalCwd: "",
  gitCommits: [
    {
      id: "c-initial",
      message: "feat: initialize Crux collaborative engine and spatial canvas",
      timestamp: Date.now() - 3600000 * 2,
      author: "Local Host",
      filesChanged: 4,
    },
  ],

  flowSpeedFactor: 1,
  isFlowPaused: false,
  focusedEdgeId: null,
  isPipelineTrackerOpen: true,

  isAiPromptOpen: false,
  isAiGenerating: false,

  setProjectName: (projectName) => set({ projectName }),

  createFileInPath: (filePath, content = "") =>
    set((state) => {
      const trimmed = filePath.trim().replace(/^\//, "");
      const fileName = trimmed.split("/").pop() || "new_file.ts";
      const lang = detectLanguage(fileName);

      const newId = `file-${Date.now()}`;
      const newFile: FileNode = {
        id: newId,
        name: fileName,
        path: trimmed,
        language: lang,
        content:
          content ||
          `// ${fileName}\n// Crux zero-latency collaborative buffer\n\nexport function main() {\n  console.log("Running ${fileName}");\n}\n\nmain();\n`,
        x: 100 + (state.files.length % 3) * 560,
        y: 80 + Math.floor(state.files.length / 3) * 480,
        width: 540,
        height: 440,
        zIndex: Math.max(...state.files.map((f) => f.zIndex), 10) + 1,
        status: "clean",
      };

      return {
        files: [...state.files, newFile],
        activeFileId: newId,
        openTabIds: [...state.openTabIds, newId],
      };
    }),

  deletePath: (targetPath) =>
    set((state) => {
      const norm = targetPath.replace(/^\//, "").replace(/\/$/, "");
      const remainingFiles = state.files.filter(
        (f) => f.path !== norm && !f.path.startsWith(`${norm}/`)
      );
      const remainingTabIds = state.openTabIds.filter((tabId) =>
        remainingFiles.some((f) => f.id === tabId)
      );
      const nextActiveId = remainingFiles.some((f) => f.id === state.activeFileId)
        ? state.activeFileId
        : remainingFiles[0]?.id || "";

      return {
        files: remainingFiles,
        openTabIds: remainingTabIds.length > 0 ? remainingTabIds : [remainingFiles[0]?.id || ""],
        activeFileId: nextActiveId,
        edges: state.edges.filter(
          (e) =>
            remainingFiles.some((f) => f.id === e.sourceNodeId) &&
            remainingFiles.some((f) => f.id === e.targetNodeId)
        ),
      };
    }),

  renamePath: (oldPath, newPath) =>
    set((state) => {
      const normOld = oldPath.replace(/^\//, "");
      const normNew = newPath.replace(/^\//, "");

      const updatedFiles = state.files.map((f) => {
        if (f.path === normOld) {
          const newName = normNew.split("/").pop() || f.name;
          return {
            ...f,
            path: normNew,
            name: newName,
            language: detectLanguage(newName),
          };
        }
        if (f.path.startsWith(`${normOld}/`)) {
          const subPath = f.path.slice(normOld.length + 1);
          const fullNew = `${normNew}/${subPath}`;
          return {
            ...f,
            path: fullNew,
          };
        }
        return f;
      });

      return { files: updatedFiles };
    }),

  importProject: (name, importedFiles) =>
    set((state) => {
      if (importedFiles.length === 0) return state;

      const colors = ["#5e6ad2", "#06b6d4", "#8b5cf6", "#f59e0b", "#10b981", "#ec4899", "#3b82f6"];
      const newNodes: FileNode[] = importedFiles.map((item, idx) => {
        const lang = detectLanguage(item.name);
        const colIndex = idx % 3;
        const rowIndex = Math.floor(idx / 3);

        return {
          id: `file-proj-${Date.now()}-${idx}`,
          name: item.name,
          path: item.path || item.name,
          language: lang,
          content: item.content,
          handle: item.handle,
          x: 60 + colIndex * 600,
          y: 60 + rowIndex * 500,
          width: 540,
          height: 440,
          zIndex: 10 + idx,
          status: "clean",
          contributorColor: colors[idx % colors.length],
          contributorName: "Imported",
        };
      });

      const newEdges: ArchitecturalEdge[] = [];
      newNodes.forEach((sourceNode) => {
        newNodes.forEach((targetNode) => {
          if (sourceNode.id === targetNode.id) return;
          const targetBase = targetNode.name.replace(/\.[^/.]+$/, "");
          if (
            sourceNode.content.includes(`./${targetBase}`) ||
            sourceNode.content.includes(`/${targetBase}`) ||
            sourceNode.content.includes(`from "${targetBase}"`) ||
            sourceNode.content.includes(`from '${targetBase}'`)
          ) {
            newEdges.push({
              id: `edge-${sourceNode.id}-${targetNode.id}`,
              sourceNodeId: sourceNode.id,
              targetNodeId: targetNode.id,
              label: `import ${targetBase}`,
              type: "import",
              color: sourceNode.contributorColor || "#5e6ad2",
              codeSymbol: `${targetBase}`,
              changeCode: `import { ... } from './${targetBase}'`,
              sourceLine: 1,
              targetLine: 1,
              flowSpeed: "1.0x",
            });
          }
        });
      });

      const entryFile =
        newNodes.find((f) => /^(index|main|app)\.(ts|js|tsx|jsx|py)$/i.test(f.name)) ||
        newNodes[0];

      return {
        projectName: name || "imported-project",
        files: newNodes,
        edges: newEdges,
        activeFileId: entryFile?.id || newNodes[0]?.id || "",
        openTabIds: newNodes.slice(0, 4).map((n) => n.id),
        canvasTransform: { panX: 80, panY: 60, zoom: 0.5 },
      };
    }),

  saveActiveFile: async () => {
    const state = get();
    const activeFile = state.files.find((f) => f.id === state.activeFileId);
    if (!activeFile) return false;

    if (activeFile.handle) {
      const saved = await saveFileToDisk(activeFile);
      if (saved) {
        set((s) => ({
          files: s.files.map((f) =>
            f.id === activeFile.id ? { ...f, status: "clean" } : f
          ),
        }));
        return true;
      }
    }
    set((s) => ({
      files: s.files.map((f) =>
        f.id === activeFile.id ? { ...f, status: "clean" } : f
      ),
    }));
    return true;
  },

  runActiveFile: async () => {
    const state = get();
    const activeFile = state.files.find((f) => f.id === state.activeFileId);
    if (!activeFile) return null;

    set({ isExecuting: true, isTerminalOpen: true, activeTerminalTab: "output" });

    const result = await executeCode(
      activeFile.content,
      activeFile.language,
      activeFile.name,
      state.files
    );

    const logLines: string[] = [];
    if (result.stdout.length > 0) {
      logLines.push(...result.stdout);
    }
    if (result.stderr.length > 0) {
      logLines.push(...result.stderr.map((e) => `[Error] ${e}`));
    }
    if (result.returnValue !== undefined) {
      logLines.push(`=> ${result.returnValue}`);
    }
    logLines.push(`✓ Done in ${result.durationMs}ms (exit: ${result.success ? 0 : 1})`);

    set((s) => ({
      isExecuting: false,
      lastExecutionResult: result,
      terminalHistory: [
        ...s.terminalHistory,
        {
          cmd: `node ${activeFile.name}`,
          output: logLines,
          type: result.success ? "ok" : "err",
        },
      ],
    }));

    return result;
  },

  runFileById: async (fileId: string) => {
    const state = get();
    const targetFile = state.files.find((f) => f.id === fileId);
    if (!targetFile) return null;

    set({ isExecuting: true, isTerminalOpen: true, activeTerminalTab: "output" });

    const result = await executeCode(
      targetFile.content,
      targetFile.language,
      targetFile.name,
      state.files
    );

    const logLines: string[] = [];
    if (result.stdout.length > 0) logLines.push(...result.stdout);
    if (result.stderr.length > 0) logLines.push(...result.stderr.map((e) => `[Error] ${e}`));
    if (result.returnValue !== undefined) logLines.push(`=> ${result.returnValue}`);
    logLines.push(`✓ Done in ${result.durationMs}ms`);

    set((s) => ({
      isExecuting: false,
      lastExecutionResult: result,
      terminalHistory: [
        ...s.terminalHistory,
        {
          cmd: `node ${targetFile.name}`,
          output: logLines,
          type: result.success ? "ok" : "err",
        },
      ],
    }));

    return result;
  },

  setTerminalCwd: (terminalCwd) => set({ terminalCwd }),

  addTerminalEntry: (entry) =>
    set((state) => ({
      terminalHistory: [...state.terminalHistory, entry],
    })),

  clearTerminal: () => set({ terminalHistory: [] }),

  addGitCommit: (message) =>
    set((state) => {
      const newCommit: GitCommit = {
        id: `c-${Date.now().toString(36)}`,
        message,
        timestamp: Date.now(),
        author: state.currentUser.name || "Local Host",
        filesChanged: state.files.filter((f) => f.status === "modified").length || 1,
      };
      return {
        gitCommits: [newCommit, ...state.gitCommits],
        files: state.files.map((f) => ({ ...f, status: "clean" })),
      };
    }),

  setActiveFile: (id) =>
    set((state) => {
      const openTabs = state.openTabIds.includes(id)
        ? state.openTabIds
        : [...state.openTabIds, id];
      return { activeFileId: id, openTabIds: openTabs };
    }),

  openTab: (id) =>
    set((state) => ({
      activeFileId: id,
      openTabIds: state.openTabIds.includes(id)
        ? state.openTabIds
        : [...state.openTabIds, id],
    })),

  closeTab: (id) =>
    set((state) => {
      const updated = state.openTabIds.filter((tabId) => tabId !== id);
      let nextActive = state.activeFileId;
      if (state.activeFileId === id) {
        nextActive = updated[0] || state.files[0]?.id || "";
      }
      return {
        openTabIds: updated.length > 0 ? updated : [state.files[0]?.id || ""],
        activeFileId: nextActive,
      };
    }),

  createFile: (name, content = "") =>
    set((state) => {
      const ext = name.split(".").pop() || "ts";
      let lang: FileNode["language"] = "typescript";
      if (ext === "js" || ext === "jsx") lang = "javascript";
      if (ext === "py") lang = "python";
      if (ext === "css") lang = "css";
      if (ext === "html") lang = "html";
      if (ext === "json") lang = "json";

      const newId = `file-${Date.now()}`;
      const newFile: FileNode = {
        id: newId,
        name: name.trim(),
        path: `src/${name.trim()}`,
        language: lang,
        content:
          content ||
          `// ${name.trim()}\n// Crux zero-latency collaborative buffer\n\nexport function ready() {\n  return true;\n}\n`,
        x: 200 + Math.random() * 200,
        y: 150 + Math.random() * 150,
        width: 540,
        height: 440,
        zIndex: Math.max(...state.files.map((f) => f.zIndex), 10) + 1,
        status: "clean",
      };

      return {
        files: [...state.files, newFile],
        activeFileId: newId,
        openTabIds: [...state.openTabIds, newId],
      };
    }),

  importFiles: (incoming) =>
    set((state) => {
      const colors = [
        "#5e6ad2",
        "#06b6d4",
        "#8b5cf6",
        "#f59e0b",
        "#10b981",
        "#ec4899",
        "#3b82f6",
      ];
      const contributors = [
        "Local User",
        "Sarah Lin",
        "CruxAI",
        "Marcus Vance",
        "Imported",
      ];

      // Build FileNode list with neat layout offsets
      const existingCount = state.files.length;
      const newNodes: FileNode[] = incoming.map((item, idx) => {
        const ext = item.name.split(".").pop()?.toLowerCase() || "ts";
        let lang: FileNode["language"] = "typescript";
        if (ext === "js" || ext === "jsx") lang = "javascript";
        else if (ext === "py") lang = "python";
        else if (ext === "css") lang = "css";
        else if (ext === "html") lang = "html";
        else if (ext === "json") lang = "json";

        const overallIdx = existingCount + idx;
        const colIndex = overallIdx % 3;
        const rowIndex = Math.floor(overallIdx / 3);
        const startX = 60;
        const startY = 60;
        const x = startX + colIndex * 600;
        const y = startY + rowIndex * 500;

        return {
          id: `file-imported-${Date.now()}-${idx}`,
          name: item.name,
          path: item.path || `src/${item.name}`,
          language: lang,
          content: item.content,
          x,
          y,
          width: 540,
          height: 440,
          zIndex: Math.max(...state.files.map((f) => f.zIndex), 10) + idx + 1,
          status: "clean",
          contributorColor: colors[(existingCount + idx) % colors.length],
          contributorName: contributors[(existingCount + idx) % contributors.length],
        };
      });

      // Analyze imports across all files to auto-connect dependencies
      const allFiles = [...state.files, ...newNodes];
      const newEdges: ArchitecturalEdge[] = [];

      newNodes.forEach((sourceNode) => {
        allFiles.forEach((targetNode) => {
          if (sourceNode.id === targetNode.id) return;
          const targetBase = targetNode.name.replace(/\.[^/.]+$/, "");
          if (
            sourceNode.content.includes(`./${targetBase}`) ||
            sourceNode.content.includes(`/${targetBase}`) ||
            sourceNode.content.includes(`from "${targetBase}"`) ||
            sourceNode.content.includes(`from '${targetBase}'`)
          ) {
            newEdges.push({
              id: `edge-${sourceNode.id}-${targetNode.id}`,
              sourceNodeId: sourceNode.id,
              targetNodeId: targetNode.id,
              label: `import ${targetBase}`,
              type: "import",
              color: sourceNode.contributorColor || "#5e6ad2",
              codeSymbol: `${targetBase}.ts`,
              changeCode: `import { ... } from './${targetBase}'`,
              sourceLine: 2,
              targetLine: 1,
              flowSpeed: "1.0x",
            });
          }
        });
      });

      const updatedFiles = [...state.files, ...newNodes];
      const newlyOpenedTabIds = Array.from(
        new Set([...state.openTabIds, ...newNodes.slice(0, 4).map((n) => n.id)])
      );
      const nextActiveId = newNodes[0]?.id || state.activeFileId;

      return {
        files: updatedFiles,
        edges: [...state.edges, ...newEdges],
        openTabIds: newlyOpenedTabIds,
        activeFileId: nextActiveId,
        canvasTransform: { panX: 60, panY: 60, zoom: 0.5 },
      };
    }),

  clearWorkspace: () =>
    set({
      files: [],
      edges: [],
      openTabIds: [],
      activeFileId: "",
    }),

  deleteFile: (id) =>
    set((state) => {
      const newFiles = state.files.filter((f) => f.id !== id);
      const newTabs = state.openTabIds.filter((t) => t !== id);
      return {
        files: newFiles,
        openTabIds: newTabs.length > 0 ? newTabs : [newFiles[0]?.id || ""],
        activeFileId:
          state.activeFileId === id ? newFiles[0]?.id || "" : state.activeFileId,
        edges: state.edges.filter(
          (e) => e.sourceNodeId !== id && e.targetNodeId !== id
        ),
      };
    }),

  renameFile: (id, newName) =>
    set((state) => ({
      files: state.files.map((f) =>
        f.id === id
          ? {
              ...f,
              name: newName,
              path: f.path.substring(0, f.path.lastIndexOf("/") + 1) + newName,
            }
          : f
      ),
    })),

  updateFileContent: (id, content) =>
    set((state) => ({
      files: state.files.map((f) =>
        f.id === id ? { ...f, content, status: "modified" } : f
      ),
    })),

  updateFilePosition: (id, x, y) =>
    set((state) => ({
      files: state.files.map((f) => (f.id === id ? { ...f, x, y } : f)),
    })),

  bringToFront: (id) =>
    set((state) => {
      const maxZ = Math.max(...state.files.map((f) => f.zIndex), 10);
      return {
        files: state.files.map((f) =>
          f.id === id ? { ...f, zIndex: maxZ + 1 } : f
        ),
        activeFileId: id,
      };
    }),

  setMode: (mode) => set({ mode }),

  setCanvasTransform: (canvasTransform) => set({ canvasTransform }),

  zoomBy: (delta) =>
    set((state) => {
      const newZoom = Math.min(
        Math.max(state.canvasTransform.zoom + delta, 0.25),
        1.75
      );
      return {
        canvasTransform: {
          ...state.canvasTransform,
          zoom: Number(newZoom.toFixed(2)),
        },
      };
    }),

  resetView: () =>
    set({
      canvasTransform: { panX: 80, panY: 60, zoom: 0.52 },
    }),

  startConnection: (sourceNodeId) =>
    set({ isConnectingNodes: true, connectionSourceId: sourceNodeId }),

  completeConnection: (targetNodeId) =>
    set((state) => {
      if (
        !state.connectionSourceId ||
        state.connectionSourceId === targetNodeId
      ) {
        return { isConnectingNodes: false, connectionSourceId: null };
      }
      const newEdge: ArchitecturalEdge = {
        id: `edge-${Date.now()}`,
        sourceNodeId: state.connectionSourceId,
        targetNodeId,
        label: "relates to",
        type: "data-flow",
        color: "#6366f1",
      };
      return {
        edges: [...state.edges, newEdge],
        isConnectingNodes: false,
        connectionSourceId: null,
      };
    }),

  cancelConnection: () =>
    set({ isConnectingNodes: false, connectionSourceId: null }),

  removeEdge: (edgeId) =>
    set((state) => ({
      edges: state.edges.filter((e) => e.id !== edgeId),
    })),

  addSuggestion: (suggestion) =>
    set((state) => ({
      suggestions: [
        ...state.suggestions,
        {
          ...suggestion,
          id: `sug-${Date.now()}`,
          createdAt: Date.now(),
          status: "pending",
        },
      ],
    })),

  acceptSuggestion: (suggestionId) =>
    set((state) => {
      const sug = state.suggestions.find((s) => s.id === suggestionId);
      if (!sug) return state;

      const targetFile = state.files.find((f) => f.id === sug.fileId);
      let updatedContent = targetFile?.content || "";

      if (targetFile) {
        if (updatedContent.includes(sug.originalText)) {
          updatedContent = updatedContent.replace(
            sug.originalText,
            sug.suggestedText
          );
        } else {
          updatedContent =
            updatedContent.slice(0, sug.from) +
            sug.suggestedText +
            updatedContent.slice(sug.to);
        }
      }

      return {
        files: state.files.map((f) =>
          f.id === sug.fileId ? { ...f, content: updatedContent } : f
        ),
        suggestions: state.suggestions.map((s) =>
          s.id === suggestionId ? { ...s, status: "accepted" } : s
        ),
      };
    }),

  rejectSuggestion: (suggestionId) =>
    set((state) => ({
      suggestions: state.suggestions.map((s) =>
        s.id === suggestionId ? { ...s, status: "rejected" } : s
      ),
    })),

  addComment: (fileId, lineNumber, snippet, initialMessage) =>
    set((state) => {
      const newThread: ContextualThread = {
        id: `thread-${Date.now()}`,
        fileId,
        lineNumber,
        charOffset: 0,
        anchorSnippet: snippet,
        author: state.currentUser,
        createdAt: Date.now(),
        resolved: false,
        messages: [
          {
            id: `msg-${Date.now()}`,
            author: state.currentUser,
            text: initialMessage,
            createdAt: Date.now(),
          },
        ],
      };
      return {
        comments: [...state.comments, newThread],
        activeCommentThreadId: newThread.id,
      };
    }),

  addCommentReply: (threadId, text) =>
    set((state) => ({
      comments: state.comments.map((th) =>
        th.id === threadId
          ? {
              ...th,
              messages: [
                ...th.messages,
                {
                  id: `msg-${Date.now()}`,
                  author: state.currentUser,
                  text,
                  createdAt: Date.now(),
                },
              ],
            }
          : th
      ),
    })),

  resolveComment: (threadId) =>
    set((state) => ({
      comments: state.comments.map((th) =>
        th.id === threadId ? { ...th, resolved: true } : th
      ),
      activeCommentThreadId:
        state.activeCommentThreadId === threadId
          ? null
          : state.activeCommentThreadId,
    })),

  setActiveCommentThread: (threadId) => set({ activeCommentThreadId: threadId }),

  toggleSidebar: () => set((state) => ({ isSidebarOpen: !state.isSidebarOpen })),
  toggleTerminal: () =>
    set((state) => ({ isTerminalOpen: !state.isTerminalOpen })),
  setTerminalOpen: (open) => set({ isTerminalOpen: open }),
  setActiveTerminalTab: (activeTerminalTab) => set({ activeTerminalTab }),
  setCommandPaletteOpen: (isCommandPaletteOpen) => set({ isCommandPaletteOpen }),
  setCursorPos: (cursorPos) => set({ cursorPos }),
  setAiPromptOpen: (isAiPromptOpen) => set({ isAiPromptOpen }),

  triggerAiGenerate: async (prompt: string) => {
    set({ isAiGenerating: true });
    // Realistic AI refinement response
    await new Promise((resolve) => setTimeout(resolve, 800));

    const state = get();
    const currentFile = state.files.find((f) => f.id === state.activeFileId);

    if (currentFile) {
      const original = currentFile.content;
      // Propose an inline suggestion diff
      get().addSuggestion({
        fileId: currentFile.id,
        author: MOCK_USERS[1], // CruxAI
        from: 0,
        to: original.length,
        originalText: "const timeout = Math.min(this.retryAttempts * 1000, 30000);",
        suggestedText:
          "// AI-Refactored: Monotonic exponential backoff with full jitter\n    const jitter = Math.random() * 500;\n    const timeout = Math.min(Math.pow(2, this.retryAttempts) * 1000 + jitter, 30000);",
        description: `AI Proposal: ${prompt || "Optimized reconnection backoff with jitter"}`,
      });
    }

    set({ isAiGenerating: false, isAiPromptOpen: false });
  },

  updateRemoteCursor: (userId: string, data: Partial<SpatialCursor>) =>
    set((state) => {
      const existing = state.remoteCursors[userId];
      if (!existing) return state;
      return {
        remoteCursors: {
          ...state.remoteCursors,
          [userId]: {
            ...existing,
            ...data,
            lastUpdated: Date.now(),
          },
        },
      };
    }),

  setFlowSpeedFactor: (flowSpeedFactor) => set({ flowSpeedFactor }),
  toggleFlowPause: () => set((state) => ({ isFlowPaused: !state.isFlowPaused })),
  setFocusedEdgeId: (focusedEdgeId) => set({ focusedEdgeId }),
  togglePipelineTracker: () => set((state) => ({ isPipelineTrackerOpen: !state.isPipelineTrackerOpen })),
  setPipelineTrackerOpen: (isPipelineTrackerOpen) => set({ isPipelineTrackerOpen }),

  setOnboarded: (isOnboarded) => {
    if (typeof window !== "undefined") {
      if (isOnboarded) {
        localStorage.setItem("crux_onboarded", "true");
      } else {
        localStorage.removeItem("crux_onboarded");
      }
    }
    set({ isOnboarded });
  },

  setUserProfile: (profile) =>
    set((state) => {
      const updatedUser = {
        ...state.currentUser,
        ...profile,
      };
      if (typeof window !== "undefined") {
        localStorage.setItem("crux_user_profile", JSON.stringify(updatedUser));
        localStorage.setItem("crux_onboarded", "true");
      }
      return {
        currentUser: updatedUser,
        isOnboarded: true,
      };
    }),

  setIdentityDrawerOpen: (isIdentityDrawerOpen) => set({ isIdentityDrawerOpen }),
  setShareModalOpen: (isShareModalOpen) => set({ isShareModalOpen }),
  setInboxOpen: (isInboxOpen) => set({ isInboxOpen }),

  toggleViewerLock: () => set((state) => ({ viewerLock: !state.viewerLock })),
  setViewerLock: (viewerLock) => set({ viewerLock }),
  setAccessLevel: (accessLevel) => set({ accessLevel }),
  setAllowedFiles: (allowedFiles) => set({ allowedFiles }),
  setAllowedLineRange: (allowedLineRange) => set({ allowedLineRange }),

  sendInvite: (inviteData) => {
    const newInvite: ShareInvite = {
      ...inviteData,
      id: `inv-${Date.now()}`,
      timestamp: Date.now(),
      status: "pending",
    };
    set((state) => ({
      inboxInvites: [newInvite, ...state.inboxInvites],
      viewerLock: inviteData.viewerLock !== undefined ? inviteData.viewerLock : state.viewerLock,
    }));
  },

  acceptInvite: (inviteId) =>
    set((state) => {
      const invite = state.inboxInvites.find((i) => i.id === inviteId);
      if (!invite) return state;
      return {
        inboxInvites: state.inboxInvites.map((i) =>
          i.id === inviteId ? { ...i, status: "accepted" as const } : i
        ),
        accessLevel: invite.accessLevel,
        allowedFiles: invite.allowedFiles || state.allowedFiles,
        allowedLineRange: invite.allowedLineRange,
        viewerLock: invite.viewerLock,
        isInboxOpen: false,
      };
    }),

  declineInvite: (inviteId) =>
    set((state) => ({
      inboxInvites: state.inboxInvites.map((i) =>
        i.id === inviteId ? { ...i, status: "declined" as const } : i
      ),
    })),
}));
