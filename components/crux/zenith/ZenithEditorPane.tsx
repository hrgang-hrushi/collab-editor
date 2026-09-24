"use client";

import React, { useState, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { invoke } from "@tauri-apps/api/core";
import CodeMirrorEditor from "@/components/editor/CodeMirrorEditor";
import {
  Play,
  Save,
  Check,
  SplitSquareVertical,
  Code2,
  FileCode2,
  Loader2,
  Columns,
  Lock,
  Eye,
  Search,
  X,
  Share2,
  Link2,
} from "lucide-react";
import { Rise, Morph } from "cube-motion/react";
import { CrexWebGpuCanvas } from "../webgpu/CrexWebGpuCanvas";
import { triggerHaptic } from "@/lib/haptics";

export default function ZenithEditorPane() {
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const openTabIds = useWorkspaceStore((state) => state.openTabIds);
  const closeTab = useWorkspaceStore((state) => state.closeTab);
  const runActiveFile = useWorkspaceStore((state) => state.runActiveFile);
  const runActiveFileInTerminal = useWorkspaceStore((state) => state.runActiveFileInTerminal);
  const saveActiveFile = useWorkspaceStore((state) => state.saveActiveFile);
  const isExecuting = useWorkspaceStore((state) => state.isExecuting);
  const updateFileContent = useWorkspaceStore((state) => state.updateFileContent);
  const viewerLock = useWorkspaceStore((state) => state.viewerLock);
  const toggleViewerLock = useWorkspaceStore((state) => state.toggleViewerLock);
  const accessLevel = useWorkspaceStore((state) => state.accessLevel);
  const allowedFiles = useWorkspaceStore((state) => state.allowedFiles);
  const activeSessionId = useWorkspaceStore((state) => state.activeSessionId);
  const setActiveSessionId = useWorkspaceStore((state) => state.setActiveSessionId);

  const [savedFeedback, setSavedFeedback] = useState(false);
  const [isSplitScreen, setIsSplitScreen] = useState(false);
  const [editorMode, setEditorMode] = useState<"editor" | "diff" | "hardware">("editor");
  const [diffState, setDiffState] = useState<"pending" | "accepted" | "rejected">("pending");
  const [isFindOpen, setIsFindOpen] = useState(false);
  const [findQuery, setFindQuery] = useState("");
  const [findMatchCount, setFindMatchCount] = useState(0);
  const [copiedLink, setCopiedLink] = useState(false);

  const activeFile = files.find((f) => f.id === activeFileId) || files[0];

  useEffect(() => {
    if (files.length === 0) {
      useWorkspaceStore.getState().loadStarterWorkspace();
    }
  }, [files.length]);

  const handleCopyP2PLink = () => {
    if (typeof window === "undefined") return;
    triggerHaptic("click");
    let sid = activeSessionId;
    if (!sid) {
      const params = new URLSearchParams(window.location.search);
      sid = params.get("session") || params.get("room");
      if (!sid && window.location.hash.startsWith("#session-")) {
        sid = window.location.hash.replace("#session-", "").split("?")[0];
      }
      if (!sid) {
        sid = "session-" + Math.random().toString(36).substring(2, 9);
      }
      setActiveSessionId(sid);
    }

    const currentParams = new URLSearchParams(window.location.search);
    currentParams.set("session", sid);
    const newRelativePathQuery =
      window.location.pathname + "?" + currentParams.toString() + window.location.hash;
    window.history.replaceState(null, "", newRelativePathQuery);

    if (!window.location.hash || !window.location.hash.includes(sid)) {
      window.location.hash = sid.startsWith("session-") ? sid : `session-${sid}`;
    }

    const fullUrl = `${window.location.origin}${window.location.pathname}?session=${sid}&access=full#${
      sid.startsWith("session-") ? sid : `session-${sid}`
    }`;
    navigator.clipboard.writeText(fullUrl);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const isFileRestricted = accessLevel === "limited" && !allowedFiles.includes(activeFile?.name || "");
  const isViewerOnly = accessLevel === "viewer";
  const isBinaryFile = activeFile?.binaryBase64 !== undefined;
  const isReadOnly = viewerLock || isViewerOnly || isFileRestricted || isBinaryFile;

  const openFiles = files.filter(
    (f) => openTabIds.includes(f.id) || f.id === activeFile?.id
  );

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === "Enter" || e.key.toLowerCase() === "r")) {
        e.preventDefault();
        if (!isReadOnly) {
          runActiveFileInTerminal();
        }
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        if (!isReadOnly) {
          saveActiveFile().then((ok) => {
            if (ok) {
              setSavedFeedback(true);
              setTimeout(() => setSavedFeedback(false), 1200);
            }
          });
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [runActiveFile, runActiveFileInTerminal, saveActiveFile, isReadOnly]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "f") {
        e.preventDefault();
        setIsFindOpen(true);
      }
      if (e.key === "Escape" && isFindOpen) {
        setIsFindOpen(false);
        setFindQuery("");
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [isFindOpen]);

  useEffect(() => {
    if (!findQuery || !activeFile) { setFindMatchCount(0); return; }
    const regex = new RegExp(findQuery.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    const matches = activeFile.content.match(regex);
    setFindMatchCount(matches?.length || 0);
  }, [findQuery, activeFile]);


  const handleSave = async () => {
    if (isReadOnly) return;
    const ok = await saveActiveFile();
    if (ok) {
      setSavedFeedback(true);
      setTimeout(() => setSavedFeedback(false), 1200);
    }
  };

  const handleAcceptDiff = () => {
    if (isReadOnly) return;
    setDiffState("accepted");
    if (activeFile && activeFile.name === "stream_syncer.ts") {
      const newCode = `import { LocalDaemonClient } from "@crux/daemon";

export class StreamSyncer {
  timeout = Math.min(5 * 1000, 30000);
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
`;
      updateFileContent(activeFile.id, newCode);
    }
  };

  const handleRejectDiff = () => {
    if (isReadOnly) return;
    setDiffState("rejected");
    if (activeFile && activeFile.name === "stream_syncer.ts") {
      const newCode = `import { LocalDaemonClient } from "@crux/daemon";

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
`;
      updateFileContent(activeFile.id, newCode);
    }
  };

  const isStreamSyncer = activeFile?.name === "stream_syncer.ts";

  return (
    <main className="flex-1 bg-[#000000] flex flex-col relative overflow-hidden font-sans select-text">
      {/* Crex Header: h-8 bg-[#111111] border-b border-[#222222] */}
      <div className="flex h-8 border-b border-[#222222] bg-[#111111] items-center justify-between select-none shrink-0 overflow-x-auto">
        <Rise as="div" targets="children" className="flex items-center h-full overflow-x-auto">
          {openFiles.map((tab) => {
            const isActive = tab.id === activeFile?.id;
            return (
              <div
                key={tab.id}
                onClick={() => setActiveFile(tab.id)}
                className={`px-3 border-r border-[#222222] text-[11px] font-sans uppercase tracking-tight flex items-center gap-2 cursor-pointer transition-none shrink-0 h-full ${
                  isActive
                    ? "bg-[#000000] text-white font-medium"
                    : "bg-[#111111] text-[#444444] hover:text-white"
                }`}
              >
                <span>{tab.name}</span>
                {(tab.content || "").split('\n').length > 1 && (
                  <span className="text-[9px] text-[#444444] font-mono shrink-0 hidden md:inline">
                    {(tab.content || "").split('\n').length}L
                  </span>
                )}
                {tab.isDirty && (
                  <span className="w-1.5 h-1.5 bg-white shrink-0" title="Unsaved changes" />
                )}
                {openFiles.length > 1 && (
                  <span
                    onClick={(e) => {
                      e.stopPropagation();
                      closeTab(tab.id);
                    }}
                    className="text-[#444444] hover:text-white cursor-pointer ml-1"
                  >
                    ×
                  </span>
                )}
              </div>
            );
          })}
        </Rise>

        {/* Tab Strip Right Controls */}
        <div className="flex items-center gap-1.5 px-3 shrink-0 bg-surface h-full">
          <button
            onClick={() => setEditorMode(editorMode === "hardware" ? "editor" : "hardware")}
            className={`px-2 py-0.5 text-[10px] font-mono border uppercase transition-none mr-1 ${
              editorMode === "hardware"
                ? "bg-white text-black border-white font-bold"
                : "bg-transparent text-[#888888] border-[#222222] hover:text-white hover:border-white"
            }`}
            title="Toggle Hardware View"
          >
            {editorMode === "hardware" ? "HARDWARE VIEW: ON" : "HARDWARE VIEW"}
          </button>

          {isStreamSyncer && (
            <button
              onClick={() => setEditorMode(editorMode === "diff" ? "editor" : "diff")}
              className={`px-2 py-0.5 text-[10px] font-mono border uppercase transition-none mr-2 ${
                editorMode === "diff"
                  ? "bg-white text-black border-white font-bold"
                  : "bg-void border-grid text-muted hover:text-signal"
              }`}
              title="Toggle Suggestion Review"
            >
              {editorMode === "diff" ? "Diff: On" : "Review Changes"}
            </button>
          )}

          <button
            onClick={() => runActiveFileInTerminal()}
            disabled={isExecuting || !activeFile || isReadOnly}
            title={isBinaryFile ? "Binary files cannot run" : isReadOnly ? "Execution disabled (Viewer Lock active)" : "Run Code (⌘+Enter)"}
            className="px-2 py-0.5 border border-grid bg-void text-muted hover:text-signal disabled:opacity-30 transition-colors flex items-center gap-1 font-mono text-[10px] uppercase font-bold"
          >
            {isExecuting ? (
              <Loader2 className="w-3 h-3 animate-spin text-signal" />
            ) : (
              <Play className="w-3 h-3 fill-current text-accent1" />
            )}
            <span>RUN ↵</span>
          </button>

          <button
            onClick={handleSave}
            disabled={isReadOnly}
            title={isBinaryFile ? "Binary files are read-only; export preserves the original bytes" : isReadOnly ? "Saving disabled (Viewer Lock active)" : "Save (⌘S)"}
            className="p-1 border border-grid bg-void text-muted hover:text-signal disabled:opacity-30 transition-colors"
          >
            {savedFeedback ? <Check className="w-3.5 h-3.5 text-[#00FF00]" /> : <Save className="w-3.5 h-3.5" />}
          </button>

          <button
            onClick={handleCopyP2PLink}
            title="Copy share link"
            className={`px-2 py-0.5 text-[10px] font-mono border transition-none flex items-center gap-1 uppercase ${
              copiedLink
                ? "bg-white text-black border-white font-bold"
                : "bg-[#000000] text-[#FFFFFF] border-[#222222] hover:bg-white hover:text-black"
            }`}
          >
            {copiedLink ? (
              <Check className="w-3 h-3 text-black" />
            ) : (
              <Link2 className="w-3 h-3" />
            )}
            <Morph active={copiedLink} off="SHARE LINK" on="COPIED" />
          </button>

          <button
            onClick={() => setIsSplitScreen(!isSplitScreen)}
            title="Split Editor Pane"
            className={`p-1 border border-grid transition-colors ${
              isSplitScreen ? "bg-grid text-signal" : "bg-void text-muted hover:text-signal"
            }`}
          >
            <SplitSquareVertical className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Breadcrumb Bar */}
      {activeFile && (
        <div className="h-7 px-4 border-b border-[#111111] bg-[#050505] flex items-center gap-1 text-[11px] font-mono text-[#555555] shrink-0 select-none overflow-hidden">
          <span className="text-[#444444]">WORKSPACE</span>
          <span className="text-[#333333] mx-1">/</span>
          {activeFile.path
            ? activeFile.path.split('/').filter(Boolean).map((segment, idx, arr) => (
                <React.Fragment key={idx}>
                  <span className={idx === arr.length - 1 ? 'text-[#888888]' : 'text-[#444444]'}>
                    {segment}
                  </span>
                  {idx < arr.length - 1 && <span className="text-[#333333] mx-1">/</span>}
                </React.Fragment>
              ))
            : <span className="text-[#888888]">{activeFile.name}</span>
          }
        </div>
      )}

      {/* Find Bar (Cmd+F) */}
      {isFindOpen && (
        <div className="h-9 border-b border-[#222222] bg-[#0A0A0A] flex items-center gap-3 px-4 shrink-0">
          <Search className="w-3.5 h-3.5 text-[#555555] shrink-0" />
          <input
            autoFocus
            type="text"
            value={findQuery}
            onChange={(e) => setFindQuery(e.target.value)}
            placeholder="Find in file..."
            className="flex-1 bg-transparent border-none outline-none text-xs font-mono text-white placeholder-[#444444]"
          />
          {findQuery && (
            <span className="text-[11px] font-mono text-[#555555] shrink-0">
              {findMatchCount} {findMatchCount === 1 ? 'match' : 'matches'}
            </span>
          )}
          <button
            onClick={() => { setIsFindOpen(false); setFindQuery(''); }}
            className="p-1 text-[#555555] hover:text-white transition-colors shrink-0"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* VIEWER LOCK / RESTRICTED ACCESS NOTIFICATION BANNER */}
      {isReadOnly && (
        <div className={`bg-[#0A0A0A] border-b px-4 py-1.5 flex items-center justify-between text-[11px] font-mono shrink-0 select-none z-20 ${isBinaryFile ? "border-[#222222]" : "border-[#FF453A]/40"}`}>
          <div className={`flex items-center gap-2 ${isBinaryFile ? "text-white" : "text-accent2"}`}>
            <Lock className={`w-3.5 h-3.5 shrink-0 ${isBinaryFile ? "text-white" : "text-accent2"}`} />
            <span className="font-semibold tracking-wider uppercase">
              {isBinaryFile
                ? "BINARY FILE — READ-ONLY PREVIEW; ORIGINAL BYTES PRESERVED FOR EXPORT"
                : viewerLock
                ? "VIEWER LOCK ACTIVE — ALL WORKSPACE WRITES ARE SUSPENDED BY HOST"
                : isViewerOnly
                ? "VIEWER ROLE ACTIVE — READ-ONLY ACCESS TO ALL WORKSPACE BUFFERS"
                : `LIMITED ACCESS — BUFFER '${activeFile?.name}' IS WRITE-PROTECTED`}
            </span>
          </div>
          {viewerLock && (
            <button
              onClick={toggleViewerLock}
              className="px-2 py-0.5 border border-[#FF453A]/60 bg-void text-accent2 hover:bg-[#FF453A] hover:text-white transition-colors text-[10px] uppercase font-bold"
              title="Override Viewer Lock and enable writes"
            >
              Unlock (Host)
            </button>
          )}
        </div>
      )}

      {/* Editor Surface */}
      <div className="flex-1 w-full h-full flex flex-row overflow-hidden bg-void">
        {editorMode === "hardware" ? (
          <div className="w-full h-full flex flex-col overflow-hidden">
            <CrexWebGpuCanvas
              initialCode={activeFile?.content || ""}
              initialLanguage={activeFile?.language || "rust"}
              onCodeChange={(newCode) => {
                if (activeFile) {
                  updateFileContent(activeFile.id, newCode);
                }
              }}
            />
          </div>
        ) : (
          <div className={`h-full overflow-hidden flex flex-col ${isSplitScreen ? "w-1/2" : "w-full"}`}>
            {isStreamSyncer && editorMode === "diff" ? (
              /* CANONICAL STREAM_SYNCER SUGGESTION REVIEW */
              <div className="flex-1 p-6 font-mono text-[13px] leading-loose text-muted overflow-auto">
              <div className="flex">
                <span className="w-8 text-[#444] select-none">1</span>
                <span>import &#123; LocalDaemonClient &#125; from &quot;@crux/daemon&quot;;</span>
              </div>
              <div className="flex">
                <span className="w-8 text-[#444] select-none">2</span>
              </div>
              <div className="flex">
                <span className="w-8 text-[#444] select-none">3</span>
                <span className="text-signal">export class StreamSyncer &#123;</span>
              </div>

              {/* SUGGESTING MODE DIFF */}
              <div className="my-4 border border-grid bg-void">
                <div className="flex justify-between items-center px-3 py-1.5 border-b border-grid bg-surface">
                  <div className="flex items-center gap-2">
                    <div className="w-1.5 h-1.5 bg-accent1"></div>
                    <span className="text-[11px] font-sans">
                      <span className="text-signal font-medium">Sarah L.</span> suggests an update
                      {diffState === "accepted" && (
                        <span className="ml-2 px-1.5 py-0.2 text-[9px] bg-void border border-grid text-[#00FF00] font-mono">
                          ACCEPTED
                        </span>
                      )}
                      {diffState === "rejected" && (
                        <span className="ml-2 px-1.5 py-0.2 text-[9px] bg-void border border-grid text-accent2 font-mono">
                          REJECTED
                        </span>
                      )}
                    </span>
                  </div>
                  <div className="flex gap-2">
                    {diffState === "pending" ? (
                      <>
                        <button
                          onClick={isReadOnly ? undefined : handleAcceptDiff}
                          disabled={isReadOnly}
                          title={isReadOnly ? "Workspace writes are frozen (Viewer Lock active)" : "Accept Suggested Update"}
                          className={`px-3 py-0.5 text-[10px] font-sans border transition-all ${
                            isReadOnly
                              ? "bg-void border-grid text-muted cursor-not-allowed opacity-40"
                              : "border-grid bg-signal text-void font-medium hover:opacity-90"
                          }`}
                        >
                          Accept
                        </button>
                        <button
                          onClick={isReadOnly ? undefined : handleRejectDiff}
                          disabled={isReadOnly}
                          title={isReadOnly ? "Workspace writes are frozen (Viewer Lock active)" : "Reject Suggested Update"}
                          className={`px-3 py-0.5 text-[10px] font-sans border transition-all ${
                            isReadOnly
                              ? "bg-void border-grid text-muted cursor-not-allowed opacity-40"
                              : "border-grid hover:text-signal text-muted"
                          }`}
                        >
                          Reject
                        </button>
                      </>
                    ) : (
                      <button
                        onClick={isReadOnly ? undefined : () => setDiffState("pending")}
                        disabled={isReadOnly}
                        className={`px-3 py-0.5 text-[10px] font-sans border transition-colors ${
                          isReadOnly
                            ? "bg-void border-grid text-muted cursor-not-allowed opacity-40"
                            : "border-grid text-muted hover:text-signal"
                        }`}
                      >
                        Reset Diff
                      </button>
                    )}
                  </div>
                </div>

                {/* Deletion Line */}
                {diffState !== "accepted" && (
                  <div className="px-2 py-1 bg-[#FF453A]/10 text-signal border-l-2 border-accent2 flex">
                    <span className="w-6 text-accent2/50 select-none">4</span>
                    <span className="line-through opacity-50">-   timeout = 5000;</span>
                  </div>
                )}

                {/* Addition Line */}
                {diffState !== "rejected" && (
                  <div className="px-2 py-1 bg-[#00FF00]/10 text-signal border-l-2 border-[#00FF00] flex relative">
                    <span className="w-6 text-[#00FF00]/50 select-none">4</span>
                    <span>+   timeout = Math.min(5 * 1000, 30000);</span>
                  </div>
                )}
              </div>

              <div className="flex">
                <span className="w-8 text-[#444] select-none">5</span>
                <span className="text-signal">  daemon = new LocalDaemonClient(&#123; port: 7447 &#125;);</span>
              </div>
              <div className="flex">
                <span className="w-8 text-[#444] select-none">6</span>
                <span className="text-signal">  async acquireLock(channel = &quot;stream-mesh-primary&quot;) &#123;</span>
              </div>
              <div className="flex relative">
                <span className="w-8 text-[#444] select-none">7</span>
                <span>    const ticket = await this.daemon.acquireLock(channel);</span>
              </div>
              <div className="flex">
                <span className="w-8 text-[#444] select-none">8</span>
                <span className="text-signal">    return ticket;</span>
              </div>
              <div className="flex">
                <span className="w-8 text-[#444] select-none">9</span>
                <span className="text-signal">  &#125;</span>
              </div>
              <div className="flex">
                <span className="w-8 text-[#444] select-none">10</span>
                <span className="text-signal">&#125;</span>
              </div>
            </div>
          ) : activeFile ? (
            /* RAW CODEMIRROR / GENERAL FILE EDITOR */
            <CodeMirrorEditor key={activeFile.id} file={activeFile} readOnly={isReadOnly} />
          ) : (
            <Rise className="w-full h-full flex flex-col items-center justify-center p-8 text-center bg-void">
              <div className="max-w-sm p-6 border border-grid bg-surface space-y-3">
                <div className="w-8 h-8 mx-auto bg-void border border-grid flex items-center justify-center">
                  <Code2 className="w-4 h-4 text-signal" />
                </div>
                <h3 className="text-sm font-semibold uppercase tracking-wider text-signal">Starter Workspace</h3>
                <p className="text-xs text-muted leading-relaxed">
                  No active file is open. Click below to load the starter workspace files.
                </p>
                <button
                  onClick={() => useWorkspaceStore.getState().loadStarterWorkspace()}
                  className="px-4 py-2 bg-white text-black hover:bg-[#CCCCCC] text-xs font-semibold uppercase tracking-wider transition-none w-full"
                >
                  Load Starter Files
                </button>
              </div>
            </Rise>
          )}
        </div>
        )}

        {/* Split Screen Secondary Editor */}
        {isSplitScreen && (
          <div className="w-1/2 h-full border-l border-grid flex flex-col bg-void">
            {files[1] ? (
              <CodeMirrorEditor key={files[1].id} file={files[1]} readOnly={isReadOnly} />
            ) : (
              <div className="p-4 text-xs font-mono text-muted">No secondary file to split</div>
            )}
          </div>
        )}
      </div>
    </main>
  );
}
