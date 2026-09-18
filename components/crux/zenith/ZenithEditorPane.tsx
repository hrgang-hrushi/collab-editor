"use client";

import React, { useState, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
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
} from "lucide-react";
import CruxPointerCursor from "../CruxPointerCursor";

export default function ZenithEditorPane() {
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const openTabIds = useWorkspaceStore((state) => state.openTabIds);
  const closeTab = useWorkspaceStore((state) => state.closeTab);
  const runActiveFile = useWorkspaceStore((state) => state.runActiveFile);
  const saveActiveFile = useWorkspaceStore((state) => state.saveActiveFile);
  const isExecuting = useWorkspaceStore((state) => state.isExecuting);
  const updateFileContent = useWorkspaceStore((state) => state.updateFileContent);
  const viewerLock = useWorkspaceStore((state) => state.viewerLock);
  const toggleViewerLock = useWorkspaceStore((state) => state.toggleViewerLock);
  const accessLevel = useWorkspaceStore((state) => state.accessLevel);
  const allowedFiles = useWorkspaceStore((state) => state.allowedFiles);

  const [savedFeedback, setSavedFeedback] = useState(false);
  const [isSplitScreen, setIsSplitScreen] = useState(false);
  const [editorMode, setEditorMode] = useState<"zenith" | "raw">("raw");
  const [diffState, setDiffState] = useState<"pending" | "accepted" | "rejected">("pending");

  const activeFile = files.find((f) => f.id === activeFileId) || files[0];

  const isFileRestricted = accessLevel === "limited" && !allowedFiles.includes(activeFile?.name || "");
  const isViewerOnly = accessLevel === "viewer";
  const isReadOnly = viewerLock || isViewerOnly || isFileRestricted;

  const openFiles = files.filter(
    (f) => openTabIds.includes(f.id) || f.id === activeFile?.id
  );

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        if (!isReadOnly) {
          runActiveFile();
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
  }, [runActiveFile, saveActiveFile, isReadOnly]);

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
  const timeout = Math.min(attempt * 1000, 30000);
  async acquireLock() {
    await this.daemon.
  }
}
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
  const timeout = 5000;
  async acquireLock() {
    await this.daemon.
  }
}
`;
      updateFileContent(activeFile.id, newCode);
    }
  };

  const isStreamSyncer = activeFile?.name === "stream_syncer.ts";

  return (
    <main className="flex-1 bg-void flex flex-col relative overflow-hidden font-sans select-text">
      {/* Tab Strip (36px h-9, bg-surface border-b border-grid) */}
      <div className="flex h-9 border-b border-grid bg-surface items-center justify-between select-none shrink-0 overflow-x-auto">
        <div className="flex items-center h-full overflow-x-auto">
          {openFiles.map((tab) => {
            const isActive = tab.id === activeFile?.id;
            return (
              <div
                key={tab.id}
                onClick={() => setActiveFile(tab.id)}
                className={`px-4 py-2 border-r border-grid text-[11px] font-mono flex items-center gap-3 cursor-pointer transition-colors shrink-0 h-full ${
                  isActive
                    ? "bg-void text-signal font-medium"
                    : "bg-surface text-muted hover:text-signal"
                }`}
              >
                <span>{tab.name}</span>
                {openFiles.length > 1 && (
                  <span
                    onClick={(e) => {
                      e.stopPropagation();
                      closeTab(tab.id);
                    }}
                    className="text-muted hover:text-signal cursor-pointer"
                  >
                    ×
                  </span>
                )}
              </div>
            );
          })}
        </div>

        {/* Tab Strip Right Controls */}
        <div className="flex items-center gap-1.5 px-3 shrink-0 bg-surface h-full">
          {isStreamSyncer && (
            <button
              onClick={() => setEditorMode(editorMode === "zenith" ? "raw" : "zenith")}
              className="px-2 py-0.5 text-[10px] font-mono border border-grid bg-void text-muted hover:text-signal uppercase transition-colors mr-2"
              title="Toggle between Live Editor and Diff Mock"
            >
              {editorMode === "zenith" ? "Edit Code" : "Diff Mock"}
            </button>
          )}

          <button
            onClick={() => runActiveFile()}
            disabled={isExecuting || !activeFile || isReadOnly}
            title={isReadOnly ? "Execution disabled (Viewer Lock active)" : "Run Code (⌘+Enter)"}
            className="p-1 border border-grid bg-void text-muted hover:text-signal disabled:opacity-30 transition-colors"
          >
            {isExecuting ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin text-signal" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-current text-accent1" />
            )}
          </button>

          <button
            onClick={handleSave}
            disabled={isReadOnly}
            title={isReadOnly ? "Saving disabled (Viewer Lock active)" : "Save (⌘S)"}
            className="p-1 border border-grid bg-void text-muted hover:text-signal disabled:opacity-30 transition-colors"
          >
            {savedFeedback ? <Check className="w-3.5 h-3.5 text-[#00FF00]" /> : <Save className="w-3.5 h-3.5" />}
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

      {/* VIEWER LOCK / RESTRICTED ACCESS NOTIFICATION BANNER */}
      {isReadOnly && (
        <div className="bg-[#0A0A0A] border-b border-[#FF453A]/40 px-4 py-1.5 flex items-center justify-between text-[11px] font-mono shrink-0 select-none z-20">
          <div className="flex items-center gap-2 text-accent2">
            <Lock className="w-3.5 h-3.5 text-accent2 shrink-0" />
            <span className="font-semibold tracking-wider uppercase">
              {viewerLock
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
        <div className={`h-full overflow-hidden flex flex-col ${isSplitScreen ? "w-1/2" : "w-full"}`}>
          {isStreamSyncer && editorMode === "zenith" ? (
            /* CANONICAL ZENITH STREAM_SYNCER VIEW */
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
                    <span className="line-through opacity-50">- const timeout = 5000;</span>
                  </div>
                )}

                {/* Addition Line with Peer Cursor */}
                {diffState !== "rejected" && (
                  <div className="px-2 py-1 bg-[#00FF00]/10 text-signal border-l-2 border-[#00FF00] flex relative">
                    <span className="w-6 text-[#00FF00]/50 select-none">4</span>
                    <span>+ const timeout = Math.min(attempt * 1000, 30000);</span>

                    {/* Collaborative Peer Cursor: Sarah Lin */}
                    <div className="absolute top-0 left-[390px] pointer-events-none z-10">
                      <CruxPointerCursor
                        name="Sarah Lin"
                        uid="CRX-9941-SL"
                        color="#38b6ff"
                      />
                    </div>
                  </div>
                )}
              </div>

              <div className="flex">
                <span className="w-8 text-[#444] select-none">5</span>
                <span className="text-signal">  async acquireLock() &#123;</span>
              </div>
              <div className="flex relative">
                <span className="w-8 text-[#444] select-none">6</span>
                <span>    await this.daemon.</span>

                {/* AI Co-Pilot Cursor: CruxAI */}
                <div className="absolute top-0 left-[210px] pointer-events-none z-10">
                  <CruxPointerCursor
                    name="CruxAI"
                    uid="CRX-0001-AI"
                    color="#ff5757"
                  />
                </div>
              </div>
              <div className="flex">
                <span className="w-8 text-[#444] select-none">7</span>
                <span className="text-signal">  &#125;</span>
              </div>
            </div>
          ) : activeFile ? (
            /* RAW CODEMIRROR / GENERAL FILE EDITOR */
            <CodeMirrorEditor key={activeFile.id} file={activeFile} readOnly={isReadOnly} />
          ) : (
            <div className="w-full h-full flex flex-col items-center justify-center text-muted font-mono text-xs">
              <Code2 className="w-8 h-8 mb-3 text-grid" />
              <span>NO BUFFER ACTIVE. SELECT A FILE FROM EXPLORER.</span>
            </div>
          )}
        </div>

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
