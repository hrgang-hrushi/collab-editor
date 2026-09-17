"use client";

import React, { useState, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import CodeMirrorEditor from "@/components/editor/CodeMirrorEditor";
import CruxAgentCursor from "../CruxAgentCursor";
import {
  FileCode2,
  Copy,
  Check,
  Columns,
  X,
  ShieldCheck,
  Database,
  Code2,
  Layers,
  Play,
  Save,
  Loader2,
} from "lucide-react";

export default function ZenithEditorPane() {
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const openTabIds = useWorkspaceStore((state) => state.openTabIds);
  const closeTab = useWorkspaceStore((state) => state.closeTab);
  const isExecuting = useWorkspaceStore((state) => state.isExecuting);
  const runActiveFile = useWorkspaceStore((state) => state.runActiveFile);
  const saveActiveFile = useWorkspaceStore((state) => state.saveActiveFile);

  const [copied, setCopied] = useState(false);
  const [savedFeedback, setSavedFeedback] = useState(false);
  const [isSplitScreen, setIsSplitScreen] = useState(false);

  // Active File Reference
  const activeFile =
    files.find((f) => f.id === activeFileId) ||
    files[0];

  // Open tabs list
  const openFiles = files.filter(
    (f) => openTabIds.includes(f.id) || f.id === activeFile?.id
  );

  // Keyboard shortcuts: Cmd+Enter to Run, Cmd+S to Save
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        runActiveFile();
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        saveActiveFile().then((ok) => {
          if (ok) {
            setSavedFeedback(true);
            setTimeout(() => setSavedFeedback(false), 1500);
          }
        });
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [runActiveFile, saveActiveFile]);

  const handleCopy = () => {
    if (activeFile) {
      navigator.clipboard?.writeText(activeFile.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleSave = async () => {
    const ok = await saveActiveFile();
    if (ok) {
      setSavedFeedback(true);
      setTimeout(() => setSavedFeedback(false), 1500);
    }
  };

  const getFileIcon = (name: string) => {
    if (name.includes("db") || name.includes("database")) {
      return <Database className="w-3.5 h-3.5 text-purple-400 shrink-0" />;
    }
    if (name.includes("auth") || name.includes("session")) {
      return <ShieldCheck className="w-3.5 h-3.5 text-cyan-400 shrink-0" />;
    }
    if (name.includes("spatial") || name.includes("engine")) {
      return <Layers className="w-3.5 h-3.5 text-amber-400 shrink-0" />;
    }
    return <FileCode2 className="w-3.5 h-3.5 text-[#5e6ad2] shrink-0" />;
  };

  const getContributorBadge = (name?: string, color?: string) => {
    if (!name) return null;
    const initial =
      name === "Sarah Lin"
        ? "SL"
        : name === "CruxAI"
        ? "AI"
        : name === "Marcus Vance"
        ? "MV"
        : name === "Contracts"
        ? "TS"
        : "PE";

    return (
      <span
        className="px-1 text-[8.5px] border font-mono tracking-tight"
        style={{
          backgroundColor: `${color || "#5e6ad2"}15`,
          borderColor: `${color || "#5e6ad2"}50`,
          color: color || "#5e6ad2",
        }}
      >
        {initial}
      </span>
    );
  };

  return (
    <div className="flex-1 h-full flex flex-col bg-black overflow-hidden font-sans select-text">
      {/* Tab Strip - Strict 1px borders, pure flat Linear/Vercel spec */}
      <div className="h-8 px-2 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A] select-none shrink-0">
        <div className="flex items-center h-full overflow-x-auto">
          {openFiles.map((tab) => {
            const isActive = tab.id === activeFile?.id;
            const tabColor = tab.contributorColor || "#5e6ad2";

            return (
              <div
                key={tab.id}
                onClick={() => setActiveFile(tab.id)}
                className={`group flex items-center gap-2 px-3 h-full text-xs font-sans border-r border-[#222222] cursor-pointer transition-colors shrink-0 ${
                  isActive
                    ? "bg-black text-[#f7f8f8] font-medium"
                    : "text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516]"
                }`}
                style={
                  isActive
                    ? {
                        borderTop: `2px solid ${tabColor}`,
                      }
                    : undefined
                }
              >
                {getFileIcon(tab.name)}
                <span className="truncate max-w-[130px]">{tab.name}</span>

                {/* Dirty / Modified indicator dot */}
                {tab.status === "modified" && (
                  <span className="w-1.5 h-1.5 rounded-full bg-[#f59e0b]" title="Unsaved changes" />
                )}

                {/* Multiplayer Presence Dot on Tab */}
                {tab.contributorName && getContributorBadge(tab.contributorName, tab.contributorColor)}

                {/* Close Tab Button */}
                {openFiles.length > 1 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      closeTab(tab.id);
                    }}
                    className="opacity-0 group-hover:opacity-100 hover:text-white p-0.5 ml-1 transition-opacity"
                  >
                    <X className="w-2.5 h-2.5" />
                  </button>
                )}
              </div>
            );
          })}
        </div>

        {/* Tab Strip Actions */}
        <div className="flex items-center gap-1.5 shrink-0">
          {/* ▶ Run Code Action Button */}
          <button
            onClick={() => runActiveFile()}
            disabled={isExecuting || !activeFile}
            title="Execute Active File (⌘ + Enter)"
            className="flex items-center gap-1 px-2.5 py-0.5 text-[11px] font-sans font-medium bg-[#27a644]/15 hover:bg-[#27a644]/25 text-[#27a644] border border-[#27a644]/40 transition-colors disabled:opacity-40"
          >
            {isExecuting ? (
              <Loader2 className="w-3 h-3 animate-spin" />
            ) : (
              <Play className="w-3 h-3 fill-current" />
            )}
            <span className="font-semibold">Run</span>
          </button>

          {/* Save File Button */}
          <button
            onClick={handleSave}
            title="Save Buffer (⌘S)"
            className={`flex items-center gap-1 px-2 py-0.5 text-[11px] font-sans font-medium border transition-colors ${
              savedFeedback
                ? "text-[#27a644] border-[#27a644]/50 bg-[#27a644]/10"
                : activeFile?.status === "modified"
                ? "text-[#f59e0b] border-[#f59e0b]/50 bg-[#f59e0b]/10 hover:bg-[#f59e0b]/20"
                : "text-[#8a8f98] border-[#222222] hover:text-[#f7f8f8] hover:bg-[#141516]"
            }`}
          >
            {savedFeedback ? (
              <Check className="w-3 h-3 text-[#27a644]" />
            ) : (
              <Save className="w-3 h-3" />
            )}
            <span className="hidden sm:inline">{savedFeedback ? "Saved" : "Save"}</span>
          </button>

          <div className="h-3 w-[1px] bg-[#222222] hidden sm:block" />

          {/* Split Screen Toggle Button */}
          <button
            onClick={() => setIsSplitScreen(!isSplitScreen)}
            title="Toggle Split-Screen AI Co-Pilot block"
            className={`flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-sans font-medium border transition-colors ${
              isSplitScreen
                ? "bg-[#141516] text-[#5e6ad2] border-[#5e6ad2]/50"
                : "bg-transparent text-[#8a8f98] hover:text-[#f7f8f8] border-[#222222]"
            }`}
          >
            <Columns className="w-3 h-3" />
            <span className="hidden sm:inline">Split: @CruxAI</span>
          </button>

          {/* Copy Button */}
          <button
            onClick={handleCopy}
            title={`Copy ${activeFile?.name || "buffer"}`}
            className="p-1 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] border border-transparent hover:border-[#222222] transition-colors"
          >
            {copied ? (
              <Check className="w-3 h-3 text-[#27a644]" />
            ) : (
              <Copy className="w-3 h-3" />
            )}
          </button>
        </div>
      </div>

      {/* Main Central Editor Area - Pure Black (bg-black) */}
      <div className="flex-1 w-full h-full flex flex-row overflow-hidden bg-black">
        {/* LEFT PANE: Real Interactive CodeMirror 6 Editor */}
        <div
          className={`h-full overflow-hidden bg-black transition-all ${
            isSplitScreen ? "w-1/2" : "w-full"
          }`}
        >
          {activeFile ? (
            <CodeMirrorEditor key={activeFile.id} file={activeFile} />
          ) : (
            <div className="w-full h-full flex flex-col items-center justify-center text-[#62666d] text-xs">
              <Code2 className="w-8 h-8 mb-2 text-[#333333]" />
              <span>No file open. Select a file from the explorer or create a new one.</span>
            </div>
          )}
        </div>

        {/* RIGHT PANE: AGENTIC AI CO-PILOT CURSOR (@CruxAI) IN SPLIT-SCREEN BLOCK */}
        {isSplitScreen && (
          <div className="w-1/2 h-full border-l border-[#222222] flex flex-col bg-black">
            <CruxAgentCursor isSplitPane={true} />
          </div>
        )}
      </div>
    </div>
  );
}
