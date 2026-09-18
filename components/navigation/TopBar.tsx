"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { EditorInteractionMode } from "@/lib/types";
import {
  Code,
  Sparkles,
  Layers,
  Share2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Plus,
  Command,
  Check,
  Network,
  Users,
} from "lucide-react";

export default function TopBar() {
  const mode = useWorkspaceStore((state) => state.mode);
  const setMode = useWorkspaceStore((state) => state.setMode);
  const activeUsers = useWorkspaceStore((state) => state.activeUsers);
  const canvasTransform = useWorkspaceStore((state) => state.canvasTransform);
  const zoomBy = useWorkspaceStore((state) => state.zoomBy);
  const resetView = useWorkspaceStore((state) => state.resetView);
  const setCommandPaletteOpen = useWorkspaceStore((state) => state.setCommandPaletteOpen);
  const files = useWorkspaceStore((state) => state.files);
  const edges = useWorkspaceStore((state) => state.edges);

  const [copiedShare, setCopiedShare] = useState(false);
  const [showNewFileModal, setShowNewFileModal] = useState(false);
  const [newFileName, setNewFileName] = useState("");

  const handleShare = () => {
    navigator.clipboard?.writeText(window.location.href);
    setCopiedShare(true);
    setTimeout(() => setCopiedShare(false), 2000);
  };

  const handleCreateFile = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFileName.trim()) return;

    const ext = newFileName.split(".").pop() || "ts";
    let lang: any = "typescript";
    if (ext === "js" || ext === "jsx") lang = "javascript";
    if (ext === "py") lang = "python";
    if (ext === "css") lang = "css";
    if (ext === "html") lang = "html";
    if (ext === "json") lang = "json";

    const newId = `file-${Date.now()}`;
    const newFile = {
      id: newId,
      name: newFileName.trim(),
      path: `src/${newFileName.trim()}`,
      language: lang,
      content: `// ${newFileName.trim()}\n// Multiplayer collaborative buffer\n\nexport function init() {\n  console.log("Ready");\n}\n`,
      x: 300 + Math.random() * 200,
      y: 200 + Math.random() * 150,
      width: 520,
      height: 420,
      zIndex: 20,
    };

    useWorkspaceStore.setState((state) => ({
      files: [...state.files, newFile],
      activeFileId: newId,
    }));

    setNewFileName("");
    setShowNewFileModal(false);
  };

  return (
    <>
      <header className="fixed top-3 left-4 right-4 z-40 h-14 px-4 flex items-center justify-between glass-panel rounded-2xl shadow-glass select-none border border-white/10">
        {/* Left: Brand & Room */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded bg-[#007acc] flex items-center justify-center">
              <span className="font-mono font-bold text-xs text-white">
                AU
              </span>
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-sm tracking-tight text-[#cccccc] font-sans">
                  Aura
                </span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#333333] border border-[#3e3e42] text-[#cccccc] font-mono">
                  PRO
                </span>
              </div>
              <p className="text-[10px] text-[#858585] font-mono -mt-0.5">
                multiplayer-mesh #9214
              </p>
            </div>
          </div>

          <div className="h-4 w-[1px] bg-white/10 mx-1 hidden sm:block" />

          {/* Mode Selector Pill */}
          <div className="flex items-center p-1 rounded-xl bg-void-950/80 border border-white/10">
            <button
              onClick={() => setMode("edit")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium transition ${
                mode === "edit"
                  ? "bg-white/15 text-white shadow-sm"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Code className="w-3.5 h-3.5 text-collab-cyan" />
              <span>Code</span>
            </button>

            <button
              onClick={() => setMode("suggest")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium transition ${
                mode === "suggest"
                  ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 shadow-sm"
                  : "text-slate-400 hover:text-emerald-300"
              }`}
            >
              <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
              <span>Suggesting</span>
            </button>

            <button
              onClick={() => setMode("canvas")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium transition ${
                mode === "canvas"
                  ? "bg-collab-purple/20 text-purple-200 border border-collab-purple/30 shadow-sm"
                  : "text-slate-400 hover:text-purple-200"
              }`}
            >
              <Layers className="w-3.5 h-3.5 text-collab-purple" />
              <span>Canvas Mode</span>
            </button>
          </div>
        </div>

        {/* Center: Quick Stats / Canvas State */}
        <div className="hidden lg:flex items-center gap-3 text-xs text-slate-400 font-mono">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/5 border border-white/5">
            <Network className="w-3.5 h-3.5 text-collab-cyan" />
            <span>{files.length} Files</span>
            <span className="text-white/20">|</span>
            <span>{edges.length} Wires</span>
          </div>

          {/* Zoom HUD */}
          <div className="flex items-center gap-1 bg-void-950/80 p-0.5 rounded-lg border border-white/10">
            <button
              onClick={() => zoomBy(-0.1)}
              title="Zoom Out"
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 transition"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="text-[11px] px-1 text-slate-300 min-w-[36px] text-center">
              {Math.round(canvasTransform.zoom * 100)}%
            </span>
            <button
              onClick={() => zoomBy(0.1)}
              title="Zoom In"
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 transition"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={resetView}
              title="Reset View (100%)"
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-white/10 transition"
            >
              <RotateCcw className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Right: Multiplayer Avatar Stack & Actions */}
        <div className="flex items-center gap-3">
          {/* Active Collaborators */}
          <div className="flex items-center -space-x-2">
            {activeUsers.map((user) => (
              <div
                key={user.id}
                title={`${user.name} ${user.isSelf ? "(You)" : "(Active)"}`}
                className="relative group cursor-pointer"
              >
                <div
                  className="w-7 h-7 rounded-full border-2 border-void-950 flex items-center justify-center text-[10px] font-bold text-white shadow-md transition transform group-hover:-translate-y-1 group-hover:z-10"
                  style={{ backgroundColor: user.color }}
                >
                  {user.name[0]}
                </div>
                {/* Active live presence indicator */}
                <span
                  className="absolute bottom-0 right-0 w-2 h-2 rounded-full border border-[#1e1e1e]"
                  style={{ backgroundColor: user.color }}
                />
              </div>
            ))}
          </div>

          <div className="h-4 w-[1px] bg-white/10 mx-0.5" />

          {/* New File Button */}
          <button
            onClick={() => setShowNewFileModal(true)}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-200 border border-white/10 text-xs font-medium transition"
          >
            <Plus className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">File</span>
          </button>

          {/* Command Palette trigger */}
          <button
            onClick={() => setCommandPaletteOpen(true)}
            className="p-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 text-xs transition flex items-center gap-1"
            title="Command Palette (Cmd+K)"
          >
            <Command className="w-3.5 h-3.5" />
            <span className="text-[10px] text-slate-400 font-mono hidden md:inline">
              K
            </span>
          </button>

          {/* Instant Share Link */}
          <button
            onClick={handleShare}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-none bg-black hover:bg-[#222222] text-white border border-[#222222] text-xs font-semibold transition-colors"
          >
            {copiedShare ? (
              <>
                <Check className="w-3.5 h-3.5 text-white" />
                <span className="text-white">Link Copied!</span>
              </>
            ) : (
              <>
                <Share2 className="w-3.5 h-3.5 text-[#007AFF]" />
                <span>Share</span>
              </>
            )}
          </button>
        </div>
      </header>

      {/* New File Modal */}
      {showNewFileModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 animate-in fade-in">
          <div className="w-full max-w-sm p-4 rounded-none bg-[#0A0A0A] shadow-[4px_4px_0px_#222222] border border-[#222222] text-white space-y-3 font-sans">
            <h3 className="font-semibold text-xs text-white uppercase tracking-widest">Create New File Node</h3>
            <p className="text-xs text-[#888888]">
              Enter file name with extension (e.g. <code>apiHandler.ts</code>, <code>style.css</code>).
            </p>
            <form onSubmit={handleCreateFile} className="space-y-3">
              <input
                type="text"
                autoFocus
                value={newFileName}
                onChange={(e) => setNewFileName(e.target.value)}
                placeholder="e.g. databaseClient.ts"
                className="w-full px-3 py-2 rounded-none bg-black border border-[#222222] text-xs text-white focus:outline-none focus:border-[#007AFF] font-mono placeholder-[#888888]"
              />
              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowNewFileModal(false)}
                  className="px-3 py-1.5 rounded-none hover:bg-[#222222] text-xs text-[#888888] hover:text-white border border-[#222222] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!newFileName.trim()}
                  className="px-3 py-1.5 rounded-none bg-white text-black hover:bg-[#cccccc] text-xs font-medium disabled:opacity-40 transition-colors"
                >
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
