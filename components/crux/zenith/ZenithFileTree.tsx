"use client";

import React, { useState, useRef, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { Plus, Trash2, Download, FolderDown, X, Search } from "lucide-react";
import { exportWorkspaceAsZip } from "@/lib/fileUtils";
import ZenithSearch from "./ZenithSearch";

export default function ZenithFileTree() {
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const createFile = useWorkspaceStore((state) => state.createFile);
  const deleteFile = useWorkspaceStore((state) => state.deleteFile);
  const importFiles = useWorkspaceStore((state) => state.importFiles);
  const projectName = useWorkspaceStore((state) => state.projectName);
  const renameFile = useWorkspaceStore((state) => state.renameFile);
  const fetchDiscoveryReport = useWorkspaceStore((state) => state.fetchDiscoveryReport);

  const activeFile = files.find((f) => f.id === activeFileId) || files[0];

  // Sidebar mode: files list or search panel
  const [mode, setMode] = useState<"files" | "search">("files");

  const [isCreating, setIsCreating] = useState(false);
  const [newFileName, setNewFileName] = useState("");

  const [gitInfo, setGitInfo] = useState<{ branch: string; isDirty: boolean }>({
    branch: "main",
    isDirty: false,
  });

  useEffect(() => {
    fetch("/api/git", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "branch" }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.branch) {
          setGitInfo({ branch: data.branch, isDirty: !!data.isDirty });
        }
      })
      .catch(() => {/* keep defaults */});

    fetchDiscoveryReport();
  }, [fetchDiscoveryReport]);

  // Inline rename state
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameVal, setRenameVal] = useState("");

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newFileName.trim();
    if (!trimmed) {
      setIsCreating(false);
      return;
    }
    createFile(trimmed);
    setNewFileName("");
    setIsCreating(false);
  };

  const handleExportZip = async () => {
    await exportWorkspaceAsZip(files, projectName);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = e.target.files;
    if (!uploadedFiles || uploadedFiles.length === 0) return;

    const imported: Array<{ name: string; path: string; content: string }> = [];
    for (let i = 0; i < uploadedFiles.length; i++) {
      const f = uploadedFiles[i];
      try {
        const text = await f.text();
        imported.push({
          name: f.name,
          path: f.name,
          content: text,
        });
      } catch (err) {
        console.error("Failed to read file", f.name, err);
      }
    }
    if (imported.length > 0) {
      importFiles(imported);
    }
    e.target.value = "";
  };

  return (
    <aside className="w-64 border-r border-grid bg-surface flex flex-col select-none shrink-0 h-full font-sans">
      <input
        type="file"
        ref={fileInputRef}
        multiple
        className="hidden"
        onChange={handleFileUpload}
      />

      {/* Explorer Header */}
      <div className="px-4 py-3 border-b border-grid text-[10px] font-bold tracking-widest text-muted uppercase flex items-center justify-between">
        <span>{mode === "search" ? "Search" : "Explorer"}</span>
        <div className="flex items-center gap-1.5 text-muted">
          {mode === "files" && (
            <>
              <button
                onClick={() => setIsCreating(true)}
                title="New File"
                className="hover:text-signal p-0.5 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => fileInputRef.current?.click()}
                title="Import Files"
                className="hover:text-signal p-0.5 transition-colors"
              >
                <FolderDown className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={handleExportZip}
                title="Export Workspace ZIP"
                className="hover:text-signal p-0.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
              </button>
            </>
          )}
          <button
            onClick={() => setMode((m) => (m === "search" ? "files" : "search"))}
            title={mode === "search" ? "Back to Files" : "Search in Files"}
            className={`p-0.5 transition-colors ${
              mode === "search" ? "text-[#00E5FF]" : "hover:text-signal"
            }`}
          >
            <Search className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* File List or Search Panel */}
      {mode === "search" ? (
        <div className="flex-1 overflow-hidden">
          <ZenithSearch />
        </div>
      ) : (
        <div className="flex-1 py-2 font-mono text-xs overflow-y-auto">
          {isCreating && (
            <form onSubmit={handleCreateSubmit} className="px-4 py-1.5 bg-void border-l-2 border-accent1 flex items-center gap-2">
              <input
                type="text"
                value={newFileName}
                onChange={(e) => setNewFileName(e.target.value)}
                placeholder="filename.ts"
                autoFocus
                onBlur={() => {
                  if (!newFileName.trim()) setIsCreating(false);
                }}
                className="bg-transparent border-none outline-none text-signal text-xs font-mono p-0 w-full"
              />
              <button
                type="button"
                onClick={() => setIsCreating(false)}
                className="text-muted hover:text-signal"
              >
                <X className="w-3 h-3" />
              </button>
            </form>
          )}

          {files.map((file) => {
            const isActive = file.id === activeFileId;
            const isRenaming = renamingId === file.id;
            return (
              <div
                key={file.id}
                onClick={() => {
                  if (!isRenaming) {
                    setActiveFile(file.id);
                    openTab(file.id);
                  }
                }}
                onDoubleClick={(e) => {
                  e.stopPropagation();
                  setRenamingId(file.id);
                  setRenameVal(file.name);
                }}
                className={`px-4 py-1.5 flex items-center justify-between group cursor-pointer transition-colors ${
                  isActive
                    ? "text-signal bg-grid border-l-2 border-signal"
                    : "text-muted border-l-2 border-transparent hover:text-signal hover:bg-[#111111]"
                }`}
              >
                {isRenaming ? (
                  <input
                    type="text"
                    value={renameVal}
                    autoFocus
                    onChange={(e) => setRenameVal(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        const trimmed = renameVal.trim();
                        if (trimmed) renameFile(file.id, trimmed);
                        setRenamingId(null);
                      } else if (e.key === "Escape") {
                        setRenamingId(null);
                      }
                    }}
                    onBlur={() => {
                      const trimmed = renameVal.trim();
                      if (trimmed) renameFile(file.id, trimmed);
                      setRenamingId(null);
                    }}
                    onClick={(e) => e.stopPropagation()}
                    className="bg-transparent border-none border-b border-[#00E5FF] outline-none text-signal text-xs font-mono p-0 w-full"
                  />
                ) : (
                  <span className="truncate">{file.name}</span>
                )}
                {!isRenaming && files.length > 1 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteFile(file.id);
                    }}
                    title="Delete file"
                    className="opacity-0 group-hover:opacity-100 text-muted hover:text-accent2 p-0.5 transition-opacity"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </aside>
  );
}
