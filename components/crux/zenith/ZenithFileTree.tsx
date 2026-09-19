"use client";

import React, { useState, useRef, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { Plus, Trash2, Download, FolderDown, X, Package, Search, Cpu, Play } from "lucide-react";
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
  const libraries = useWorkspaceStore((state) => state.libraries);
  const insertLibraryImport = useWorkspaceStore((state) => state.insertLibraryImport);
  const setLibraryModalOpen = useWorkspaceStore((state) => state.setLibraryModalOpen);
  const renameFile = useWorkspaceStore((state) => state.renameFile);
  const discoveredRuntimes = useWorkspaceStore((state) => state.discoveredRuntimes);
  const runProfiles = useWorkspaceStore((state) => state.runProfiles);
  const executeRunProfile = useWorkspaceStore((state) => state.executeRunProfile);
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


      {/* Libraries & Packages Section */}
      <div className="border-t border-grid flex flex-col shrink-0">
        <div className="px-4 py-2.5 bg-surface text-[10px] font-bold tracking-widest text-muted uppercase flex items-center justify-between border-b border-grid">
          <div className="flex items-center gap-1.5">
            <Package className="w-3 h-3 text-accent1" />
            <span>Libraries</span>
            <span className="px-1 py-0.1 text-[9px] bg-void border border-grid text-muted">
              {libraries.filter((l) => l.isInstalled).length}
            </span>
          </div>
          <button
            onClick={() => setLibraryModalOpen(true)}
            title="Browse & Add Libraries"
            className="hover:text-signal p-0.5 transition-colors flex items-center gap-1 text-[10px] font-mono text-muted"
          >
            <Plus className="w-3 h-3" />
            <span>Add</span>
          </button>
        </div>

        <div className="py-1 max-h-40 overflow-y-auto font-mono text-[11px]">
          {libraries
            .filter((l) => l.isInstalled)
            .map((lib) => {
              const isInCurrentFile =
                activeFile?.content.includes(`"${lib.name}"`) ||
                activeFile?.content.includes(`'${lib.name}'`);

              return (
                <div
                  key={lib.id}
                  className="px-4 py-1 flex items-center justify-between group hover:bg-[#111111] transition-colors"
                >
                  <span className="truncate text-muted group-hover:text-signal">
                    {lib.name}
                  </span>
                  <div className="flex items-center gap-1 shrink-0">
                    {isInCurrentFile ? (
                      <span
                        title="Import present in current file"
                        className="w-1.5 h-1.5 rounded-none bg-accent1 inline-block"
                      />
                    ) : (
                      <button
                        onClick={() => insertLibraryImport(lib.id)}
                        title={`Insert import into ${activeFile?.name}`}
                        className="opacity-0 group-hover:opacity-100 text-[10px] border border-grid px-1 py-0.2 text-muted hover:text-signal hover:border-signal bg-void transition-all"
                      >
                        + Import
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
        </div>
      </div>

      {/* Discovered Run Profiles Section (Legacy IDE Import: .vscode / .idea) */}
      {runProfiles.length > 0 && (
        <div className="border-t border-grid flex flex-col shrink-0">
          <div className="px-4 py-2 bg-surface text-[10px] font-bold tracking-widest text-muted uppercase flex items-center justify-between border-b border-grid">
            <div className="flex items-center gap-1.5">
              <Play className="w-3 h-3 text-white" />
              <span>Run Profiles</span>
              <span className="px-1 py-0.1 text-[9px] bg-void border border-grid text-muted">
                {runProfiles.length}
              </span>
            </div>
            <button
              onClick={() => setLibraryModalOpen(true)}
              title="Open Universal Hub"
              className="text-[9px] font-mono text-muted hover:text-white transition-colors"
            >
              [HUB]
            </button>
          </div>

          <div className="py-1 max-h-28 overflow-y-auto font-mono text-[11px]">
            {runProfiles.slice(0, 4).map((prof) => (
              <div
                key={prof.id}
                className="px-4 py-1 flex items-center justify-between group hover:bg-[#111111] transition-colors"
              >
                <div className="flex items-center gap-1.5 min-w-0">
                  <span
                    className={`text-[8px] px-1 py-0.1 border uppercase ${
                      prof.source === "jetbrains"
                        ? "border-accent1/40 text-accent1"
                        : prof.source === "vscode"
                        ? "border-[#007AFF]/40 text-[#007AFF]"
                        : "border-grid text-muted"
                    }`}
                  >
                    {prof.source === "jetbrains" ? "IDEA" : prof.source === "vscode" ? "VS" : "CRX"}
                  </span>
                  <span className="truncate text-muted group-hover:text-signal text-[10.5px]">
                    {prof.name.replace(/^\[.*?\]\s*/, "")}
                  </span>
                </div>

                <button
                  onClick={() => executeRunProfile(prof.id)}
                  title={`Run ${prof.name}`}
                  className="opacity-0 group-hover:opacity-100 text-[9px] border border-grid px-1.5 py-0.2 text-white hover:bg-white hover:text-black bg-void transition-all"
                >
                  ▶ Run
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sidebar Footer Telemetry */}
      <div className="p-3 border-t border-grid text-[10px] font-mono text-muted space-y-1 bg-surface">
        <div className="flex items-center justify-between">
          <span>DAEMON</span>
          <span className="text-[#00FF00]">7447 (0.08ms)</span>
        </div>
        <div className="flex items-center justify-between">
          <span>PEER</span>
          <span className="text-accent1">Sarah L.</span>
        </div>
        <div className="flex items-center justify-between">
          <span>BRANCH</span>
          <span className="text-signal">main*</span>
        </div>
      </div>
    </aside>
  );
}
