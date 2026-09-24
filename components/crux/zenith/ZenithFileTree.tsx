"use client";

import React, { useState, useRef, useEffect, useMemo } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { Plus, Trash2, Download, FolderDown, FolderPlus, X, Search } from "lucide-react";
import { buildFileTree, exportWorkspaceAsZip, isTauriDesktop, readDroppedItems, readFileList, readNativeDirectory, ImportedWorkspace, TreeItem } from "@/lib/fileUtils";
import ZenithSearch from "./ZenithSearch";
import BranchedMenu, { BranchedMenuItem, BranchedMenuChildItem } from "./BranchedMenu";
import {
  Folder01Icon,
  FolderOpenIcon,
  File01Icon,
  CodeIcon,
  JavaScriptIcon,
  PythonIcon,
} from "@hugeicons/core-free-icons";

export default function ZenithFileTree() {
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const createFile = useWorkspaceStore((state) => state.createFile);
  const deleteFile = useWorkspaceStore((state) => state.deleteFile);
  const importFiles = useWorkspaceStore((state) => state.importFiles);
  const importFolders = useWorkspaceStore((state) => state.importFolders);
  const renamePath = useWorkspaceStore((state) => state.renamePath);
  const folderPaths = useWorkspaceStore((state) => state.folderPaths);
  const importMessage = useWorkspaceStore((state) => state.lastImportStatus);
  const setImportMessage = useWorkspaceStore((state) => state.setLastImportStatus);
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
    import("@/lib/gitUtils").then(({ getGitBranchInfo }) => {
      getGitBranchInfo().then((info) => {
        setGitInfo(info);
      });
    });

    fetchDiscoveryReport();
  }, [fetchDiscoveryReport]);

  // Inline rename state
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameVal, setRenameVal] = useState("");

  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const [dragOverFolder, setDragOverFolder] = useState<string | null>(null);
  const fileTree = useMemo(() => buildFileTree(files, folderPaths), [files, folderPaths]);

  const addImportedWorkspace = (result: ImportedWorkspace) => {
    if (result.folders.length) importFolders(result.folders);
    if (result.files.length) importFiles(result.files);
    setImportMessage(`Imported ${result.files.length} files and ${result.folders.length} folders${result.skipped ? ` · ${result.skipped} skipped (large, unreadable, or ignored)` : ""}`);
  };

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
    await exportWorkspaceAsZip(files, projectName, folderPaths);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = e.target.files;
    if (!uploadedFiles || uploadedFiles.length === 0) return;
    const imported = await readFileList(uploadedFiles);
    addImportedWorkspace({ files: imported, folders: [], skipped: uploadedFiles.length - imported.length });
    e.target.value = "";
  };

  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = e.target.files;
    if (!uploadedFiles || uploadedFiles.length === 0) return;

    const imported = await readFileList(uploadedFiles);
    const rootFolder = uploadedFiles[0]?.webkitRelativePath?.split("/")[0];
    addImportedWorkspace({ files: imported, folders: rootFolder ? [rootFolder] : [], skipped: uploadedFiles.length - imported.length });
    e.target.value = "";
  };

  const openFolderPicker = async () => {
    if (!isTauriDesktop()) {
      folderInputRef.current?.click();
      return;
    }
    try {
      const imported = await readNativeDirectory();
      if (imported) addImportedWorkspace(imported);
    } catch (error) {
      console.error("Failed to import folder", error);
      window.alert(`Could not import folder: ${String(error)}`);
    }
  };

  const moveIntoFolder = (sourcePath: string, targetFolder: string) => {
    const name = sourcePath.split("/").pop() || "";
    const nextPath = targetFolder ? `${targetFolder}/${name}` : name;
    if (!name || nextPath === sourcePath || targetFolder === sourcePath || targetFolder.startsWith(`${sourcePath}/`)) return;
    const occupied = files.some((file) => file.path === nextPath || file.path.startsWith(`${nextPath}/`)) || folderPaths.includes(nextPath);
    if (occupied) {
      setImportMessage(`A file or folder named ${name} already exists there.`);
      return;
    }
    renamePath(sourcePath, nextPath);
    setImportMessage(`Moved ${name} to ${targetFolder || "workspace root"}`);
  };

  const handleTreeDrop = async (e: React.DragEvent, targetFolder: string) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOverFolder(null);
    const plainPath = e.dataTransfer.getData("text/plain");
    const sourcePath = e.dataTransfer.getData("application/x-crux-path") ||
      (files.some((file) => file.path === plainPath) || folderPaths.includes(plainPath) ? plainPath : "");
    if (sourcePath) {
      moveIntoFolder(sourcePath, targetFolder);
      return;
    }
    if (e.dataTransfer.items.length) {
      try {
        const imported = await readDroppedItems(e.dataTransfer.items);
        if (targetFolder) {
          imported.files = imported.files.map((file) => ({ ...file, path: `${targetFolder}/${file.path}` }));
          imported.folders = imported.folders.map((folder) => `${targetFolder}/${folder}`);
        }
        addImportedWorkspace(imported);
      } catch (error) {
        setImportMessage(`Could not import dropped items: ${String(error)}`);
      }
    }
  };

function getFileIcon(filename: string) {
  const lower = filename.toLowerCase();
  if (
    lower.endsWith(".ts") ||
    lower.endsWith(".tsx") ||
    lower.endsWith(".js") ||
    lower.endsWith(".jsx")
  ) {
    return JavaScriptIcon;
  }
  if (lower.endsWith(".py")) {
    return PythonIcon;
  }
  if (
    lower.endsWith(".rs") ||
    lower.endsWith(".cpp") ||
    lower.endsWith(".c") ||
    lower.endsWith(".json") ||
    lower.endsWith(".html") ||
    lower.endsWith(".css")
  ) {
    return CodeIcon;
  }
  return File01Icon;
}

  const branchedMenuItems = useMemo(() => {
    const sections: BranchedMenuItem[] = [];

    const mapFileItem = (item: TreeItem): BranchedMenuChildItem => {
      const file = item.file!;
      const isRenaming = renamingId === file.id;

      return {
        value: file.id,
        label: file.name,
        icon: getFileIcon(file.name),
        draggable: !isRenaming,
        onDragStart: (e: React.DragEvent) => {
          e.dataTransfer.effectAllowed = "move";
          e.dataTransfer.setData("application/x-crux-path", file.path);
          e.dataTransfer.setData("text/plain", file.path);
        },
        onDragOver: (e: React.DragEvent) => {
          e.preventDefault();
          e.stopPropagation();
          setDragOverFolder(file.path);
        },
        onDragLeave: () => setDragOverFolder(null),
        onDrop: (e: React.DragEvent) => {
          void handleTreeDrop(
            e,
            file.path.includes("/") ? file.path.slice(0, file.path.lastIndexOf("/")) : ""
          );
        },
        onDoubleClick: (e: React.MouseEvent) => {
          e.stopPropagation();
          setRenamingId(file.id);
          setRenameVal(file.name);
        },
        renderLabel: isRenaming
          ? () => (
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
                className="bg-transparent border-none border-b border-white outline-none text-white text-xs font-mono p-0 w-full"
              />
            )
          : undefined,
        actions:
          files.length > 1 && !isRenaming ? (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                deleteFile(file.id);
              }}
              title="Delete file"
              className="text-[#666666] hover:text-white p-0.5 transition-colors"
            >
              <Trash2 className="w-3 h-3" />
            </button>
          ) : undefined,
      };
    };

    const mapFolderItem = (folderItem: TreeItem): BranchedMenuItem => {
      const kids: BranchedMenuChildItem[] = [];
      const walk = (items: TreeItem[], prefix = "") => {
        for (const it of items) {
          if (it.isFolder) {
            if (it.children) {
              walk(it.children, `${prefix}${it.name}/`);
            }
          } else if (it.file) {
            const child = mapFileItem(it);
            if (prefix) {
              child.label = `${prefix}${it.name}`;
            }
            kids.push(child);
          }
        }
      };
      if (folderItem.children) {
        walk(folderItem.children);
      }

      return {
        label: folderItem.name.toUpperCase(),
        value: folderItem.path,
        icon: Folder01Icon,
        draggable: true,
        onDragStart: (e: React.DragEvent) => {
          e.dataTransfer.effectAllowed = "move";
          e.dataTransfer.setData("application/x-crux-path", folderItem.path);
          e.dataTransfer.setData("text/plain", folderItem.path);
        },
        onDragOver: (e: React.DragEvent) => {
          e.preventDefault();
          e.stopPropagation();
          setDragOverFolder(folderItem.path);
        },
        onDragLeave: () => setDragOverFolder(null),
        onDrop: (e: React.DragEvent) => void handleTreeDrop(e, folderItem.path),
        children: kids,
      };
    };

    const folders = fileTree.filter((it) => it.isFolder);
    const rootFiles = fileTree.filter((it) => !it.isFolder);

    folders.forEach((folder) => {
      sections.push(mapFolderItem(folder));
    });

    if (rootFiles.length > 0) {
      const rootKids = rootFiles.map(mapFileItem);
      const label =
        folders.length > 0
          ? "ROOT FILES"
          : projectName
          ? `${projectName}`.toUpperCase()
          : "CRUX // WORKSPACE";

      sections.push({
        label,
        value: "workspace-root",
        icon: Folder01Icon,
        children: rootKids,
        draggable: false,
        onDragOver: (e: React.DragEvent) => {
          e.preventDefault();
          setDragOverFolder("");
        },
        onDragLeave: () => setDragOverFolder(null),
        onDrop: (e: React.DragEvent) => void handleTreeDrop(e, ""),
      });
    }

    return sections;
  }, [fileTree, renamingId, renameVal, files.length, projectName, renameFile, deleteFile, handleTreeDrop]);

  return (
    <aside className="w-64 border-r border-grid bg-surface flex flex-col select-none shrink-0 h-full font-sans">
      <input
        type="file"
        ref={fileInputRef}
        multiple
        className="hidden"
        onChange={handleFileUpload}
      />
      <input
        type="file"
        ref={folderInputRef}
        {...({ webkitdirectory: "", directory: "", multiple: true } as any)}
        className="hidden"
        onChange={handleFolderUpload}
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

      {mode === "files" && (
        <div className="flex border-b border-[#222222] text-[10px] font-bold tracking-wide">
          <button
            type="button"
            onClick={openFolderPicker}
            className="flex-1 flex items-center justify-center gap-1.5 px-2 py-2 bg-white text-black hover:bg-[#CCCCCC] transition-none"
          >
            <FolderPlus className="w-3.5 h-3.5" />
            IMPORT FOLDER
          </button>
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="flex-1 flex items-center justify-center gap-1.5 px-2 py-2 border-l border-[#222222] bg-black text-white hover:bg-[#111111] transition-none"
          >
            <FolderDown className="w-3.5 h-3.5" />
            IMPORT FILES
          </button>
        </div>
      )}

      {importMessage && <div role="status" className="px-3 py-2 border-b border-[#222222] text-[10px] leading-tight text-[#CCCCCC]">{importMessage}</div>}

      {/* File List or Search Panel */}
      {mode === "search" ? (
        <div className="flex-1 overflow-hidden">
          <ZenithSearch />
        </div>
      ) : (
        <div
          className={`flex-1 py-2 font-mono text-xs overflow-y-auto ${dragOverFolder === "" ? "outline outline-1 outline-white" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setDragOverFolder(""); }}
          onDragLeave={() => setDragOverFolder(null)}
          onDrop={(e) => void handleTreeDrop(e, "")}
        >
          {isCreating && (
            <form onSubmit={handleCreateSubmit} className="px-4 py-1.5 bg-void border-l-2 border-accent1 flex items-center gap-2 mb-2">
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

          <BranchedMenu
            items={branchedMenuItems}
            defaultOpen={branchedMenuItems.map((_, i) => i)}
            active={activeFileId}
            onSelect={(value) => {
              setActiveFile(value);
              openTab(value);
            }}
            color="#888888"
            accentColor="#ffffff"
            lineColor="#222222"
            width="100%"
            rowHeight={32}
            indent={36}
            trunk={14}
            radius={8}
            lineWidth={1.5}
            fontSize={12}
            drawDuration={350}
            foldDuration={250}
          />
        </div>
      )}
    </aside>
  );
}
