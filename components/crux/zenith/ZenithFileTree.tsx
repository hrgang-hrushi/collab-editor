"use client";

import React, { useState, useRef, useMemo } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { FileNode } from "@/lib/types";
import {
  FolderOpen,
  Folder,
  FileCode2,
  ChevronRight,
  ChevronDown,
  Plus,
  PanelLeftClose,
  PanelLeft,
  Bot,
  Database,
  ShieldCheck,
  Code2,
  FileText,
  Upload,
  FolderPlus,
  Trash2,
  Search,
  Check,
  Download,
  FolderDown,
  FilePlus,
  Edit2,
} from "lucide-react";
import { readDirectoryHandle, exportWorkspaceAsZip } from "@/lib/fileUtils";

interface TreeNode {
  name: string;
  path: string;
  isDir: boolean;
  children: Record<string, TreeNode>;
  file?: FileNode;
}

export default function ZenithFileTree() {
  const projectName = useWorkspaceStore((state) => state.projectName);
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const createFile = useWorkspaceStore((state) => state.createFile);
  const createFileInPath = useWorkspaceStore((state) => state.createFileInPath);
  const deleteFile = useWorkspaceStore((state) => state.deleteFile);
  const importFiles = useWorkspaceStore((state) => state.importFiles);
  const importProject = useWorkspaceStore((state) => state.importProject);
  const isCollapsed = !useWorkspaceStore((state) => state.isSidebarOpen);
  const toggleCollapse = useWorkspaceStore((state) => state.toggleSidebar);

  const [isCreatingFile, setIsCreatingFile] = useState(false);
  const [newFileName, setNewFileName] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [isDragOver, setIsDragOver] = useState(false);
  const [openFolders, setOpenFolders] = useState<Record<string, boolean>>({
    src: true,
    lib: true,
    speculative: true,
    components: true,
  });

  const folderInputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const toggleFolder = (folderPath: string) => {
    setOpenFolders((prev) => ({
      ...prev,
      [folderPath]: prev[folderPath] !== undefined ? !prev[folderPath] : false,
    }));
  };

  const handleOpenDirectoryPicker = async () => {
    if (typeof window !== "undefined" && "showDirectoryPicker" in window) {
      try {
        const dirHandle = await (window as any).showDirectoryPicker();
        const imported = await readDirectoryHandle(dirHandle);
        if (imported.length > 0) {
          importProject(dirHandle.name, imported, dirHandle);
        }
      } catch (err: any) {
        if (err.name !== "AbortError") {
          console.error("Directory picker error:", err);
        }
      }
    } else {
      folderInputRef.current?.click();
    }
  };

  const handleExportZip = async () => {
    await exportWorkspaceAsZip(files, projectName);
  };

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newFileName.trim();
    if (!trimmed) return;
    if (trimmed.includes("/")) {
      createFileInPath(trimmed);
    } else {
      createFile(trimmed);
    }
    setNewFileName("");
    setIsCreatingFile(false);
  };

  // Helper to read file as text
  const readFileAsText = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  };

  // Handle manual file input selection
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = e.target.files;
    if (!uploadedFiles || uploadedFiles.length === 0) return;

    const imported: Array<{ name: string; path: string; content: string }> = [];
    for (let i = 0; i < uploadedFiles.length; i++) {
      const f = uploadedFiles[i];
      try {
        const content = await readFileAsText(f);
        imported.push({
          name: f.name,
          path: (f as any).webkitRelativePath || f.name,
          content,
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

  // Handle folder upload with webkitdirectory
  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = e.target.files;
    if (!uploadedFiles || uploadedFiles.length === 0) return;

    const imported: Array<{ name: string; path: string; content: string }> = [];
    for (let i = 0; i < uploadedFiles.length; i++) {
      const f = uploadedFiles[i];
      // Skip binary, image, and heavy vendor folders
      if (
        f.name.startsWith(".") ||
        (f as any).webkitRelativePath?.includes("node_modules/") ||
        (f as any).webkitRelativePath?.includes(".git/") ||
        f.name.endsWith(".png") ||
        f.name.endsWith(".jpg") ||
        f.name.endsWith(".ico")
      ) {
        continue;
      }

      try {
        const content = await readFileAsText(f);
        imported.push({
          name: f.name,
          path: (f as any).webkitRelativePath || f.name,
          content,
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

  // Drag and Drop folder entry recursive reader
  const readEntryRecursively = async (
    entry: any,
    pathPrefix = ""
  ): Promise<Array<{ name: string; path: string; content: string }>> => {
    if (entry.isFile) {
      return new Promise((resolve) => {
        entry.file(async (file: File) => {
          if (
            file.name.startsWith(".") ||
            file.name.endsWith(".png") ||
            file.name.endsWith(".jpg")
          ) {
            resolve([]);
            return;
          }
          try {
            const content = await readFileAsText(file);
            resolve([
              {
                name: file.name,
                path: pathPrefix ? `${pathPrefix}/${file.name}` : file.name,
                content,
              },
            ]);
          } catch {
            resolve([]);
          }
        });
      });
    } else if (entry.isDirectory) {
      const dirReader = entry.createReader();
      const entries = await new Promise<any[]>((resolve) => {
        dirReader.readEntries((ents: any[]) => resolve(ents));
      });
      const currentPrefix = pathPrefix ? `${pathPrefix}/${entry.name}` : entry.name;
      const results: Array<{ name: string; path: string; content: string }> = [];
      for (const ent of entries) {
        if (ent.name === "node_modules" || ent.name === ".git") continue;
        const subFiles = await readEntryRecursively(ent, currentPrefix);
        results.push(...subFiles);
      }
      return results;
    }
    return [];
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    const items = e.dataTransfer.items;
    if (!items || items.length === 0) return;

    const imported: Array<{ name: string; path: string; content: string }> = [];
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.kind === "file") {
        const entry = (item as any).webkitGetAsEntry?.();
        if (entry) {
          const filesInEntry = await readEntryRecursively(entry);
          imported.push(...filesInEntry);
        } else {
          const file = item.getAsFile();
          if (file) {
            const content = await readFileAsText(file);
            imported.push({
              name: file.name,
              path: file.name,
              content,
            });
          }
        }
      }
    }

    if (imported.length > 0) {
      importFiles(imported);
    }
  };

  // Build recursive tree from files list
  const fileTree = useMemo(() => {
    const root: TreeNode = {
      name: "root",
      path: "",
      isDir: true,
      children: {},
    };

    const filteredFiles = searchQuery
      ? files.filter((f) =>
          f.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          f.path.toLowerCase().includes(searchQuery.toLowerCase())
        )
      : files;

    filteredFiles.forEach((file) => {
      const parts = (file.path || `src/${file.name}`).split("/").filter(Boolean);
      let current = root;

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        const isLast = i === parts.length - 1;
        const currentPath = parts.slice(0, i + 1).join("/");

        if (isLast) {
          current.children[part] = {
            name: part,
            path: currentPath,
            isDir: false,
            children: {},
            file,
          };
        } else {
          if (!current.children[part]) {
            current.children[part] = {
              name: part,
              path: currentPath,
              isDir: true,
              children: {},
            };
          }
          current = current.children[part];
        }
      }
    });

    return root;
  }, [files, searchQuery]);

  const getFileIcon = (fileName: string) => {
    if (fileName.includes("db") || fileName.includes("database") || fileName.includes("prisma")) {
      return <Database className="w-3.5 h-3.5 text-emerald-400 shrink-0" />;
    }
    if (fileName.includes("auth") || fileName.includes("session") || fileName.includes("token")) {
      return <ShieldCheck className="w-3.5 h-3.5 text-indigo-400 shrink-0" />;
    }
    if (fileName.endsWith(".rs")) {
      return <Code2 className="w-3.5 h-3.5 text-amber-400 shrink-0" />;
    }
    if (fileName.endsWith(".json")) {
      return <FileCode2 className="w-3.5 h-3.5 text-yellow-400 shrink-0" />;
    }
    if (fileName.endsWith(".css")) {
      return <FileCode2 className="w-3.5 h-3.5 text-rose-400 shrink-0" />;
    }
    if (fileName.endsWith(".md") || fileName.endsWith(".txt")) {
      return <FileText className="w-3.5 h-3.5 text-[#8a8f98] shrink-0" />;
    }
    return <FileCode2 className="w-3.5 h-3.5 text-sky-400 shrink-0" />;
  };

  // Render tree node recursively
  const renderTreeNode = (node: TreeNode, depth = 0): React.ReactNode => {
    const isRoot = node.name === "root";
    if (isRoot) {
      return Object.values(node.children).map((child) =>
        renderTreeNode(child, depth)
      );
    }

    if (node.isDir) {
      const isOpen = openFolders[node.path] !== false;
      return (
        <div key={node.path} className="select-none">
          <button
            onClick={() => toggleFolder(node.path)}
            style={{ paddingLeft: `${Math.max(depth * 10, 6)}px` }}
            className="w-full flex items-center gap-1.5 py-1 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] text-[11px] font-sans font-medium transition-colors text-left"
          >
            {isOpen ? (
              <ChevronDown className="w-3 h-3 text-[#62666d] shrink-0" />
            ) : (
              <ChevronRight className="w-3 h-3 text-[#62666d] shrink-0" />
            )}
            {isOpen ? (
              <FolderOpen className="w-3.5 h-3.5 text-[#5e6ad2] shrink-0" />
            ) : (
              <Folder className="w-3.5 h-3.5 text-[#8a8f98] shrink-0" />
            )}
            <span className="font-semibold truncate">{node.name}</span>
          </button>

          {isOpen && (
            <div>
              {Object.values(node.children).map((child) =>
                renderTreeNode(child, depth + 1)
              )}
            </div>
          )}
        </div>
      );
    }

    // It's a file node
    const file = node.file;
    if (!file) return null;
    const isActive = file.id === activeFileId;

    return (
      <div
        key={file.id}
        onClick={() => setActiveFile(file.id)}
        style={{ paddingLeft: `${Math.max(depth * 10 + 6, 8)}px` }}
        className={`group flex items-center justify-between pr-2 py-1 cursor-pointer transition-colors text-[11px] font-sans ${
          isActive
            ? "bg-[#141516] text-[#f7f8f8] font-medium border-l-2 border-[#5e6ad2]"
            : "text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516]/50 border-l-2 border-transparent"
        }`}
      >
        <div className="flex items-center gap-1.5 truncate">
          {getFileIcon(file.name)}
          <span className="truncate">{file.name}</span>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {/* Active Multiplayer Peer Chip in file tree */}
          {file.contributorName && (
            <span
              className="px-1 text-[8.5px] border font-mono tracking-tight"
              style={{
                backgroundColor: `${file.contributorColor || "#5e6ad2"}15`,
                borderColor: `${file.contributorColor || "#5e6ad2"}50`,
                color: file.contributorColor || "#5e6ad2",
              }}
              title={`Contributor: ${file.contributorName}`}
            >
              {file.contributorName === "Sarah Lin"
                ? "SL"
                : file.contributorName === "CruxAI"
                ? "AI"
                : file.contributorName === "Marcus Vance"
                ? "MV"
                : "TS"}
            </span>
          )}

          {/* Delete File Action */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              deleteFile(file.id);
            }}
            title="Delete file"
            className="opacity-0 group-hover:opacity-100 p-0.5 text-[#62666d] hover:text-[#e5484d] transition-opacity"
          >
            <Trash2 className="w-2.5 h-2.5" />
          </button>
        </div>
      </div>
    );
  };

  if (isCollapsed) {
    return (
      <div className="w-10 h-full flex flex-col items-center py-2.5 border-r border-[#222222] bg-[#0A0A0A] select-none shrink-0">
        <button
          onClick={toggleCollapse}
          title="Expand Explorer (Cmd+B)"
          className="p-1.5 bg-transparent hover:bg-[#141516] text-[#8a8f98] hover:text-[#f7f8f8] border border-transparent hover:border-[#222222] transition-colors"
        >
          <PanelLeft className="w-4 h-4" />
        </button>
        <div className="w-4 h-[1px] bg-[#222222] my-2" />
        <span className="text-[10px] text-[#62666d] font-sans [writing-mode:vertical-rl] tracking-widest uppercase mt-1">
          EXPLORER
        </span>
      </div>
    );
  }

  return (
    <aside
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={`w-60 h-full flex flex-col border-r border-[#222222] bg-[#0A0A0A] select-none shrink-0 font-sans relative transition-none ${
        isDragOver ? "ring-2 ring-inset ring-[#5e6ad2] bg-[#5e6ad2]/5" : ""
      }`}
    >
      {/* Hidden Folder & File input elements for standard browser uploads */}
      <input
        type="file"
        ref={folderInputRef}
        {...({ webkitdirectory: "", directory: "", multiple: true } as any)}
        className="hidden"
        onChange={handleFolderUpload}
      />
      <input
        type="file"
        ref={fileInputRef}
        multiple
        className="hidden"
        onChange={handleFileUpload}
      />

      {/* Explorer Header */}
      <div className="h-8 px-2 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A]">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold text-[#8a8f98] uppercase tracking-wider truncate max-w-[120px]" title={projectName}>
          <span className="text-[#f7f8f8] truncate">{projectName}</span>
          <span className="text-[#62666d] text-[10px]">({files.length})</span>
        </div>

        <div className="flex items-center gap-0.5">
          {/* Open Folder from Computer (Directory Picker) */}
          <button
            onClick={handleOpenDirectoryPicker}
            title="Open Folder from Computer"
            className="p-1 text-[#8a8f98] hover:text-[#5e6ad2] hover:bg-[#141516] transition-colors"
          >
            <FolderDown className="w-3.5 h-3.5 text-[#5e6ad2]" />
          </button>

          {/* New File Button */}
          <button
            onClick={() => setIsCreatingFile(true)}
            title="New File (e.g. src/utils.ts)"
            className="p-1 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] transition-colors"
          >
            <FilePlus className="w-3.5 h-3.5" />
          </button>

          {/* Export Project as ZIP */}
          <button
            onClick={handleExportZip}
            title="Export Project as ZIP"
            className="p-1 text-[#8a8f98] hover:text-[#27a644] hover:bg-[#141516] transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
          </button>

          {/* Collapse Explorer */}
          <button
            onClick={toggleCollapse}
            title="Collapse Explorer (Cmd+B)"
            className="p-1 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] transition-colors"
          >
            <PanelLeftClose className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Quick Filter Search Bar */}
      <div className="px-2 py-1 border-b border-[#222222] bg-black">
        <div className="flex items-center gap-1.5 px-1.5 py-0.5 bg-[#0A0A0A] border border-[#222222] text-[#8a8f98]">
          <Search className="w-3 h-3 text-[#62666d]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter files..."
            className="w-full bg-transparent text-xs text-white placeholder-[#62666d] focus:outline-none"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              className="text-[10px] text-[#62666d] hover:text-white"
            >
              ×
            </button>
          )}
        </div>
      </div>

      {/* Inline Create File Form */}
      {isCreatingFile && (
        <div className="p-2 border-b border-[#222222] bg-[#141516]">
          <form onSubmit={handleCreateSubmit} className="space-y-1.5">
            <input
              type="text"
              autoFocus
              value={newFileName}
              onChange={(e) => setNewFileName(e.target.value)}
              placeholder="e.g. src/router.ts"
              className="w-full px-2 py-1 bg-black border border-[#222222] focus:border-[#5e6ad2] text-xs text-[#f7f8f8] font-mono focus:outline-none"
            />
            <div className="flex items-center justify-end gap-1 text-[10px]">
              <button
                type="button"
                onClick={() => setIsCreatingFile(false)}
                className="px-2 py-0.5 text-[#8a8f98] hover:text-[#f7f8f8]"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!newFileName.trim()}
                className="px-2 py-0.5 bg-[#5e6ad2] hover:bg-[#6c78e6] text-white font-medium disabled:opacity-50"
              >
                Add
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Drag & Drop Visual Overlay */}
      {isDragOver && (
        <div className="absolute inset-0 z-30 bg-black/90 flex flex-col items-center justify-center p-4 text-center border-2 border-dashed border-[#5e6ad2]">
          <FolderPlus className="w-8 h-8 text-[#5e6ad2] animate-bounce mb-2" />
          <span className="text-xs font-semibold text-white">Drop Folder or Files</span>
          <span className="text-[10px] text-[#8a8f98] mt-1">
            Files will be parsed into the workspace & canvas
          </span>
        </div>
      )}

      {/* Dynamic Recursive Tree Container */}
      <div className="flex-1 overflow-y-auto p-1 text-xs space-y-0.5">
        {renderTreeNode(fileTree)}
      </div>

      {/* Explorer Footer Telemetry */}
      <div className="h-7 px-2.5 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[10px] text-[#62666d]">
        <span>Branch: main</span>
        <div className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 bg-[#27a644]" />
          <span className="text-[#27a644]">Sync Clean</span>
        </div>
      </div>
    </aside>
  );
}
