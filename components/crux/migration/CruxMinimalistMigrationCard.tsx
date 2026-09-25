"use client";

import React, { useRef, useState } from "react";
import { ArrowRight, FolderOpen } from "lucide-react";
import { useWorkspaceStore } from "@/lib/store";
import { ImportedWorkspace, isTauriDesktop, readFileList, readNativeDirectory } from "@/lib/fileUtils";
import CruxMinimalistMigrationModal from "./CruxMinimalistMigrationModal";

interface CruxMinimalistMigrationCardProps {
  className?: string;
  onMigrationComplete?: () => void;
}

export default function CruxMinimalistMigrationCard({ className = "", onMigrationComplete }: CruxMinimalistMigrationCardProps) {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [error, setError] = useState("");
  const folderInputRef = useRef<HTMLInputElement>(null);
  const importProject = useWorkspaceStore((state) => state.importProject);
  const importFolders = useWorkspaceStore((state) => state.importFolders);
  const setLastImportStatus = useWorkspaceStore((state) => state.setLastImportStatus);
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);
  const setZeroStateOpen = useWorkspaceStore((state) => state.setZeroStateOpen);

  const finishImport = (workspace: ImportedWorkspace) => {
    const root = workspace.folders.find((folder) => !folder.includes("/")) ||
      workspace.files[0]?.path.split("/")[0] || "Imported workspace";
    importProject(root, workspace.files);
    if (workspace.folders.length) importFolders(workspace.folders);
    setLastImportStatus(`Imported ${workspace.files.length} files and ${workspace.folders.length} folders${workspace.skipped ? ` · ${workspace.skipped} skipped (large, unreadable, or ignored)` : ""}`);
    setOnboarded(true);
    setZeroStateOpen(false);
  };

  const openFolder = async () => {
    setError("");
    if (!isTauriDesktop()) {
      folderInputRef.current?.click();
      return;
    }
    setIsImporting(true);
    try {
      const workspace = await readNativeDirectory();
      if (workspace) finishImport(workspace);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not read this folder.");
    } finally {
      setIsImporting(false);
    }
  };

  const onBrowserFolder = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const selected = event.target.files;
    if (!selected?.length) return;
    setIsImporting(true);
    setError("");
    try {
      const files = await readFileList(selected);
      const root = selected[0].webkitRelativePath.split("/")[0];
      finishImport({ files, folders: root ? [root] : [], skipped: selected.length - files.length });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not read this folder.");
    } finally {
      event.target.value = "";
      setIsImporting(false);
    }
  };

  return (
    <>
      <div className={`w-full border border-[#222222] bg-[#0A0A0A] p-3 sm:p-3.5 text-white ${className}`}>
        <div className="flex items-start gap-2.5">
          <FolderOpen className="h-4 w-4 shrink-0 text-white mt-0.5" />
          <div>
            <h4 className="font-mono text-xs font-bold uppercase">Import Existing Workspace</h4>
            <p className="mt-0.5 font-mono text-[10px] leading-relaxed text-[#888888]">
              Select a project folder to open its files and subfolders in Crux.
            </p>
          </div>
        </div>
        <button type="button" disabled={isImporting} onClick={openFolder}
          className="mt-2.5 flex h-8 w-full items-center justify-center gap-2 border border-white bg-white font-mono text-[10px] font-bold uppercase text-black hover:bg-black hover:text-white disabled:opacity-50 cursor-pointer transition-none">
          {isImporting ? "Importing Folder…" : "Import Project Folder"}
          <ArrowRight className="h-3 w-3" />
        </button>
        <button type="button" onClick={() => setIsModalOpen(true)}
          className="mt-1.5 w-full border border-[#222222] px-2.5 py-1.5 text-left font-mono text-[9px] uppercase text-[#888888] hover:border-white hover:text-white cursor-pointer transition-none">
          Import VS Code / Cursor settings
        </button>
        {error && <p role="alert" className="mt-1.5 font-mono text-[10px] text-white">{error}</p>}
      </div>
      <input ref={folderInputRef} type="file" multiple className="hidden" onChange={onBrowserFolder}
        {...({ webkitdirectory: "", directory: "" } as React.InputHTMLAttributes<HTMLInputElement>)} />
      <CruxMinimalistMigrationModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} onComplete={onMigrationComplete} />
    </>
  );
}
