"use client";

import React, { useState, useMemo } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { triggerHaptic } from "@/lib/haptics";
import { FileRevision } from "@/lib/types";
import {
  History,
  Calendar,
  Clock,
  RotateCcw,
  Plus,
  Search,
  X,
  FileCode,
  User,
  Check,
  ChevronDown,
  ChevronRight,
  Trash2,
  GitCommit,
  Layers,
} from "lucide-react";

export default function CruxTimelineHistoryDrawer() {
  const isOpen = useWorkspaceStore((state) => state.isHistoryDrawerOpen);
  const setIsOpen = useWorkspaceStore((state) => state.setHistoryDrawerOpen);
  const fileRevisions = useWorkspaceStore((state) => state.fileRevisions);
  const restoreFileRevision = useWorkspaceStore((state) => state.restoreFileRevision);
  const createManualCheckpoint = useWorkspaceStore((state) => state.createManualCheckpoint);
  const clearFileRevisions = useWorkspaceStore((state) => state.clearFileRevisions);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const files = useWorkspaceStore((state) => state.files);

  const [filterMode, setFilterMode] = useState<"all" | "active">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedRevId, setExpandedRevId] = useState<string | null>(null);
  const [restoredId, setRestoredId] = useState<string | null>(null);
  const [checkpointInput, setCheckpointInput] = useState("");
  const [showCheckpointForm, setShowCheckpointForm] = useState(false);

  const activeFile = useMemo(() => {
    return files.find((f) => f.id === activeFileId);
  }, [files, activeFileId]);

  // Filter revisions by file and query
  const filteredRevisions = useMemo(() => {
    return fileRevisions.filter((rev) => {
      if (filterMode === "active" && activeFileId && rev.fileId !== activeFileId) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesName = rev.fileName.toLowerCase().includes(q);
        const matchesSummary = rev.summary.toLowerCase().includes(q);
        const matchesAuthor = rev.author.toLowerCase().includes(q);
        return matchesName || matchesSummary || matchesAuthor;
      }
      return true;
    });
  }, [fileRevisions, filterMode, activeFileId, searchQuery]);

  // Group revisions by Calendar Date
  const calendarGroups = useMemo(() => {
    const groups: Record<string, FileRevision[]> = {};
    for (const rev of filteredRevisions) {
      const groupKey = rev.calendarGroup || rev.dateString || "Earlier";
      if (!groups[groupKey]) {
        groups[groupKey] = [];
      }
      groups[groupKey].push(rev);
    }
    return groups;
  }, [filteredRevisions]);

  const handleRestore = (rev: FileRevision) => {
    triggerHaptic("click");
    restoreFileRevision(rev.id);
    setRestoredId(rev.id);
    setTimeout(() => setRestoredId(null), 2000);
  };

  const handleCreateCheckpoint = (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeFileId) return;
    triggerHaptic("click");
    createManualCheckpoint(activeFileId, checkpointInput.trim() || undefined);
    setCheckpointInput("");
    setShowCheckpointForm(false);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] bg-black/85 flex items-start justify-center pt-10 sm:pt-14 px-3 sm:px-6 font-sans select-none animate-in fade-in duration-100">
      <div className="w-full max-w-3xl bg-[#000000] border border-[#222222] flex flex-col max-h-[85vh] overflow-hidden text-white">
        {/* Header Strip */}
        <div className="h-11 px-4 bg-[#111111] border-b border-[#222222] flex items-center justify-between font-mono text-[11px] select-none shrink-0">
          <div className="flex items-center gap-2.5">
            <History className="w-4 h-4 text-white" />
            <span className="font-bold text-white uppercase tracking-wider">
              REVISION TIMELINE // FILE HISTORY
            </span>
            <span className="text-[#444444]">|</span>
            <span className="text-[#888888] text-[10px]">
              {filteredRevisions.length} TOTAL REVISION SNAPSHOTS
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowCheckpointForm((prev) => !prev)}
              className="px-2 py-1 border border-[#222222] hover:border-white text-[9px] uppercase tracking-wider text-white hover:bg-white hover:text-black transition-none flex items-center gap-1 font-mono cursor-pointer"
            >
              <Plus className="w-3 h-3" />
              <span>CREATE CHECKPOINT</span>
            </button>
            <button
              onClick={() => setIsOpen(false)}
              className="text-[#888888] hover:text-white p-1 transition-none"
              title="Close Timeline (ESC)"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Checkpoint Input Form (Collapsible) */}
        {showCheckpointForm && (
          <form
            onSubmit={handleCreateCheckpoint}
            className="p-3 bg-[#0A0A0A] border-b border-[#222222] flex items-center gap-2 font-mono text-xs"
          >
            <div className="flex-1 flex items-center gap-2 bg-[#000000] border border-[#222222] px-2.5 py-1.5">
              <GitCommit className="w-3.5 h-3.5 text-[#888888]" />
              <input
                type="text"
                value={checkpointInput}
                onChange={(e) => setCheckpointInput(e.target.value)}
                placeholder={`Checkpoint note for ${activeFile?.name || "active file"}...`}
                className="w-full bg-transparent text-xs text-white placeholder-[#666666] outline-none"
                autoFocus
              />
            </div>
            <button
              type="submit"
              className="px-3 py-1.5 bg-white text-black font-bold uppercase text-[10px] hover:bg-[#CCCCCC] transition-none cursor-pointer"
            >
              COMMIT
            </button>
            <button
              type="button"
              onClick={() => setShowCheckpointForm(false)}
              className="px-2 py-1.5 border border-[#222222] text-[#888888] hover:text-white uppercase text-[10px] transition-none"
            >
              CANCEL
            </button>
          </form>
        )}

        {/* Sub-Header: Search & Segregation Filters */}
        <div className="px-4 py-2 bg-[#0A0A0A] border-b border-[#222222] flex flex-wrap items-center justify-between gap-3 font-mono text-[10px] shrink-0">
          <div className="flex items-center gap-2 flex-1 max-w-sm bg-[#000000] border border-[#222222] px-2 py-1">
            <Search className="w-3 h-3 text-[#666666]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter timeline entries by author, summary, or file..."
              className="w-full bg-transparent text-[10px] text-white placeholder-[#666666] outline-none"
            />
            {searchQuery && (
              <button onClick={() => setSearchQuery("")} className="text-[#666666] hover:text-white">
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center border border-[#222222] p-0.5 bg-[#000000]">
              <button
                onClick={() => setFilterMode("all")}
                className={`px-2 py-0.5 uppercase transition-none text-[9px] font-bold ${
                  filterMode === "all" ? "bg-white text-black" : "text-[#888888] hover:text-white"
                }`}
              >
                ALL FILES
              </button>
              <button
                onClick={() => setFilterMode("active")}
                className={`px-2 py-0.5 uppercase transition-none text-[9px] font-bold ${
                  filterMode === "active" ? "bg-white text-black" : "text-[#888888] hover:text-white"
                }`}
              >
                ACTIVE ({activeFile?.name || "NONE"})
              </button>
            </div>

            {filteredRevisions.length > 0 && (
              <button
                onClick={() => {
                  if (confirm("Clear all recorded history for these revisions?")) {
                    clearFileRevisions(filterMode === "active" ? activeFileId : undefined);
                  }
                }}
                className="p-1 border border-[#222222] text-[#666666] hover:text-white hover:border-white transition-none"
                title="Clear Revisions"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>

        {/* Main Content Area: Calendar Segregated Timeline */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-7 bg-[#000000]">
          {Object.keys(calendarGroups).length === 0 ? (
            <div className="py-14 text-center font-mono space-y-2">
              <History className="w-8 h-8 text-[#333333] mx-auto" />
              <div className="text-xs text-[#888888] uppercase tracking-wider">
                NO REVISION ENTRIES FOUND
              </div>
              <p className="text-[10px] text-[#555555] max-w-sm mx-auto">
                Edits, deletions, manual checkpoints, and restorations will automatically appear here grouped by calendar date.
              </p>
            </div>
          ) : (
            Object.entries(calendarGroups).map(([groupTitle, revs]) => (
              <div key={groupTitle} className="space-y-3 font-mono">
                {/* Calendar Date Segregator Header */}
                <div className="flex items-center gap-2 select-none">
                  <Calendar className="w-3.5 h-3.5 text-white" />
                  <span className="text-xs font-bold uppercase tracking-wider text-white">
                    {groupTitle}
                  </span>
                  <span className="text-[9px] text-[#666666] border border-[#222222] px-1 bg-[#0A0A0A]">
                    {revs.length} {revs.length === 1 ? "EVENT" : "EVENTS"}
                  </span>
                  <div className="flex-1 border-t border-[#222222] ml-2" />
                </div>

                {/* Vertical Timeline Track */}
                <div className="border-l border-[#222222] ml-3 pl-4 space-y-4">
                  {revs.map((rev) => {
                    const isExpanded = expandedRevId === rev.id;
                    const isRestored = restoredId === rev.id;

                    return (
                      <div
                        key={rev.id}
                        className="relative group border border-[#181818] hover:border-[#333333] bg-[#0A0A0A] p-3 transition-none"
                      >
                        {/* Timeline Hardware Pip Node */}
                        <div
                          className={`absolute -left-[21px] top-4 w-2 h-2 border border-black transition-none ${
                            rev.changeType === "delete_all"
                              ? "bg-white animate-hard-blink"
                              : rev.changeType === "checkpoint"
                              ? "bg-white"
                              : rev.changeType === "restore"
                              ? "bg-white"
                              : "bg-[#666666]"
                          }`}
                        />

                        {/* Top Line: Timestamp, Change Badge, File, Author */}
                        <div className="flex flex-wrap items-center justify-between gap-2 text-[10px]">
                          <div className="flex items-center gap-2">
                            <div className="flex items-center gap-1 text-white font-bold">
                              <Clock className="w-3 h-3 text-[#888888]" />
                              <span>{rev.timeString}</span>
                            </div>

                            <span className="text-[#333333]">/</span>

                            {/* Change Type Pill */}
                            <span
                              className={`px-1.5 py-0.2 border text-[9px] uppercase font-bold ${
                                rev.changeType === "delete_all"
                                  ? "border-white bg-white text-black"
                                  : rev.changeType === "checkpoint"
                                  ? "border-[#444444] bg-[#1A1A1A] text-white"
                                  : rev.changeType === "restore"
                                  ? "border-[#444444] bg-[#1A1A1A] text-white"
                                  : "border-[#222222] bg-black text-[#888888]"
                              }`}
                            >
                              {rev.changeType === "delete_all"
                                ? "CLEARED BUFFER"
                                : rev.changeType.toUpperCase()}
                            </span>

                            <span className="text-[#333333]">/</span>

                            <div className="flex items-center gap-1 text-white font-bold">
                              <FileCode className="w-3 h-3 text-[#888888]" />
                              <span>{rev.fileName}</span>
                            </div>
                          </div>

                          <div className="flex items-center gap-3">
                            <span className="text-[9px] text-[#666666] flex items-center gap-1">
                              <User className="w-2.5 h-2.5" />
                              <span>{rev.author}</span>
                            </span>

                            {/* Restore Button */}
                            <button
                              onClick={() => handleRestore(rev)}
                              className={`px-2 py-0.5 border text-[9px] uppercase font-bold transition-none flex items-center gap-1 cursor-pointer ${
                                isRestored
                                  ? "bg-white text-black border-white"
                                  : "border-white text-white hover:bg-white hover:text-black"
                              }`}
                              title="Revert file buffer to this historical checkpoint"
                            >
                              {isRestored ? (
                                <>
                                  <Check className="w-3 h-3" />
                                  <span>RESTORED!</span>
                                </>
                              ) : (
                                <>
                                  <RotateCcw className="w-3 h-3" />
                                  <span>UNDO TO THIS</span>
                                </>
                              )}
                            </button>
                          </div>
                        </div>

                        {/* Summary & Metrics */}
                        <div className="mt-2 flex items-center justify-between text-[11px] text-[#CCCCCC]">
                          <span>{rev.summary}</span>
                          <span className="text-[9px] text-[#666666]">
                            {rev.linesCount} lines · {rev.charsCount} chars
                          </span>
                        </div>

                        {/* Code Preview Toggle */}
                        <div className="mt-2.5 pt-2 border-t border-[#141414]">
                          <button
                            onClick={() => setExpandedRevId(isExpanded ? null : rev.id)}
                            className="text-[9px] text-[#888888] hover:text-white flex items-center gap-1 transition-none uppercase"
                          >
                            {isExpanded ? (
                              <>
                                <ChevronDown className="w-3 h-3" />
                                <span>HIDE BUFFER PREVIEW</span>
                              </>
                            ) : (
                              <>
                                <ChevronRight className="w-3 h-3" />
                                <span>VIEW BUFFER PREVIEW ({rev.linesCount} LINES)</span>
                              </>
                            )}
                          </button>

                          {/* Preview Code Box */}
                          {isExpanded && (
                            <div className="mt-2 p-2.5 bg-[#050505] border border-[#222222] text-[10px] font-mono overflow-x-auto max-h-48 text-[#DDDDDD] whitespace-pre selection:bg-[#222222]">
                              {rev.content.trim() ? rev.content : (
                                <span className="text-[#555555] italic">
                                  // [EMPTY BUFFER - 0 BYTES]
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="h-9 px-4 bg-[#050505] border-t border-[#222222] flex items-center justify-between font-mono text-[9px] text-[#666666] select-none shrink-0 uppercase">
          <div className="flex items-center gap-3">
            <span>[CRUX REVISION KERNEL // Yjs LOG]</span>
            <span className="text-[#333333]">/</span>
            <span className="text-white">HARDWARE BRUTALISM</span>
          </div>
          <button
            onClick={() => setIsOpen(false)}
            className="text-[#888888] hover:text-white transition-none uppercase"
          >
            [ESC // CLOSE]
          </button>
        </div>
      </div>
    </div>
  );
}
