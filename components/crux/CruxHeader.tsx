"use client";

import React from "react";
import {
  Share2,
  ChevronRight,
  FileCode2,
  GitBranch,
} from "lucide-react";

interface CruxHeaderProps {
  onToggleSuggestMode?: () => void;
  isSuggestMode?: boolean;
}

export default function CruxHeader({
  onToggleSuggestMode,
  isSuggestMode = false,
}: CruxHeaderProps) {
  return (
    <header className="w-full h-10 px-3 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A] select-none text-xs font-mono">
      {/* Left: Brand + Breadcrumbs */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 bg-[#141516] border border-[#222222] flex items-center justify-center">
            <span className="font-bold text-[10px] text-[#5e6ad2]">✕</span>
          </div>
          <span className="font-bold text-xs tracking-tight text-[#f7f8f8]">
            CRUX
          </span>
          <span className="w-1.5 h-1.5 bg-[#27a644]" />
          <span className="text-[10px] text-[#62666d] hidden sm:inline">
            0.08ms
          </span>
        </div>

        <div className="h-3 w-[1px] bg-[#222222] mx-0.5" />

        {/* File Breadcrumb */}
        <div className="flex items-center gap-1.5 text-xs text-[#8a8f98]">
          <span className="text-[#62666d]">core</span>
          <ChevronRight className="w-3 h-3 text-[#62666d]" />
          <span className="text-[#62666d]">daemon</span>
          <ChevronRight className="w-3 h-3 text-[#62666d]" />
          <div className="flex items-center gap-1.5 text-[#f7f8f8] px-1.5 py-0.2 bg-[#141516] border border-[#222222]">
            <FileCode2 className="w-3.5 h-3.5 text-[#5e6ad2]" />
            <span>stream_syncer.ts</span>
          </div>
        </div>
      </div>

      {/* Right: Flat Collaborator Badges & Actions */}
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-1">
          <div className="px-1.5 py-0.5 text-[10px] bg-[#141516] border border-[#222222] text-[#f7f8f8]">
            <span className="text-[#5e6ad2] mr-1">●</span>
            <span>SL</span>
          </div>

          <div className="px-1.5 py-0.5 text-[10px] bg-[#141516] border border-[#222222] text-[#5e6ad2]">
            <span>@CruxAI</span>
          </div>
        </div>

        <div className="h-3 w-[1px] bg-[#222222] mx-0.5" />

        <button
          onClick={onToggleSuggestMode}
          className={`px-2 py-0.5 border text-xs transition-colors ${
            isSuggestMode
              ? "bg-[#141516] text-[#5e6ad2] border-[#5e6ad2]"
              : "bg-transparent text-[#8a8f98] hover:text-[#f7f8f8] border-[#222222]"
          }`}
        >
          {isSuggestMode ? "Suggesting" : "Direct Edit"}
        </button>
      </div>
    </header>
  );
}
