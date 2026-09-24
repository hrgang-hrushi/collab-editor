"use client";

import React from "react";
import {
  Share2,
  ChevronRight,
  FileCode2,
  GitBranch,
} from "lucide-react";
import CruxMultiplayerPresence from "./presence/CruxMultiplayerPresence";
import CruxBrandLogo from "./CruxBrandLogo";

interface CruxHeaderProps {
  onToggleSuggestMode?: () => void;
  isSuggestMode?: boolean;
}

export default function CruxHeader({
  onToggleSuggestMode,
  isSuggestMode = false,
}: CruxHeaderProps) {
  return (
    <header className="w-full h-9 px-3 flex items-center justify-between border-b border-[#222222] bg-[#000000] select-none text-xs font-mono">
      {/* Left: Brand + Breadcrumbs */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <CruxBrandLogo size={16} withText={true} />
          <span className="w-1.5 h-1.5 rounded-none bg-white ml-1" />
          <span className="text-[10px] text-[#888888] hidden sm:inline font-mono">
            0.08ms
          </span>
        </div>

        <div className="h-3 w-[1px] bg-[#222222] mx-0.5" />

        {/* File Breadcrumb */}
        <div className="flex items-center gap-1.5 text-xs text-[#888888]">
          <span className="text-[#888888]">core</span>
          <ChevronRight className="w-3 h-3 text-[#222222]" />
          <span className="text-[#888888]">daemon</span>
          <ChevronRight className="w-3 h-3 text-[#222222]" />
          <div className="flex items-center gap-1.5 text-white px-1.5 py-0.5 bg-black border border-[#222222]">
            <FileCode2 className="w-3.5 h-3.5 text-white" />
            <span>stream_syncer.ts</span>
          </div>
        </div>
      </div>

      {/* Right: Flat Collaborator Badges & Actions */}
      <div className="flex items-center gap-2">
        <CruxMultiplayerPresence />

        <div className="h-3 w-[1px] bg-[#222222] mx-0.5" />

        <button
          onClick={onToggleSuggestMode}
          className={`px-2 py-0.5 border text-xs transition-none rounded-none font-mono ${
            isSuggestMode
              ? "bg-white text-black border-white font-bold"
              : "bg-black text-[#888888] hover:text-white border-[#222222]"
          }`}
        >
          {isSuggestMode ? "Suggesting" : "Direct Edit"}
        </button>
      </div>
    </header>
  );
}
