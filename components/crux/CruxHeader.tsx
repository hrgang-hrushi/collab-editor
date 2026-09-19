"use client";

import React from "react";
import {
  Share2,
  ChevronRight,
  FileCode2,
  GitBranch,
} from "lucide-react";

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
    <header className="w-full h-9 px-3 flex items-center justify-between border-b border-[#222222] bg-[#111111] select-none text-xs font-mono">
      {/* Left: Brand + Breadcrumbs */}
      <div className="flex items-center gap-3">
        <CruxBrandLogo withText={true} size={16} />

        <div className="h-3 w-[1px] bg-[#222222] mx-0.5" />

        {/* File Breadcrumb */}
        <div className="flex items-center gap-1.5 text-xs text-[#444444]">
          <span className="text-[#444444]">core</span>
          <ChevronRight className="w-3 h-3 text-[#222222]" />
          <span className="text-[#444444]">kernel</span>
          <ChevronRight className="w-3 h-3 text-[#222222]" />
          <div className="flex items-center gap-1.5 text-white px-1.5 py-0.5 bg-[#000000] border border-[#222222]">
            <FileCode2 className="w-3.5 h-3.5 text-white" />
            <span>crex_canvas.rs</span>
          </div>
        </div>
      </div>

      {/* Right: Flat Collaborator Badges & Actions */}
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-1">
          <div className="px-1.5 py-0.5 text-[10px] bg-[#000000] border border-[#222222] text-white">
            <span className="text-white mr-1 font-bold">●</span>
            <span>PEER_1</span>
          </div>

          <div className="px-1.5 py-0.5 text-[10px] bg-[#000000] border border-[#222222] text-white font-semibold">
            <span>[@CrexAI]</span>
          </div>
        </div>

        <div className="h-3 w-[1px] bg-[#222222] mx-0.5" />

        <button
          onClick={onToggleSuggestMode}
          className={`px-2 py-0.5 border text-xs transition-none rounded-none font-mono ${
            isSuggestMode
              ? "bg-white text-black border-white"
              : "bg-transparent text-[#444444] hover:bg-white hover:text-black border-[#222222]"
          }`}
        >
          {isSuggestMode ? "[SUGGESTING]" : "[DIRECT EDIT]"}
        </button>
      </div>
    </header>
  );
}

