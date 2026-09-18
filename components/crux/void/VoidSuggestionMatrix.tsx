"use client";

import React from "react";
import { GitBranch, Sparkles, Folder, Users, LayoutGrid, FilePlus, ChevronRight } from "lucide-react";

export interface VoidSuggestion {
  id: string;
  category: "CLONE" | "AGENT" | "PROJECT" | "RADAR" | "SPATIAL" | "NEW";
  title: string;
  description: string;
  commandSnippet: string;
  badge?: string;
  action: () => void;
}

interface VoidSuggestionMatrixProps {
  suggestions: VoidSuggestion[];
  selectedIndex: number;
  onSelectIndex: (index: number) => void;
  onExecute: (item: VoidSuggestion) => void;
}

export default function VoidSuggestionMatrix({
  suggestions,
  selectedIndex,
  onSelectIndex,
  onExecute,
}: VoidSuggestionMatrixProps) {
  if (suggestions.length === 0) {
    return (
      <div className="p-4 text-center font-mono text-xs text-[#555555] border-t border-[#1a1a1a]">
        No matching actions. Press <span className="text-white">↵ Enter</span> to execute raw command.
      </div>
    );
  }

  const getCategoryIcon = (category: VoidSuggestion["category"]) => {
    switch (category) {
      case "CLONE":
        return <GitBranch className="w-3.5 h-3.5 text-[#007AFF]" />;
      case "AGENT":
        return <Sparkles className="w-3.5 h-3.5 text-[#FF453A]" />;
      case "PROJECT":
        return <Folder className="w-3.5 h-3.5 text-[#E0E0E0]" />;
      case "RADAR":
        return <Users className="w-3.5 h-3.5 text-[#00FF66]" />;
      case "SPATIAL":
        return <LayoutGrid className="w-3.5 h-3.5 text-[#FF9F0A]" />;
      case "NEW":
        return <FilePlus className="w-3.5 h-3.5 text-[#FFFFFF]" />;
    }
  };

  const getCategoryBadgeClass = (category: VoidSuggestion["category"]) => {
    switch (category) {
      case "CLONE":
        return "border-[#007AFF]/40 text-[#007AFF] bg-[#007AFF]/10";
      case "AGENT":
        return "border-[#FF453A]/40 text-[#FF453A] bg-[#FF453A]/10";
      case "PROJECT":
        return "border-[#333333] text-[#AAAAAA] bg-[#111111]";
      case "RADAR":
        return "border-[#00FF66]/40 text-[#00FF66] bg-[#00FF66]/10";
      case "SPATIAL":
        return "border-[#FF9F0A]/40 text-[#FF9F0A] bg-[#FF9F0A]/10";
      case "NEW":
        return "border-white/30 text-white bg-white/10";
    }
  };

  return (
    <div className="max-h-[300px] overflow-y-auto border-t border-[#1a1a1a] bg-[#050505] divide-y divide-[#111111] select-none">
      {suggestions.map((item, idx) => {
        const isSelected = idx === selectedIndex;
        return (
          <div
            key={item.id}
            onMouseEnter={() => onSelectIndex(idx)}
            onClick={() => onExecute(item)}
            className={`px-3 py-2.5 flex items-center justify-between cursor-pointer transition-colors ${
              isSelected
                ? "bg-[#111111] border-l-2 border-white pl-[10px]"
                : "hover:bg-[#0c0c0c] border-l-2 border-transparent"
            }`}
          >
            {/* Left Column: Icon + Category Badge + Title */}
            <div className="flex items-center gap-2.5 min-w-0 flex-1">
              <span className="shrink-0">{getCategoryIcon(item.category)}</span>
              <span
                className={`text-[9px] font-mono font-bold px-1.5 py-0.5 border shrink-0 uppercase tracking-wider ${getCategoryBadgeClass(
                  item.category
                )}`}
              >
                {item.category}
              </span>
              <span className="text-xs text-white font-medium truncate font-sans">
                {item.title}
              </span>
              <span className="hidden md:inline text-[11px] text-[#666666] truncate font-sans">
                {item.description}
              </span>
            </div>

            {/* Right Column: Code Snippet / Shortcut */}
            <div className="flex items-center gap-2 shrink-0 ml-3">
              {item.badge && (
                <span className="text-[10px] font-mono text-[#00FF66] border border-[#00FF66]/30 px-1.5 py-0.2 bg-[#00FF66]/5">
                  {item.badge}
                </span>
              )}
              <span className="hidden sm:inline font-mono text-[10px] text-[#555555] bg-[#0c0c0c] px-1.5 py-0.5 border border-[#1f1f1f]">
                {item.commandSnippet}
              </span>
              <ChevronRight
                className={`w-3.5 h-3.5 ${
                  isSelected ? "text-white" : "text-[#333333]"
                }`}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
