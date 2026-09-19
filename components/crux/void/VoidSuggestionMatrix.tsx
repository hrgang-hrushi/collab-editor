"use client";

import React from "react";

export interface VoidSuggestion {
  id: string;
  category: "CLONE" | "AGENT" | "PROJECT" | "RADAR" | "SPATIAL" | "NEW";
  title: string;
  description: string;
  commandSnippet: string;
  badge?: string;
  previewDetails?: {
    type: string;
    target: string;
    payload: string;
    meta: string;
  };
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
  const getCategoryTag = (category: VoidSuggestion["category"]) => {
    switch (category) {
      case "CLONE":
        return "[GIT_CLONE]";
      case "AGENT":
        return "[@CruxAI]";
      case "PROJECT":
        return "[WORKSPACE]";
      case "RADAR":
        return "[LIVE_PEER]";
      case "SPATIAL":
        return "[NEXUS_2D]";
      case "NEW":
        return "[BUFFER_NEW]";
    }
  };

  if (suggestions.length === 0) {
    return (
      <div className="p-8 text-center font-mono text-[11px] text-[#444444] bg-[#000000]">
        [NULL_MATCH: PRESS ENTER TO DISPATCH DIRECT COMMAND]
      </div>
    );
  }

  return (
    <div className="bg-[#000000] w-full max-h-[380px] overflow-y-auto divide-y divide-[#222222] font-sans">
      {suggestions.map((item, idx) => {
        const isSelected = idx === selectedIndex;
        return (
          <div
            key={item.id}
            onMouseEnter={() => onSelectIndex(idx)}
            onClick={() => onExecute(item)}
            className={`px-4 py-2 flex items-center justify-between cursor-pointer transition-none select-none ${
              isSelected
                ? "bg-white text-black"
                : "bg-transparent text-white hover:bg-white hover:text-black"
            }`}
          >
            {/* Left: Action Tag + Primary Title */}
            <div className="flex items-center gap-3 min-w-0 flex-1 pr-4">
              <span
                className={`font-mono text-[10px] px-1.5 py-0.5 border transition-none shrink-0 uppercase tracking-tight ${
                  isSelected
                    ? "border-black bg-black text-white font-bold"
                    : "border-[#222222] bg-[#111111] text-[#888888]"
                }`}
              >
                {getCategoryTag(item.category)}
              </span>
              <span className="text-sm uppercase tracking-tight truncate font-semibold">
                {item.title}
              </span>
            </div>

            {/* Right: Description / Subtext & Shortcut */}
            <div className="flex items-center gap-4 shrink-0 font-mono text-[11px]">
              <span
                className={`hidden md:inline truncate max-w-[260px] ${
                  isSelected ? "text-[#333333]" : "text-[#555555]"
                }`}
              >
                {item.description}
              </span>

              {item.badge && (
                <span
                  className={`px-1.5 py-0.5 border uppercase text-[9px] ${
                    isSelected
                      ? "border-black text-black font-bold"
                      : "border-[#222222] text-[#666666]"
                  }`}
                >
                  {item.badge}
                </span>
              )}

              <span className="text-xs font-mono">→</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
