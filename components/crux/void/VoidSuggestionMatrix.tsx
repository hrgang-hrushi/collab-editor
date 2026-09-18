"use client";

import React from "react";

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
      <div className="p-3 text-center font-mono text-[11px] text-[#444444] border-t border-[#222222] bg-[#000000]">
        [NULL_MATCH: PRESS ENTER TO EXECUTE RAW MACHINE INSTRUCTION]
      </div>
    );
  }

  const getCategoryTag = (category: VoidSuggestion["category"]) => {
    switch (category) {
      case "CLONE":
        return "[GIT_CLONE]";
      case "AGENT":
        return "[@CrexAI]";
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

  return (
    <div className="max-h-[300px] overflow-y-auto border-t border-[#222222] bg-[#000000] divide-y divide-[#222222] select-none font-sans">
      {suggestions.map((item, idx) => {
        const isSelected = idx === selectedIndex;
        return (
          <div
            key={item.id}
            onMouseEnter={() => onSelectIndex(idx)}
            onClick={() => onExecute(item)}
            className={`px-3 py-2 flex items-center justify-between cursor-pointer transition-none ${
              isSelected
                ? "bg-white text-black font-semibold"
                : "bg-transparent text-white hover:bg-white hover:text-black"
            }`}
          >
            {/* Left Column: Category Tag + Command Title */}
            <div className="flex items-center gap-2 min-w-0 flex-1">
              <span
                className={`font-mono text-[10px] px-1 py-0.2 border transition-none shrink-0 uppercase ${
                  isSelected
                    ? "border-black bg-black text-white"
                    : "border-[#222222] bg-[#111111] text-white"
                }`}
              >
                {getCategoryTag(item.category)}
              </span>
              <span className="text-xs uppercase tracking-tight truncate">
                {item.title}
              </span>
              <span
                className={`hidden md:inline text-[11px] font-mono truncate transition-none ${
                  isSelected ? "text-black/70" : "text-[#444444]"
                }`}
              >
                — {item.description}
              </span>
            </div>

            {/* Right Column: Monospace Command Snippet / Status */}
            <div className="flex items-center gap-2 shrink-0 ml-2 font-mono text-[10px]">
              {item.badge && (
                <span
                  className={`px-1 py-0.2 border uppercase ${
                    isSelected
                      ? "border-black text-black"
                      : "border-[#222222] text-[#888888]"
                  }`}
                >
                  {item.badge}
                </span>
              )}
              <span
                className={`hidden sm:inline px-1.5 py-0.5 border ${
                  isSelected
                    ? "border-black bg-black text-white"
                    : "border-[#222222] bg-[#111111] text-[#FFFFFF]"
                }`}
              >
                {item.commandSnippet}
              </span>
              <span className="font-mono text-xs">→</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
