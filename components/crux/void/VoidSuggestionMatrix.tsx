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
  const selectedItem = suggestions[selectedIndex] || suggestions[0];

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

  if (suggestions.length === 0) {
    return (
      <div className="p-4 text-center font-mono text-[11px] text-[#444444] border-t border-[#222222] bg-[#000000]">
        [NULL_MATCH: PRESS ENTER TO DISPATCH DIRECT HARDWARE COMMAND]
      </div>
    );
  }

  return (
    <div className="border-t border-[#222222] bg-[#000000] flex flex-col md:flex-row divide-y md:divide-y-0 md:divide-x divide-[#222222]">
      {/* 1. Command Matrix Rows (Left Pane) */}
      <div className="flex-1 max-h-[320px] overflow-y-auto divide-y divide-[#222222] font-sans">
        {suggestions.map((item, idx) => {
          const isSelected = idx === selectedIndex;
          return (
            <div
              key={item.id}
              onMouseEnter={() => onSelectIndex(idx)}
              onClick={() => onExecute(item)}
              className={`px-3 py-2.5 flex items-center justify-between cursor-pointer transition-none ${
                isSelected
                  ? "bg-white text-black font-semibold"
                  : "bg-transparent text-white hover:bg-white hover:text-black"
              }`}
            >
              {/* Category Tag + Title */}
              <div className="flex items-center gap-2 min-w-0 flex-1">
                <span
                  className={`font-mono text-[9px] px-1 py-0.2 border transition-none shrink-0 uppercase ${
                    isSelected
                      ? "border-black bg-black text-white font-bold"
                      : "border-[#222222] bg-[#111111] text-white"
                  }`}
                >
                  {getCategoryTag(item.category)}
                </span>
                <span className="text-xs uppercase tracking-tight truncate">
                  {item.title}
                </span>
              </div>

              {/* Shortcut & Execution Arrow */}
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
                <span className="font-mono text-xs">→</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* 2. Live Hardware Telemetry & Preview Deck (Right Pane) */}
      <div className="hidden md:flex flex-col w-72 bg-[#050505] p-3 font-mono text-[11px] justify-between select-none">
        <div className="space-y-2">
          {/* Deck Header */}
          <div className="flex items-center justify-between text-[9px] text-[#444444] border-b border-[#222222] pb-1 uppercase font-bold tracking-widest">
            <span>// TELEMETRY_DECK</span>
            <span className="text-white animate-hard-blink">[ACTIVE]</span>
          </div>

          {/* Target Title & Payload Preview */}
          {selectedItem && (
            <div className="space-y-1.5">
              <div className="text-white text-xs font-bold uppercase truncate font-sans">
                {selectedItem.title}
              </div>
              <div className="text-[#666666] text-[10px] leading-snug">
                {selectedItem.description}
              </div>

              {/* Dynamic Telemetry Payload */}
              <div className="p-2 border border-[#222222] bg-[#000000] text-[10px] space-y-1 text-[#888888]">
                <div className="flex justify-between text-[#444444] text-[9px] border-b border-[#161616] pb-0.5">
                  <span>SUBSYSTEM</span>
                  <span className="text-white">{selectedItem.category}</span>
                </div>
                {selectedItem.previewDetails ? (
                  <>
                    <div className="text-white font-bold truncate">
                      {selectedItem.previewDetails.target}
                    </div>
                    <pre className="text-[9px] leading-tight text-[#CCCCCC] whitespace-pre-wrap font-mono">
                      {selectedItem.previewDetails.payload}
                    </pre>
                    <div className="text-[9px] text-[#555555] pt-0.5">
                      {selectedItem.previewDetails.meta}
                    </div>
                  </>
                ) : (
                  <>
                    <div className="text-white">COMMAND: {selectedItem.commandSnippet}</div>
                    <div className="text-[#555555]">PIPELINE: MEMORY_MAPPED_DIRECT</div>
                  </>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Silicon Metric Footprint */}
        <div className="pt-2 border-t border-[#222222] text-[9px] text-[#444444] flex justify-between uppercase">
          <span>MMU: 0xCREX</span>
          <span>LATENCY: 0.04ms</span>
        </div>
      </div>
    </div>
  );
}
