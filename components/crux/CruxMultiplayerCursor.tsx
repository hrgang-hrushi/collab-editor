"use client";

import React from "react";

interface CruxMultiplayerCursorProps {
  name?: string;
  status?: string;
  color?: string;
}

export default function CruxMultiplayerCursor({
  name = "Sarah Lin",
  status = "editing",
  color = "#5e6ad2",
}: CruxMultiplayerCursorProps) {
  return (
    <div className="relative inline-flex items-center select-none pointer-events-none z-30">
      {/* Flat and Razor-Sharp SVG Caret Pointer - Zero drop shadow, zero gradient */}
      <svg
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        className="shrink-0"
      >
        <path
          d="M0 0L14 5.5L7.5 7.5L5.5 14L0 0Z"
          fill={color}
          stroke="#000000"
          strokeWidth="1"
          strokeLinejoin="miter"
        />
      </svg>

      {/* Flat & Sharp Name Tag - 1px border, pure flat surface, zero glow */}
      <div className="ml-1 -mt-4 inline-flex items-center gap-1 px-1.5 py-0.5 bg-[#141516] border border-[#222222] rounded-none text-[10px] font-mono text-[#f7f8f8] tracking-tight">
        <span
          className="w-1.5 h-1.5 shrink-0"
          style={{ backgroundColor: color }}
        />
        <span className="font-medium text-[#f7f8f8]">{name}</span>
        {status && (
          <span className="text-[#8a8f98] text-[9px] border-l border-[#222222] pl-1 ml-0.5 hidden sm:inline">
            {status}
          </span>
        )}
      </div>
    </div>
  );
}
