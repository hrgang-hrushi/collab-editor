"use client";

import React from "react";

export default function VoidKeymapBar() {
  const keys = [
    { key: "Tab", action: "Autocomplete" },
    { key: "↑ / ↓", action: "Navigate" },
    { key: "↵ Enter", action: "Execute" },
    { key: "Esc", action: "Clear" },
    { key: "⌘K", action: "Command Palette" },
  ];

  return (
    <div className="absolute bottom-4 inset-x-0 flex items-center justify-center pointer-events-none z-20">
      <div className="flex items-center gap-4 px-3 py-1.5 border border-[#1a1a1a] bg-[#050505]/90 backdrop-blur-sm text-[11px] font-mono text-[#666666]">
        {keys.map((item, idx) => (
          <div key={idx} className="flex items-center gap-1.5">
            <span className="px-1 py-0.5 border border-[#2a2a2a] bg-[#111111] text-[#bbbbbb] text-[10px] font-mono">
              {item.key}
            </span>
            <span>{item.action}</span>
            {idx < keys.length - 1 && <span className="text-[#262626] ml-2">·</span>}
          </div>
        ))}
      </div>
    </div>
  );
}
