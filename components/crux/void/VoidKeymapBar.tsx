"use client";

import React from "react";

export default function VoidKeymapBar() {
  const keys = [
    { key: "TAB", action: "AUTOCOMPLETE" },
    { key: "↑ / ↓", action: "NAVIGATE MATRIX" },
    { key: "ENTER", action: "EXECUTE" },
    { key: "ESC", action: "RESET VOID" },
    { key: "⌘K", action: "COMMAND PALETTE" },
  ];

  return (
    <footer className="absolute bottom-0 inset-x-0 h-7 px-2 flex items-center justify-between border-t border-[#222222] bg-[#000000] z-50 select-none font-mono text-[10px] text-[#444444]">
      <div className="flex items-center gap-3">
        {keys.map((item, idx) => (
          <div key={idx} className="flex items-center gap-1">
            <span className="px-1 border border-[#222222] bg-[#111111] text-white">
              [{item.key}]
            </span>
            <span>{item.action}</span>
          </div>
        ))}
      </div>
      <div className="hidden sm:block text-[#222222]">
        HARDWARE_BRUTALISM // 0PX_RADIUS // ZERO_COLOR
      </div>
    </footer>
  );
}
