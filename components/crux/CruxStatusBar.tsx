"use client";

import React from "react";
import { Cpu, Wifi, ShieldCheck } from "lucide-react";

export default function CruxStatusBar() {
  return (
    <footer className="w-full h-6 px-3 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[10.5px] font-mono text-[#8a8f98] select-none">
      {/* Left: Daemon IPC & Engine Telemetry */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-[#f7f8f8]">
          <span className="w-1.5 h-1.5 bg-[#27a644]" />
          <span className="font-medium">Crux Daemon</span>
          <span className="text-[#27a644] text-[10px] px-1 bg-[#27a644]/10 border border-[#27a644]/30">
            0.08ms IPC
          </span>
        </div>

        <span className="text-[#333333]">·</span>

        <div className="hidden sm:flex items-center gap-1.5 text-[#8a8f98]">
          <Cpu className="w-3 h-3 text-[#5e6ad2]" />
          <span>Local Engine: Apple Silicon Metal Compute (128 tok/s)</span>
        </div>
      </div>

      {/* Right: Sync Status & Security */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-[#8a8f98]">
          <ShieldCheck className="w-3 h-3 text-[#5e6ad2]" />
          <span className="hidden md:inline">Zero-Knowledge CRDT Vector</span>
        </div>

        <span className="text-[#333333]">·</span>

        <div className="flex items-center gap-1.5 text-[#27a644]">
          <Wifi className="w-3 h-3" />
          <span>2 Peers In-Sync</span>
        </div>
      </div>
    </footer>
  );
}
