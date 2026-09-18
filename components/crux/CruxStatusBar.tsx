"use client";

import React from "react";
import { Cpu, Wifi, ShieldCheck } from "lucide-react";

export default function CruxStatusBar() {
  return (
    <footer className="w-full h-6 px-3 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[10px] font-mono text-[#888888] select-none">
      {/* Left: Daemon IPC & Engine Telemetry */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-white">
          <span className="w-1.5 h-1.5 rounded-none bg-[#007AFF]" />
          <span className="font-medium">Crux Daemon</span>
          <span className="text-white text-[9px] px-1 bg-black border border-[#222222] rounded-none">
            0.08ms IPC
          </span>
        </div>

        <span className="text-[#222222]">·</span>

        <div className="hidden sm:flex items-center gap-1.5 text-[#888888]">
          <Cpu className="w-3 h-3 text-[#888888]" />
          <span>Local Engine: Apple Silicon Metal Compute (128 tok/s)</span>
        </div>
      </div>

      {/* Right: Sync Status & Security */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-[#888888]">
          <ShieldCheck className="w-3 h-3 text-[#888888]" />
          <span className="hidden md:inline">Zero-Knowledge CRDT Vector</span>
        </div>

        <span className="text-[#222222]">·</span>

        <div className="flex items-center gap-1.5 text-white">
          <Wifi className="w-3 h-3 text-[#007AFF]" />
          <span>2 Peers In-Sync</span>
        </div>
      </div>
    </footer>
  );
}
