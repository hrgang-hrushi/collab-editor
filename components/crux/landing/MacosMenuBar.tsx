"use client";

import React, { useState, useEffect } from "react";
import { Wifi, Cpu, Activity } from "lucide-react";
import CruxBrandLogo from "../CruxBrandLogo";

interface MacosMenuBarProps {
  onOpenWaitlist: () => void;
}

export default function MacosMenuBar({ onOpenWaitlist }: MacosMenuBarProps) {
  const [time, setTime] = useState("");

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTime(
        now.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div
      className="hidden md:flex items-center justify-between px-4 h-7 bg-[#000000] border-b border-[#222222] text-[11px] font-mono text-[#888888] select-none z-50 fixed top-0 left-0 right-0"
      style={{
        fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
      }}
    >
      {/* Left: Official Crux Logo + App Menus */}
      <div className="flex items-center gap-4">
        {/* Crux Logo */}
        <div className="flex items-center gap-2">
          <CruxBrandLogo size={14} />
          <span className="font-bold text-white tracking-tight">Crux</span>
        </div>
        <span className="hover:text-white cursor-pointer transition-none">File</span>
        <span className="hover:text-white cursor-pointer transition-none">Edit</span>
        <span className="hover:text-white cursor-pointer transition-none">Selection</span>
        <span className="hover:text-white cursor-pointer transition-none">View</span>
        <span className="hover:text-white cursor-pointer transition-none">WebGPU</span>
        <span className="hover:text-white cursor-pointer transition-none">Terminal</span>
        <span className="hover:text-white cursor-pointer transition-none">Help</span>
      </div>

      {/* Right: Real-time System Metrics & Waitlist Action */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-[#888888]">
          <Cpu className="w-3 h-3 text-white" />
          <span className="text-[10px]">Apple Silicon Metal v3</span>
        </div>
        <div className="w-[1px] h-3 bg-[#222222]" />
        <div className="flex items-center gap-1.5 text-white">
          <span className="w-1.5 h-1.5 rounded-none bg-white" />
          <span className="text-[10px]">120 FPS / 4.2ms</span>
        </div>
        <div className="w-[1px] h-3 bg-[#222222]" />
        <div className="flex items-center gap-1 text-[#888888]">
          <Wifi className="w-3 h-3 text-white" />
          <span className="text-[10px]">P2P In-Sync</span>
        </div>
        <div className="w-[1px] h-3 bg-[#222222]" />
        <span className="text-white font-medium">{time || "12:00 PM"}</span>

        <button
          onClick={onOpenWaitlist}
          className="ml-2 px-2.5 py-0.5 rounded-none bg-white hover:bg-[#111111] hover:text-white border border-white text-black font-bold text-[10px] uppercase tracking-wider transition-none cursor-pointer flex items-center gap-1"
        >
          <span>Join Waitlist</span>
        </button>
      </div>
    </div>
  );
}
