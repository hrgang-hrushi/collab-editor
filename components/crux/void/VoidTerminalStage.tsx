"use client";

import React, { useEffect, useRef } from "react";
import { Terminal, Loader2, CheckCircle, ArrowRight } from "lucide-react";

interface TerminalLine {
  id: string;
  text: string;
  type?: "info" | "success" | "warn" | "error" | "dim";
}

interface VoidTerminalStageProps {
  title: string;
  command: string;
  lines: TerminalLine[];
  isRunning: boolean;
  isComplete: boolean;
  onFinish: () => void;
}

export default function VoidTerminalStage({
  title,
  command,
  lines,
  isRunning,
  isComplete,
  onFinish,
}: VoidTerminalStageProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className="w-full border border-[#262626] bg-[#050505] flex flex-col shadow-2xl transition-all duration-300 min-h-[260px] max-h-[360px]">
      {/* Terminal Titlebar */}
      <div className="h-8 px-3 border-b border-[#222222] bg-[#0c0c0c] flex items-center justify-between font-mono text-[11px] text-[#888888] select-none">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-white" />
          <span className="text-white font-medium">{title}</span>
          <span className="text-[#444444]">|</span>
          <span className="text-[#666666] truncate max-w-[280px]">{command}</span>
        </div>
        <div className="flex items-center gap-2">
          {isRunning && (
            <div className="flex items-center gap-1.5 text-[#00FF66]">
              <Loader2 className="w-3 h-3 animate-spin" />
              <span className="text-[10px] tracking-wider uppercase">EXECUTING</span>
            </div>
          )}
          {isComplete && (
            <div className="flex items-center gap-1.5 text-[#00FF66]">
              <CheckCircle className="w-3 h-3" />
              <span className="text-[10px] tracking-wider uppercase">READY</span>
            </div>
          )}
        </div>
      </div>

      {/* Output Stream */}
      <div
        ref={scrollRef}
        className="flex-1 p-3 overflow-y-auto font-mono text-[12px] space-y-1 bg-[#000000] text-[#D4D4D4] select-text"
      >
        <div className="text-[#555555]">
          crux-kernel v1.2.0 (x86_64-apple-darwin) — PID 7447
        </div>
        <div className="text-white">
          <span className="text-[#00FF66]">crux ❯</span> {command}
        </div>

        {lines.map((l) => {
          let color = "text-[#cccccc]";
          if (l.type === "success") color = "text-[#00FF66]";
          if (l.type === "warn") color = "text-[#FF9F0A]";
          if (l.type === "error") color = "text-[#FF453A]";
          if (l.type === "dim") color = "text-[#555555]";
          return (
            <div key={l.id} className={`leading-relaxed whitespace-pre-wrap break-all ${color}`}>
              {l.text}
            </div>
          );
        })}

        {isRunning && (
          <div className="flex items-center gap-1 text-[#666666] animate-pulse">
            <span className="inline-block w-2 h-3 bg-white" />
          </div>
        )}
      </div>

      {/* Complete Action Footer */}
      {isComplete && (
        <div className="h-10 px-3 border-t border-[#222222] bg-[#0c0c0c] flex items-center justify-between">
          <span className="text-[11px] font-mono text-[#888888]">
            Process exited with code 0 (Vector Clocks synchronized)
          </span>
          <button
            onClick={onFinish}
            className="flex items-center gap-1.5 px-3 py-1 bg-white text-black text-xs font-semibold hover:bg-[#E0E0E0] transition-colors"
          >
            <span>Enter IDE</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
