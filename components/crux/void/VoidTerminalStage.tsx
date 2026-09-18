"use client";

import React, { useEffect, useRef } from "react";

interface TerminalLine {
  id: string;
  text: string;
  isAgent?: boolean;
  agentTag?: string;
  isPeer?: boolean;
  peerTag?: string;
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
    <div className="w-full border border-[#222222] bg-[#000000] flex flex-col font-mono text-[12px]">
      {/* Terminal Titlebar (h-8, bg-[#111111], border-b border-[#222222]) */}
      <div className="h-8 px-2 border-b border-[#222222] bg-[#111111] flex items-center justify-between text-[11px] text-[#444444] select-none font-sans uppercase">
        <div className="flex items-center gap-2">
          <span className="font-mono text-white font-bold">[{title}]</span>
          <span className="text-[#222222]">|</span>
          <span className="font-mono text-[#888888] truncate max-w-[280px]">
            {command}
          </span>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px]">
          {isRunning && (
            <div className="flex items-center gap-1 text-white">
              <span className="inline-block w-1.5 h-1.5 bg-white animate-hard-blink" />
              <span>[PROCESSING_STREAM]</span>
            </div>
          )}
          {isComplete && (
            <div className="text-white">
              <span>[EXIT_CODE_0: SYNCHRONIZED]</span>
            </div>
          )}
        </div>
      </div>

      {/* Output Stream (Dense, tabular lining, exact alignment) */}
      <div
        ref={scrollRef}
        className="h-56 p-2 overflow-y-auto font-mono text-[12px] leading-relaxed space-y-1 bg-[#000000] text-white select-text"
      >
        <div className="text-[#444444]">
          [CREX BARE-METAL KERNEL v1.2.0 // TTY_ATTACHED // ZERO_COLOR]
        </div>
        <div className="text-white">
          <span className="text-white font-bold">crex ❯</span> {command}
        </div>

        {lines.map((l) => (
          <div
            key={l.id}
            className={`whitespace-pre-wrap break-all ${
              l.isAgent ? "pl-3 border-l border-[#222222] text-white" : "text-[#D4D4D4]"
            }`}
          >
            {l.isAgent && (
              <span className="text-white font-bold mr-2">
                {l.agentTag || "[@CrexAI]"}
              </span>
            )}
            {l.isPeer && (
              <span className="text-white font-bold mr-2">
                {l.peerTag} <span className="animate-hard-blink">[LIVE]</span>
              </span>
            )}
            <span>{l.text}</span>
          </div>
        ))}

        {isRunning && (
          <div className="flex items-center gap-1 text-white mt-1">
            <span className="crex-cursor" />
          </div>
        )}
      </div>

      {/* Complete Action Footer */}
      {isComplete && (
        <div className="h-8 px-2 border-t border-[#222222] bg-[#111111] flex items-center justify-between select-none">
          <span className="text-[10px] font-mono text-[#444444] uppercase">
            VECTOR CLOCK: RESOLVED | PIPELINE UNLOCKED
          </span>
          <button
            onClick={onFinish}
            className="btn-crex h-6 px-3 bg-white text-black font-mono font-bold hover:bg-[#111111] hover:text-white transition-none"
          >
            [ENTER WORKSPACE] →
          </button>
        </div>
      )}
    </div>
  );
}
