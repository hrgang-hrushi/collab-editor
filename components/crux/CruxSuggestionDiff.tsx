"use client";

import React, { useState } from "react";
import { Check, X } from "lucide-react";

interface CruxSuggestionDiffProps {
  onAccept?: () => void;
  onReject?: () => void;
}

export default function CruxSuggestionDiff({
  onAccept,
  onReject,
}: CruxSuggestionDiffProps) {
  const [status, setStatus] = useState<"pending" | "accepted" | "rejected">("pending");

  const handleAccept = (e: React.MouseEvent) => {
    e.stopPropagation();
    setStatus("accepted");
    if (onAccept) onAccept();
  };

  const handleReject = (e: React.MouseEvent) => {
    e.stopPropagation();
    setStatus("rejected");
    if (onReject) onReject();
  };

  const handleReset = (e: React.MouseEvent) => {
    e.stopPropagation();
    setStatus("pending");
  };

  if (status === "accepted") {
    return (
      <div className="flex items-center group py-1.5 my-1.5 rounded-none bg-[#00FF00]/10 border border-[#222222] px-3 font-mono text-[12px]">
        <span className="text-[#888888] select-none w-8 text-right pr-3 text-[11px]">
          15
        </span>
        <span className="text-white flex-1 font-mono">
          {"    "}
          const timeout = Math.min(attempt * 1000, 30000);
        </span>
        <div className="flex items-center gap-2 select-none pl-2 font-mono text-[10px]">
          <span className="text-[#00FF00] uppercase tracking-wider px-1.5 py-0.5 bg-black border border-[#222222]">
            ACCEPTED
          </span>
          <button
            onClick={handleReset}
            className="text-[#888888] hover:text-white uppercase tracking-wider underline font-mono"
            title="Reset diff"
          >
            Reset
          </button>
        </div>
      </div>
    );
  }

  if (status === "rejected") {
    return (
      <div className="flex items-center group py-1.5 my-1.5 rounded-none bg-[#0A0A0A] border border-[#222222] px-3 font-mono text-[12px]">
        <span className="text-[#888888] select-none w-8 text-right pr-3 text-[11px]">
          15
        </span>
        <span className="text-[#888888] flex-1 font-mono">
          {"    "}
          const timeout = 5000; // Static 5s fallback
        </span>
        <div className="flex items-center gap-2 select-none pl-2 font-mono text-[10px]">
          <span className="text-[#888888] uppercase tracking-wider px-1.5 py-0.5 bg-black border border-[#222222]">
            REJECTED
          </span>
          <button
            onClick={handleReset}
            className="text-[#888888] hover:text-white uppercase tracking-wider underline font-mono"
            title="Reset diff"
          >
            Reset
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="my-2 rounded-none border border-[#222222] bg-black font-mono text-[12px] select-text overflow-hidden">
      {/* Diff Meta Header */}
      <div className="h-7 px-3 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A] select-none text-[10px] tracking-wide font-sans">
        <div className="flex items-center gap-2 text-[#888888]">
          <span className="w-1.5 h-1.5 rounded-none bg-[#007AFF]" />
          <span className="font-semibold text-white uppercase tracking-widest text-[10px]">Sarah Lin</span>
          <span className="text-[#888888]">PROPOSED DIFF</span>
          <span className="text-[#222222]">/</span>
          <span className="text-[#888888] font-mono">2m ago</span>
        </div>

        {/* Flat 1px bordered action buttons */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={handleAccept}
            title="Accept replacement (⌘↵)"
            className="h-5 px-2 rounded-none bg-transparent hover:bg-[#222222] border border-[#222222] text-white text-[10px] font-mono transition-none flex items-center gap-1"
          >
            <Check className="w-3 h-3 text-[#00FF00]" />
            <span>ACCEPT</span>
            <span className="text-[#888888] text-[9px] hidden sm:inline">⌘↵</span>
          </button>

          <button
            onClick={handleReject}
            title="Reject replacement (Esc)"
            className="h-5 px-2 rounded-none bg-transparent hover:bg-[#222222] border border-[#222222] text-[#888888] hover:text-white text-[10px] font-mono transition-none flex items-center gap-1"
          >
            <X className="w-3 h-3 text-[#FF453A]" />
            <span>REJECT</span>
            <span className="text-[#888888] text-[9px] hidden sm:inline">Esc</span>
          </button>
        </div>
      </div>

      {/* Diff Removal Line: CruxAI Crimson (#FF453A) at 10% opacity */}
      <div className="flex items-center py-1.5 px-3 bg-[#FF453A]/10 border-l-2 border-[#FF453A] text-[#FF453A] font-mono">
        <span className="w-6 text-right pr-2.5 select-none text-[#FF453A] text-[11px] font-semibold">
          -
        </span>
        <span className="line-through flex-1 opacity-90">
          {"    "}
          const timeout = 5000; // Legacy static timeout
        </span>
      </div>

      {/* Diff Addition Line: Success Green (#00FF00) at 10% opacity */}
      <div className="flex items-center py-1.5 px-3 bg-[#00FF00]/10 border-l-2 border-[#00FF00] text-white font-mono">
        <span className="w-6 text-right pr-2.5 select-none text-[#00FF00] text-[11px] font-semibold">
          +
        </span>
        <span className="flex-1">
          {"    "}
          const timeout = Math.min(attempt * 1000, 30000); // Dynamic backoff
        </span>
      </div>
    </div>
  );
}
