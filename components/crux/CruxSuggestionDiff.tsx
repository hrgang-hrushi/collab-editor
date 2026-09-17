"use client";

import React, { useState } from "react";
import { Check, X, RotateCcw } from "lucide-react";

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
      <div className="flex items-center group py-0.5 bg-[#27a644]/10 border-l-2 border-[#27a644] -mx-4 px-4 font-mono text-[12px] transition-colors">
        <span className="text-[#62666d] select-none w-10 text-right pr-4 text-[11px]">
          15
        </span>
        <span className="text-[#27a644] flex-1">
          {"    "}
          <span className="text-[#5e6ad2]">const</span> timeout = Math.
          <span className="text-[#f7f8f8]">min</span>(attempt * 1000, 30000);
        </span>
        <div className="flex items-center gap-1.5 select-none pl-2">
          <span className="text-[10px] text-[#27a644] font-mono px-1 border border-[#27a644]/30">
            ✓ Accepted
          </span>
          <button
            onClick={handleReset}
            className="text-[10px] text-[#8a8f98] hover:text-[#f7f8f8] underline font-mono"
            title="Reset diff demonstration"
          >
            Reset
          </button>
        </div>
      </div>
    );
  }

  if (status === "rejected") {
    return (
      <div className="flex items-center group py-0.5 -mx-4 px-4 font-mono text-[12px]">
        <span className="text-[#62666d] select-none w-10 text-right pr-4 text-[11px]">
          15
        </span>
        <span className="text-[#8a8f98] flex-1">
          {"    "}
          <span className="text-[#5e6ad2]">const</span> timeout = 5000;{" "}
          <span className="text-[#62666d] italic">// Static 5s fallback</span>
        </span>
        <div className="flex items-center gap-1.5 select-none pl-2">
          <span className="text-[10px] text-[#8a8f98] font-mono px-1 border border-[#222222]">
            ✕ Rejected
          </span>
          <button
            onClick={handleReset}
            className="text-[10px] text-[#8a8f98] hover:text-[#f7f8f8] underline font-mono"
            title="Reset diff demonstration"
          >
            Reset
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="my-1 border border-[#222222] bg-[#0A0A0A] font-mono text-[12px] select-text">
      {/* Diff Meta Header - Flat, 1px border, zero shadow */}
      <div className="h-7 px-3 flex items-center justify-between border-b border-[#222222] bg-[#141516] select-none">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 bg-[#5e6ad2]" />
          <span className="text-[11px] font-medium text-[#f7f8f8]">Sarah Lin</span>
          <span className="text-[10px] text-[#8a8f98]">suggested replacement</span>
          <span className="text-[#62666d]">·</span>
          <span className="text-[10px] text-[#62666d]">2m ago</span>
        </div>

        {/* Sharp, Flat Accept / Reject Buttons - Strict 1px borders, zero gradients */}
        <div className="flex items-center gap-1">
          <button
            onClick={handleAccept}
            title="Accept replacement (⌘↵)"
            className="h-5 px-2 bg-[#141516] hover:bg-[#27a644]/20 text-[#27a644] border border-[#222222] hover:border-[#27a644]/40 text-[10px] font-mono transition-colors flex items-center gap-1"
          >
            <Check className="w-3 h-3" />
            <span>Accept</span>
            <span className="text-[#27a644]/60 text-[9px] hidden sm:inline">⌘↵</span>
          </button>

          <button
            onClick={handleReject}
            title="Reject replacement (Esc)"
            className="h-5 px-2 bg-[#141516] hover:bg-[#e5484d]/20 text-[#e5484d] border border-[#222222] hover:border-[#e5484d]/40 text-[10px] font-mono transition-colors flex items-center gap-1"
          >
            <X className="w-3 h-3" />
            <span>Reject</span>
            <span className="text-[#e5484d]/60 text-[9px] hidden sm:inline">Esc</span>
          </button>
        </div>
      </div>

      {/* Diff Removal Line - Flat low-opacity red */}
      <div className="flex items-center py-1 px-3 bg-[#e5484d]/10 border-l-2 border-[#e5484d] text-[#e5484d]">
        <span className="w-8 text-right pr-3 select-none text-[#e5484d]/60 text-[11px]">
          -
        </span>
        <span className="line-through flex-1">
          {"    "}
          <span className="text-[#e5484d]/80">const</span> timeout = 5000;{" "}
          <span className="italic text-[#e5484d]/60">// Legacy static timeout</span>
        </span>
      </div>

      {/* Diff Addition Line - Flat low-opacity green */}
      <div className="flex items-center py-1 px-3 bg-[#27a644]/10 border-l-2 border-[#27a644] text-[#27a644]">
        <span className="w-8 text-right pr-3 select-none text-[#27a644]/60 text-[11px]">
          +
        </span>
        <span className="flex-1">
          {"    "}
          <span className="text-[#5e6ad2]">const</span> timeout = Math.
          <span className="text-[#f7f8f8]">min</span>(attempt * 1000, 30000);{" "}
          <span className="text-[#27a644]/80 italic">// Dynamic exponential backoff</span>
        </span>
      </div>
    </div>
  );
}
