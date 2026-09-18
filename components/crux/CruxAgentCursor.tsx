"use client";

import React, { useEffect, useState } from "react";
import { Bot, Check, Play, Pause, RotateCcw, Sparkles } from "lucide-react";

interface CruxAgentCursorProps {
  onMerge?: () => void;
  isSplitPane?: boolean;
}

const STREAM_SNIPPET = `// Speculative concurrent branch synthesized by @CruxAI
export async function verifyPeerAttestation(
  peer: MeshPeer,
  fence: MemoryFence
): Promise<AttestationResult> {
  const lease = await daemonIPC.acquireLease(peer.id, {
    monotonicClock: fence.sequenceId,
    strictTimeoutMs: 120,
  });

  if (!lease.isValid) {
    throw new CryptographicFault("Untrusted state vector attestation");
  }

  return {
    verified: true,
    ringBufferOffset: lease.offset,
    syncedAt: Date.now(),
  };
}`;

export default function CruxAgentCursor({
  onMerge,
  isSplitPane = true,
}: CruxAgentCursorProps) {
  const [typedChars, setTypedChars] = useState(48);
  const [isPaused, setIsPaused] = useState(false);
  const [hasMerged, setHasMerged] = useState(false);

  // Token/character streaming loop
  useEffect(() => {
    if (isPaused || hasMerged) return;

    const interval = setInterval(() => {
      setTypedChars((prev) => {
        if (prev >= STREAM_SNIPPET.length) {
          setTimeout(() => setTypedChars(35), 2400);
          return prev;
        }
        const chunk = Math.floor(Math.random() * 4) + 2;
        return Math.min(prev + chunk, STREAM_SNIPPET.length);
      });
    }, 60);

    return () => clearInterval(interval);
  }, [isPaused, hasMerged]);

  const displayedText = STREAM_SNIPPET.slice(0, typedChars);
  const lines = displayedText.split("\n");

  const handleMerge = () => {
    setHasMerged(true);
    if (onMerge) onMerge();
  };

  const handleReset = () => {
    setHasMerged(false);
    setTypedChars(35);
  };

  return (
    <div className="w-full h-full flex flex-col bg-black font-mono text-xs select-text">
      {/* Header Bar of AI Co-Pilot Split-Screen Block */}
      <div className="h-8 px-3 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A] select-none shrink-0">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-1.5 py-0.5 rounded-none bg-black border border-[#222222] text-[#FF453A]">
            <Bot className="w-3 h-3 text-[#FF453A]" />
            <span className="font-semibold text-xs text-[#FF453A]">@CruxAI</span>
          </div>

          <span className="text-[#222222]">/</span>
          <span className="text-white text-xs font-mono">speculative_attestation.ts</span>

          <span className="hidden sm:inline-block px-1.5 py-0.5 rounded-none bg-black border border-[#222222] text-[#888888] text-[10px] font-mono">
            128 tok/s · Metal Accel
          </span>
        </div>

        {/* Right Actions */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setIsPaused(!isPaused)}
            title={isPaused ? "Resume Generation" : "Pause Generation"}
            className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] transition-colors"
          >
            {isPaused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
          </button>

          {hasMerged ? (
            <button
              onClick={handleReset}
              className="flex items-center gap-1 px-2.5 py-0.5 rounded-none bg-black text-[#888888] hover:text-white border border-[#222222] text-xs transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          ) : (
            <button
              onClick={handleMerge}
              className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-none bg-white text-black hover:bg-[#cccccc] text-xs font-semibold transition-colors"
            >
              <Check className="w-3.5 h-3.5" />
              <span>Accept Stream</span>
            </button>
          )}
        </div>
      </div>

      {/* Code Editor Body of Split-Screen Block */}
      <div className="flex-1 overflow-y-auto p-3 bg-black leading-[1.7]">
        {lines.map((line, idx) => {
          const isLastLine = idx === lines.length - 1;
          return (
            <div key={idx} className="flex items-baseline group hover:bg-[#0A0A0A] rounded-none px-1">
              {/* Gutter Line Number */}
              <span className="w-8 text-right pr-3 select-none text-[#888888] text-xs font-mono">
                {idx + 1}
              </span>

              {/* Code Line with Sharp Caret on active typing point */}
              <div className="flex-1 text-white whitespace-pre font-mono text-[12px]">
                {formatCodeLine(line)}
                {isLastLine && !hasMerged && (
                  <span className="inline-block w-1.5 h-4 bg-[#FF453A] ml-0.5 align-middle" />
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Bottom Status Rule of the AI Block */}
      <div className="h-6 px-3 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[10px] text-[#888888] select-none shrink-0 font-mono">
        <div className="flex items-center gap-1.5 text-[#888888]">
          <Sparkles className="w-3 h-3 text-[#FF453A]" />
          <span>Generating speculative fork</span>
        </div>
        <span>Tab ⇥ to complete</span>
      </div>
    </div>
  );
}

function formatCodeLine(line: string) {
  if (line.trim().startsWith("//") || line.trim().startsWith("/*") || line.trim().startsWith("*")) {
    return <span className="text-[#888888] italic">{line}</span>;
  }

  const parts = line.split(
    /(\bexport\b|\basync\b|\bfunction\b|\bconst\b|\bawait\b|\breturn\b|\bif\b|\bthrow\b|\bnew\b|\bPromise\b|\bboolean\b|\bstring\b)/g
  );

  return (
    <span>
      {parts.map((part, i) => {
        if (
          ["export", "async", "function", "const", "await", "return", "if", "throw", "new"].includes(
            part
          )
        ) {
          return (
            <span key={i} className="text-[#007AFF] font-medium">
              {part}
            </span>
          );
        }
        if (["Promise", "boolean", "string", "AttestationResult", "MeshPeer", "MemoryFence"].includes(part)) {
          return (
            <span key={i} className="text-white font-medium">
              {part}
            </span>
          );
        }
        if (part.includes('"') || part.includes("'")) {
          return (
            <span key={i} className="text-[#cccccc]">
              {part}
            </span>
          );
        }
        return <span key={i}>{part}</span>;
      })}
    </span>
  );
}
