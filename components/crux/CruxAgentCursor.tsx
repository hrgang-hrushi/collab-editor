"use client";

import React, { useEffect, useState } from "react";
import { Cpu, Check, Terminal, Play, Pause, RotateCcw } from "lucide-react";

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

  // Realistic token/character streaming loop
  useEffect(() => {
    if (isPaused || hasMerged) return;

    const interval = setInterval(() => {
      setTypedChars((prev) => {
        if (prev >= STREAM_SNIPPET.length) {
          // Pause briefly at completion then loop
          setTimeout(() => setTypedChars(35), 2400);
          return prev;
        }
        // Advance by 2-5 chars per tick to simulate 128 tok/s Metal inference
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
      {/* Header Bar of the AI Co-Pilot Split-Screen Block - Strict 1px borders, zero gradients */}
      <div className="h-8 px-3 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A] select-none shrink-0">
        <div className="flex items-center gap-2">
          {/* Flat Sharp Identity Pill */}
          <div className="flex items-center gap-1.5 px-1.5 py-0.5 bg-[#141516] border border-[#222222] text-[#f7f8f8]">
            <span className="w-1.5 h-1.5 bg-[#5e6ad2]" />
            <span className="font-semibold text-[11px] text-[#f7f8f8]">@CruxAI</span>
          </div>

          <span className="text-[#62666d]">/</span>
          <span className="text-[#8a8f98] text-[11px]">speculative_attestation.ts</span>

          {/* Telemetry pill */}
          <span className="hidden sm:inline-block px-1.5 py-0.5 bg-black border border-[#222222] text-[#62666d] text-[10px]">
            128 tok/s · Metal Accel
          </span>
        </div>

        {/* Right Actions */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setIsPaused(!isPaused)}
            title={isPaused ? "Resume Generation" : "Pause Generation"}
            className="p-1 bg-[#141516] hover:bg-[#191a1b] text-[#8a8f98] hover:text-[#f7f8f8] border border-[#222222] transition-colors"
          >
            {isPaused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
          </button>

          {hasMerged ? (
            <button
              onClick={handleReset}
              className="flex items-center gap-1 px-2 py-0.5 bg-[#141516] text-[#8a8f98] hover:text-[#f7f8f8] border border-[#222222] text-[10px]"
            >
              <RotateCcw className="w-2.5 h-2.5" />
              <span>Reset</span>
            </button>
          ) : (
            <button
              onClick={handleMerge}
              className="flex items-center gap-1 px-2 py-0.5 bg-[#5e6ad2] hover:bg-[#828fff] text-white border border-[#5e6ad2] text-[10px] font-medium transition-colors"
            >
              <Check className="w-3 h-3" />
              <span>Accept Stream</span>
            </button>
          )}
        </div>
      </div>

      {/* Code Editor Body of Split-Screen Block - Pure Black, Strict 1px Gutter */}
      <div className="flex-1 overflow-y-auto p-3 bg-black leading-[1.65]">
        {lines.map((line, idx) => {
          const isLastLine = idx === lines.length - 1;
          return (
            <div key={idx} className="flex items-baseline group hover:bg-[#0A0A0A]">
              {/* Gutter Line Number */}
              <span className="w-8 text-right pr-3 select-none text-[#62666d] text-[11px]">
                {idx + 1}
              </span>

              {/* Code Line with Sharp Blinking Cursor on active typing point */}
              <div className="flex-1 text-[#d0d6e0] whitespace-pre font-mono text-[12px]">
                {formatCodeLine(line)}
                {isLastLine && !hasMerged && (
                  /* Flat Sharp Caret - Zero drop shadow, zero blur, zero gradient */
                  <span className="inline-block w-2 h-3.5 bg-[#5e6ad2] ml-0.5 animate-pulse align-middle" />
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Bottom Status Rule of the AI Block */}
      <div className="h-6 px-3 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[10px] text-[#62666d] select-none shrink-0">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 bg-[#5e6ad2]" />
          <span>Generating speculative fork</span>
        </div>
        <span>Tab ⇥ to complete</span>
      </div>
    </div>
  );
}

// Minimal, flat syntax formatter using Linear typography rules
function formatCodeLine(line: string) {
  if (line.trim().startsWith("//") || line.trim().startsWith("/*") || line.trim().startsWith("*")) {
    return <span className="text-[#62666d] italic">{line}</span>;
  }

  // Basic regex token styling without neon colors
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
            <span key={i} className="text-[#5e6ad2] font-medium">
              {part}
            </span>
          );
        }
        if (["Promise", "boolean", "string", "AttestationResult", "MeshPeer", "MemoryFence"].includes(part)) {
          return (
            <span key={i} className="text-[#f7f8f8]">
              {part}
            </span>
          );
        }
        if (part.includes('"') || part.includes("'")) {
          return (
            <span key={i} className="text-[#27a644]">
              {part}
            </span>
          );
        }
        return <span key={i}>{part}</span>;
      })}
    </span>
  );
}
