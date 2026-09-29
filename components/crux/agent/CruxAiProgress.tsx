"use client";

import { ThinkingOrb } from "thinking-orbs";
import type { AgentStep } from "@/lib/agentEngine";

interface CruxAiProgressProps {
  steps: AgentStep[];
  layout: "float" | "dock";
  provider?: string;
}

export default function CruxAiProgress({ steps, provider }: CruxAiProgressProps) {
  const status = steps.some((step) => step.status === "running")
    ? "Processing Task"
    : steps.length > 0
      ? "Finishing"
      : provider
        ? "Running AI"
        : "Starting Task";

  return (
    <div
      className="min-w-0 flex-1 border border-[#222222] bg-[#111111] px-2 py-2 font-mono"
      role="status"
      aria-live="polite"
      aria-label={status}
    >
      <div className="flex items-center gap-2 text-white">
        <ThinkingOrb state="composing" size={20} theme="dark" aria-hidden="true" />
        <span className="text-[11px] uppercase tracking-wider">{status}</span>
      </div>
    </div>
  );
}
