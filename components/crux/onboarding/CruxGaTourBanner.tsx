"use client";

import React, { useState, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { triggerHaptic } from "@/lib/haptics";
import {
  Terminal,
  Layers,
  FileCode,
  Share2,
  Search,
  X,
  Check,
  ChevronRight,
  ExternalLink,
} from "lucide-react";

export default function CruxGaTourBanner() {
  const [isVisible, setIsVisible] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const setMode = useWorkspaceStore((state) => state.setMode);
  const setCommandPaletteOpen = useWorkspaceStore((state) => state.setCommandPaletteOpen);
  const setShareModalOpen = useWorkspaceStore((state) => state.setShareModalOpen);
  const toggleTerminal = useWorkspaceStore((state) => state.toggleTerminal);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const dismissed = localStorage.getItem("crux_ga_tour_dismissed");
      if (!dismissed) {
        setIsVisible(true);
      }
    }
  }, []);

  const handleDismiss = () => {
    triggerHaptic("tap");
    setIsVisible(false);
    if (typeof window !== "undefined") {
      localStorage.setItem("crux_ga_tour_dismissed", "true");
    }
  };

  const steps = [
    {
      code: "OMNIBAR // ⌘P",
      title: "Omnibar & Command Kernel",
      desc: "Instant fuzzy file navigation, model runtime switches, and system diagnostics.",
      action: () => setCommandPaletteOpen(true),
      actionLabel: "EXECUTE ⌘P",
      icon: <Search className="w-3.5 h-3.5 text-white" />,
    },
    {
      code: "CANVAS // ⌘1",
      title: "Spatial Vector Canvas",
      desc: "Interactive 120Hz node topology map. Visualize file relations, WAL pipelines, and telemetry.",
      action: () => setMode("canvas"),
      actionLabel: "SWITCH TO CANVAS",
      icon: <Layers className="w-3.5 h-3.5 text-white" />,
    },
    {
      code: "EDITOR // ⌘2",
      title: "Collaborative CRDT Editor",
      desc: "Bare-metal CodeMirror with real-time vector clocks and live peer cursor tracking.",
      action: () => setMode("edit"),
      actionLabel: "SWITCH TO EDITOR",
      icon: <FileCode className="w-3.5 h-3.5 text-white" />,
    },
    {
      code: "TERMINAL // ^`",
      title: "HyperTerminal Subshell",
      desc: "Live local-first daemon runner with memory-mapped ring buffers and stdout streaming.",
      action: () => toggleTerminal(),
      actionLabel: "TOGGLE TERMINAL",
      icon: <Terminal className="w-3.5 h-3.5 text-white" />,
    },
    {
      code: "PEER MESH // SHARE",
      title: "Zero-Knowledge Collab",
      desc: "Share your room URL. Remote operators join instantly over WebRTC with no account needed.",
      action: () => setShareModalOpen(true),
      actionLabel: "OPEN SHARE ENCLAVE",
      icon: <Share2 className="w-3.5 h-3.5 text-white" />,
    },
  ];

  if (!isVisible) return null;

  const current = steps[activeStep];

  return (
    <div className="fixed bottom-9 right-4 z-40 w-[420px] max-w-[calc(100vw-32px)] border border-[#222222] bg-[#000000] text-white font-sans select-none animate-in fade-in slide-in-from-bottom-2 duration-150">
      {/* Top Header Strip */}
      <div className="h-8 px-3 bg-[#111111] border-b border-[#222222] flex items-center justify-between font-mono text-[10px]">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 bg-white animate-hard-blink" />
          <span className="text-white font-bold tracking-wider uppercase">CRUX GA v1.0.0</span>
          <span className="text-[#444444]">|</span>
          <span className="text-[#888888]">HARDWARE KERNEL READY</span>
        </div>
        <button
          onClick={handleDismiss}
          className="text-[#888888] hover:text-white p-0.5 transition-none"
          title="Dismiss Welcome Tour"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Main Feature Body */}
      <div className="p-3.5 space-y-3 bg-[#000000]">
        <div className="flex items-start gap-3">
          <div className="w-7 h-7 shrink-0 border border-[#222222] bg-[#0A0A0A] flex items-center justify-center">
            {current.icon}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-mono text-[#888888] uppercase tracking-widest">
                STEP {activeStep + 1} OF {steps.length} // {current.code}
              </span>
            </div>
            <h4 className="text-xs font-bold uppercase tracking-wide text-white mt-0.5">
              {current.title}
            </h4>
            <p className="text-[11px] text-[#888888] leading-relaxed mt-1 font-mono">
              {current.desc}
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="pt-2 border-t border-[#181818] flex items-center justify-between font-mono text-[10px]">
          <div className="flex items-center gap-1.5">
            {steps.map((_, idx) => (
              <button
                key={idx}
                onClick={() => {
                  triggerHaptic("tap");
                  setActiveStep(idx);
                }}
                className={`w-2 h-2 transition-none ${
                  idx === activeStep ? "bg-white" : "bg-[#222222] hover:bg-[#444444]"
                }`}
                title={`Step ${idx + 1}`}
              />
            ))}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                triggerHaptic("click");
                current.action();
              }}
              className="px-2.5 py-1 border border-[#222222] text-[#CCCCCC] hover:text-black hover:bg-white hover:border-white transition-none uppercase tracking-wider text-[9px] font-bold"
            >
              {current.actionLabel}
            </button>
            {activeStep < steps.length - 1 ? (
              <button
                onClick={() => {
                  triggerHaptic("tap");
                  setActiveStep((prev) => prev + 1);
                }}
                className="px-2.5 py-1 bg-white text-black hover:bg-[#CCCCCC] transition-none uppercase tracking-wider text-[9px] font-bold flex items-center gap-1"
              >
                <span>NEXT</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            ) : (
              <button
                onClick={handleDismiss}
                className="px-2.5 py-1 bg-white text-black hover:bg-[#CCCCCC] transition-none uppercase tracking-wider text-[9px] font-bold flex items-center gap-1"
              >
                <span>FINISH</span>
                <Check className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
