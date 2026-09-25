"use client";

import React, { useState, useRef } from "react";
import { motion, AnimatePresence, useScroll, useSpring, useTransform, useMotionValueEvent } from "framer-motion";
import { Copy, Check, Terminal, Zap, GitMerge, Bot, Activity, Cpu } from "lucide-react";
import Link from "next/link";

export default function AeyeInstallationSection() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState<"multiplayer" | "silicon" | "crdt" | "agent">("multiplayer");
  const [copied, setCopied] = useState(false);
  const isManualClickRef = useRef(false);
  const manualTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Smooth scroll interpolation using spring physics for butter-smooth response
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end end"],
  });

  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 140,
    damping: 26,
    mass: 0.2,
  });

  // Continuous vertical rail fill height (0% to 100%)
  const verticalRailHeight = useTransform(smoothProgress, [0.06, 0.94], ["0%", "100%"]);

  // Update activeTab ONLY when thresholding across sections (prevents re-render lag)
  useMotionValueEvent(smoothProgress, "change", (latest) => {
    if (isManualClickRef.current) return;
    if (latest < 0.25) {
      setActiveTab((prev) => (prev !== "multiplayer" ? "multiplayer" : prev));
    } else if (latest < 0.50) {
      setActiveTab((prev) => (prev !== "silicon" ? "silicon" : prev));
    } else if (latest < 0.75) {
      setActiveTab((prev) => (prev !== "crdt" ? "crdt" : prev));
    } else {
      setActiveTab((prev) => (prev !== "agent" ? "agent" : prev));
    }
  });

  const tabs = [
    {
      id: "multiplayer" as const,
      serial: "// 001",
      label: "Real-Time Collaborative Mesh",
      subtitle: "SUB-MILLISECOND PEER PRESENCE",
      desc: "Live multiplayer spatial presence with zero-latency peer cursor vectors, active selection tracking, and conflict-free concurrent editing across teams.",
      copyText: "Crux Collaborative Multiplayer Engine:\n- Active Peers: Tarika (0.4ms), Pavan (0.6ms)\n- Cursor Transport: Lock-Free WebRTC Mesh\n- Sync Protocol: CRDT Vector Ring Buffer (0-conflict)\n- Presence Precision: Sub-pixel cursor coordinates",
    },
    {
      id: "silicon" as const,
      serial: "// 002",
      label: "Native Silicon Runtime",
      subtitle: "SUB-15ms INPUT-TO-PHOTON",
      desc: "Direct Metal and WebGPU rasterization bypassing 200MB Chromium bloat. Keystrokes hit phosphor in 4.2ms vs 48.6ms in Electron.",
      copyText: "Crux vs Electron Benchmarks:\n- Input-to-Photon: 4.2ms vs 48.6ms (11.5x faster)\n- Idle Memory: 38 MB vs 680 MB (17.8x leaner)\n- Scroll Rate: 120 FPS vs 18 FPS (6.6x smoother)",
    },
    {
      id: "crdt" as const,
      serial: "// 003",
      label: "Decentralized AST-CRDT",
      subtitle: "STRUCTURAL SYNTAX CONVERGENCE",
      desc: "Deterministic sub-10ms peer synchronization over encrypted P2P WebRTC channels with zero line collisions or syntax breakage.",
      copyText: "AST-CRDT Replication Protocol:\n- Topology: P2P Encrypted WebRTC Mesh\n- Convergence: Sub-10ms Deterministic State\n- Conflict Resolution: Abstract Syntax Tree token transforms",
    },
    {
      id: "agent" as const,
      serial: "// 004",
      label: "Autonomous @CruxAI Agents",
      subtitle: "ISOLATED POSIX OS NAMESPACE",
      desc: "Background compiler passes, multi-file refactors, and atomic git diffs execute directly on host silicon with zero cloud latency.",
      copyText: "@CruxAI Execution Specs:\n- Sandbox: Local POSIX OS Namespace\n- Cloud Latency: 0ms (Local Inference / Direct Hardware)\n- Verification: Real-time Cargo & Clang compiler checks",
    },
  ];

  const activeIndex = tabs.findIndex((t) => t.id === activeTab);
  const currentTab = tabs[activeIndex] || tabs[0];

  const handleStepClick = (idx: number) => {
    const selected = tabs[idx];
    if (!selected) return;
    setActiveTab(selected.id);

    if (containerRef.current && typeof window !== "undefined") {
      if (window.innerWidth >= 1024) {
        isManualClickRef.current = true;
        if (manualTimeoutRef.current) clearTimeout(manualTimeoutRef.current);
        manualTimeoutRef.current = setTimeout(() => {
          isManualClickRef.current = false;
        }, 750);

        const rect = containerRef.current.getBoundingClientRect();
        const scrollTop = window.scrollY || document.documentElement.scrollTop;
        const containerTop = rect.top + scrollTop;
        const scrollableDistance = containerRef.current.offsetHeight - window.innerHeight;

        if (scrollableDistance > 0) {
          const targets = [0.05, 0.32, 0.62, 0.92];
          window.scrollTo({
            top: containerTop + targets[idx] * scrollableDistance,
            behavior: "smooth",
          });
        }
      }
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(currentTab.copyText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="why-crux" className="relative w-full border-b border-[#222222] bg-[#000000]">
      {/* Anchor for backwards compatibility */}
      <div id="installation" className="absolute -top-20" />

      {/* Scroll-driven Sticky Container matching Feature & How-It-Works sections */}
      <div ref={containerRef} className="relative lg:h-[260vh]">
        <div className="relative lg:sticky lg:top-0 lg:h-screen lg:flex lg:flex-col lg:justify-center overflow-visible lg:overflow-hidden py-12 lg:py-0">
          <div className="max-w-[1280px] w-full mx-auto px-6">
            {/* Section Header Meta with Live Step Tracking */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#222222] text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="text-[#0055FF] font-bold">[N.05/11]</span>
                <span className="text-[#888888]">— &gt;</span>
                <span className="text-[#888888] uppercase">WHY CRUX?</span>
              </div>
              <div className="flex items-center gap-3 pt-2 sm:pt-0">
                <span className="text-[10px] text-[#71717a] uppercase tracking-wider hidden sm:inline font-mono">
                  THE BARE-METAL ADVANTAGE
                </span>
                <div className="flex items-center gap-1.5">
                  {tabs.map((tab, idx) => (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => handleStepClick(idx)}
                      className={`h-1.5 transition-none rounded-none ${
                        activeTab === tab.id ? "w-7 bg-[#0055FF]" : "w-2.5 bg-[#222222] hover:bg-[#444444]"
                      }`}
                      aria-label={`Jump to ${tab.label}`}
                    />
                  ))}
                </div>
                <span className="text-xs font-mono text-[#0055FF] font-bold">
                  [ 0{activeIndex + 1} / 04 ]
                </span>
              </div>
            </div>

            {/* 2-Column Section Layout */}
            <div className="pt-8 sm:pt-10 grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 xl:gap-16 items-center">
              {/* Left Column: Fixed-Height Interactive Engineering Display (Zero Height Jumping) */}
              <div className="lg:col-span-7">
                <div className="relative p-5 sm:p-6 border border-[#222222] bg-[#050507]">
                  {/* Corner Double-Dot Accents */}
                  <div className="absolute top-2 left-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>
                  <div className="absolute top-2 right-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>
                  <div className="absolute bottom-2 left-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>
                  <div className="absolute bottom-2 right-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>

                  {/* Rock-solid Fixed-Size Box (h-[390px]) - NEVER resizes between tabs */}
                  <div className="border border-[#222222] bg-[#0a0a0c] rounded-none overflow-hidden h-[390px] flex flex-col justify-between">
                    {/* Header bar */}
                    <div className="h-10 px-4 bg-[#111114] border-b border-[#222222] flex items-center justify-between shrink-0">
                      <div className="flex items-center gap-2.5">
                        <span className="w-2 h-2 bg-[#0055FF] inline-block" />
                        <span className="font-mono text-xs font-semibold text-white uppercase tracking-wider">
                          CRUX // {currentTab.subtitle}
                        </span>
                      </div>
                      <button
                        onClick={handleCopy}
                        className="flex items-center gap-1.5 font-mono text-xs text-[#888888] hover:text-white transition-none px-2 py-1 border border-transparent hover:border-[#333333]"
                        aria-label="Copy data"
                      >
                        <span>{copied ? "Copied" : "Copy"}</span>
                        {copied ? (
                          <Check className="w-3.5 h-3.5 text-[#0055FF]" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>

                    {/* Dedicated Interface Body (Smooth Crossfade inside Fixed Frame) */}
                    <div className="flex-1 p-5 font-mono text-xs sm:text-[13px] leading-relaxed overflow-hidden relative">
                      <AnimatePresence mode="wait">
                        {/* TAB 1: Real-Time Collaborative Mesh (Tarika & Pavan Cursors) */}
                        {activeTab === "multiplayer" && (
                          <motion.div
                            key="tab-multiplayer"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ duration: 0.15 }}
                            className="h-full flex flex-col justify-between select-none relative"
                          >
                            {/* Live Presence Header */}
                            <div className="p-2 border border-[#222222] bg-[#0e0e12] flex items-center justify-between text-[11px] font-mono shrink-0">
                              <div className="flex items-center gap-2">
                                <span className="w-2 h-2 rounded-none bg-[#22c55e] animate-pulse" />
                                <span className="text-white font-bold tracking-wide">CRUX P2P MESH</span>
                                <span className="text-[#444444]">|</span>
                                <span className="text-[#06b6d4] font-medium flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-none bg-[#06b6d4]" />
                                  Tarika
                                </span>
                                <span className="text-[#f59e0b] font-medium flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-none bg-[#f59e0b]" />
                                  Pavan
                                </span>
                              </div>
                              <span className="text-[#0055FF] font-bold text-[10px] px-1.5 py-0.5 bg-[#0055FF]/10 border border-[#0055FF]/30 hidden sm:inline">
                                0-LATENCY
                              </span>
                            </div>

                            {/* Collaborative Workspace Buffer Viewport with Live Animated Cursors */}
                            <div className="relative flex-1 my-2 p-3 border border-[#222222] bg-[#070709] overflow-hidden flex flex-col justify-between font-mono text-[11.5px]">
                              {/* Background grid pattern */}
                              <div className="absolute inset-0 opacity-[0.03] bg-[linear-gradient(to_right,#ffffff_1px,transparent_1px),linear-gradient(to_bottom,#ffffff_1px,transparent_1px)] bg-[size:16px_16px] pointer-events-none" />

                              {/* Floating Animated Cursor 1: Tarika */}
                              <motion.div
                                className="absolute pointer-events-none z-30 flex items-start gap-1 select-none"
                                animate={{
                                  x: [24, 130, 210, 110, 45, 24],
                                  y: [24, 48, 92, 65, 32, 24],
                                }}
                                transition={{
                                  duration: 7.5,
                                  repeat: Infinity,
                                  ease: "easeInOut",
                                }}
                              >
                                <svg
                                  className="w-4 h-4 text-[#06b6d4] drop-shadow-[0_2px_4px_rgba(0,0,0,0.8)]"
                                  viewBox="0 0 16 16"
                                  fill="currentColor"
                                >
                                  <path d="M0 0L6 14L8.5 8.5L14 6L0 0Z" />
                                </svg>
                                <div className="px-1.5 py-0.5 bg-[#0a0a0c] border border-[#06b6d4] text-[9.5px] font-mono font-medium text-white flex items-center gap-1.5 shadow-[0_2px_8px_rgba(6,182,212,0.3)]">
                                  <span className="w-1.5 h-1.5 rounded-none bg-[#06b6d4]" />
                                  <span>Tarika</span>
                                </div>
                              </motion.div>

                              {/* Floating Animated Cursor 2: Pavan */}
                              <motion.div
                                className="absolute pointer-events-none z-30 flex items-start gap-1 select-none"
                                animate={{
                                  x: [190, 260, 180, 240, 210, 190],
                                  y: [80, 125, 145, 62, 105, 80],
                                }}
                                transition={{
                                  duration: 8.5,
                                  repeat: Infinity,
                                  ease: "easeInOut",
                                  delay: 0.4,
                                }}
                              >
                                <svg
                                  className="w-4 h-4 text-[#f59e0b] drop-shadow-[0_2px_4px_rgba(0,0,0,0.8)]"
                                  viewBox="0 0 16 16"
                                  fill="currentColor"
                                >
                                  <path d="M0 0L6 14L8.5 8.5L14 6L0 0Z" />
                                </svg>
                                <div className="px-1.5 py-0.5 bg-[#0a0a0c] border border-[#f59e0b] text-[9.5px] font-mono font-medium text-white flex items-center gap-1.5 shadow-[0_2px_8px_rgba(245,158,11,0.3)]">
                                  <span className="w-1.5 h-1.5 rounded-none bg-[#f59e0b]" />
                                  <span>Pavan</span>
                                </div>
                              </motion.div>

                              {/* Code / Canvas Content Lines with active multi-selection highlights */}
                              <div className="space-y-1.5 relative z-10">
                                <div className="flex items-center gap-2 text-[#555555]">
                                  <span className="w-5 text-right text-[10px]">01</span>
                                  <span className="text-[#888888]">// Shared CRDT Ring Buffer · Zero Locks</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <span className="w-5 text-right text-[10px] text-[#555555]">02</span>
                                  <span className="text-[#0055FF]">export async function</span>
                                  <span className="text-white font-semibold">streamReplication</span>
                                  <span className="text-[#71717a]">(ctx: CRDTRing) &#123;</span>
                                </div>
                                {/* Line 03: Tarika's selection */}
                                <div className="flex items-center gap-2 relative bg-[#06b6d4]/10 border-l-2 border-[#06b6d4] pl-1">
                                  <span className="w-5 text-right text-[10px] text-[#06b6d4]">03</span>
                                  <span className="text-[#a1a1aa] pl-3">const buffer = await ctx.acquireShm(16 * 1024);</span>
                                  <span className="ml-auto text-[9px] text-[#06b6d4] font-mono font-semibold pr-1 hidden sm:inline">Tarika selecting</span>
                                </div>
                                {/* Line 04: Pavan's active edit */}
                                <div className="flex items-center gap-2 relative bg-[#f59e0b]/10 border-l-2 border-[#f59e0b] pl-1">
                                  <span className="w-5 text-right text-[10px] text-[#f59e0b]">04</span>
                                  <span className="text-[#a1a1aa] pl-3">return buffer.broadcastMultiplayer([&quot;Tarika&quot;, &quot;Pavan&quot;]);</span>
                                  <span className="ml-auto text-[9px] text-[#f59e0b] font-mono font-semibold pr-1 hidden sm:inline">Pavan editing</span>
                                </div>
                                <div className="flex items-center gap-2 text-[#71717a]">
                                  <span className="w-5 text-right text-[10px] text-[#555555]">05</span>
                                  <span>&#125;</span>
                                </div>
                              </div>

                              {/* Real-time telemetry indicators */}
                              <div className="grid grid-cols-3 gap-2 pt-2 border-t border-[#1a1a20] relative z-10">
                                <div className="p-1.5 border border-[#222222] bg-[#0c0c10] text-[10px]">
                                  <span className="text-[#71717a] block">TARIKA JITTER</span>
                                  <span className="text-[#06b6d4] font-bold">0.4ms (Tokyo)</span>
                                </div>
                                <div className="p-1.5 border border-[#222222] bg-[#0c0c10] text-[10px]">
                                  <span className="text-[#71717a] block">PAVAN JITTER</span>
                                  <span className="text-[#f59e0b] font-bold">0.6ms (SF)</span>
                                </div>
                                <div className="p-1.5 border border-[#222222] bg-[#0c0c10] text-[10px]">
                                  <span className="text-[#71717a] block">SYNTAX STATE</span>
                                  <span className="text-[#22c55e] font-bold">100% Attested</span>
                                </div>
                              </div>
                            </div>

                            {/* Bottom Status bar */}
                            <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px] shrink-0">
                              <span className="text-[#888888]">
                                PEER REPLICATION: <strong className="text-white">0 CONFLICTS</strong>
                              </span>
                              <span className="text-[#888888]">
                                PRECISION: <strong className="text-[#0055FF]">SUB-PIXEL PRESENCE</strong>
                              </span>
                            </div>
                          </motion.div>
                        )}

                        {/* TAB 2: Native Silicon Benchmarks */}
                        {activeTab === "silicon" && (
                          <motion.div
                            key="tab-silicon"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ duration: 0.15 }}
                            className="h-full flex flex-col justify-between"
                          >
                            <div className="space-y-4 text-left font-mono">
                              {/* Metric 1 */}
                              <div>
                                <div className="flex items-center justify-between text-xs mb-1">
                                  <span className="text-white font-medium">Input-to-Photon Latency</span>
                                  <span className="text-[#0055FF] font-bold">11.5x FASTER</span>
                                </div>
                                <div className="space-y-1">
                                  <div className="flex items-center gap-3">
                                    <span className="w-16 text-[10px] text-[#71717a]">CRUX</span>
                                    <div className="flex-1 h-3 bg-[#111114] border border-[#222222] relative overflow-hidden">
                                      <div className="h-full bg-[#0055FF] w-[14%]" />
                                    </div>
                                    <span className="w-14 text-right text-xs text-white font-bold">4.2ms</span>
                                  </div>
                                  <div className="flex items-center gap-3">
                                    <span className="w-16 text-[10px] text-[#555555]">ELECTRON</span>
                                    <div className="flex-1 h-3 bg-[#111114] border border-[#222222] relative overflow-hidden">
                                      <div className="h-full bg-[#333333] w-[95%]" />
                                    </div>
                                    <span className="w-14 text-right text-xs text-[#71717a]">48.6ms</span>
                                  </div>
                                </div>
                              </div>

                              {/* Metric 2 */}
                              <div>
                                <div className="flex items-center justify-between text-xs mb-1">
                                  <span className="text-white font-medium">Idle Memory Footprint</span>
                                  <span className="text-[#0055FF] font-bold">17.8x LEANER</span>
                                </div>
                                <div className="space-y-1">
                                  <div className="flex items-center gap-3">
                                    <span className="w-16 text-[10px] text-[#71717a]">CRUX</span>
                                    <div className="flex-1 h-3 bg-[#111114] border border-[#222222] relative overflow-hidden">
                                      <div className="h-full bg-[#0055FF] w-[10%]" />
                                    </div>
                                    <span className="w-14 text-right text-xs text-white font-bold">38 MB</span>
                                  </div>
                                  <div className="flex items-center gap-3">
                                    <span className="w-16 text-[10px] text-[#555555]">ELECTRON</span>
                                    <div className="flex-1 h-3 bg-[#111114] border border-[#222222] relative overflow-hidden">
                                      <div className="h-full bg-[#333333] w-[90%]" />
                                    </div>
                                    <span className="w-14 text-right text-xs text-[#71717a]">680 MB</span>
                                  </div>
                                </div>
                              </div>

                              {/* Metric 3 */}
                              <div>
                                <div className="flex items-center justify-between text-xs mb-1">
                                  <span className="text-white font-medium">250,000-Line Monorepo Scroll</span>
                                  <span className="text-[#0055FF] font-bold">6.6x SMOOTHER</span>
                                </div>
                                <div className="space-y-1">
                                  <div className="flex items-center gap-3">
                                    <span className="w-16 text-[10px] text-[#71717a]">CRUX</span>
                                    <div className="flex-1 h-3 bg-[#111114] border border-[#222222] relative overflow-hidden">
                                      <div className="h-full bg-[#0055FF] w-[100%]" />
                                    </div>
                                    <span className="w-14 text-right text-xs text-white font-bold">120 FPS</span>
                                  </div>
                                  <div className="flex items-center gap-3">
                                    <span className="w-16 text-[10px] text-[#555555]">ELECTRON</span>
                                    <div className="flex-1 h-3 bg-[#111114] border border-[#222222] relative overflow-hidden">
                                      <div className="h-full bg-[#333333] w-[22%]" />
                                    </div>
                                    <span className="w-14 text-right text-xs text-[#71717a]">18 FPS</span>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}

                        {/* TAB 2: Decentralized AST-CRDT Sync */}
                        {activeTab === "crdt" && (
                          <motion.div
                            key="tab-crdt"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ duration: 0.15 }}
                            className="h-full flex flex-col justify-between select-none"
                          >
                            <div className="space-y-2.5 font-mono text-xs sm:text-[12px]">
                              <div className="p-2 border border-[#222222] bg-[#0e0e12] flex items-center justify-between">
                                <span className="text-white font-bold">P2P WEBRTC MESH</span>
                                <span className="text-[#0055FF] font-bold text-[10px] px-1.5 py-0.5 bg-[#0055FF]/10 border border-[#0055FF]/30">LIVE CHANNEL</span>
                              </div>

                              <div className="space-y-1.5 pt-1 text-[11px]">
                                <div className="flex items-center gap-2 text-[#71717a]">
                                  <span className="text-[#555555]">[09:54:12.018]</span>
                                  <span className="text-white font-semibold">peer://tokyo-node</span>
                                  <span className="text-[#0055FF]">&gt;</span>
                                  <span className="text-[#a1a1aa]">inserts ASTNode::FnDecl("handle_stream")</span>
                                </div>
                                <div className="flex items-center gap-2 text-[#71717a]">
                                  <span className="text-[#555555]">[09:54:12.022]</span>
                                  <span className="text-white font-semibold">peer://sf-node</span>
                                  <span className="text-[#0055FF]">&gt;</span>
                                  <span className="text-[#a1a1aa]">edits ASTNode::Ident("stream_handler")</span>
                                </div>
                                <div className="flex items-center gap-2 text-[#71717a]">
                                  <span className="text-[#555555]">[09:54:12.025]</span>
                                  <span className="text-[#0055FF] font-bold">engine</span>
                                  <span className="text-[#0055FF]">&gt;</span>
                                  <span className="text-white">Applied structural AST delta · 0 syntax collisions</span>
                                </div>
                                <div className="flex items-center gap-2 text-[#71717a]">
                                  <span className="text-[#555555]">[09:54:12.028]</span>
                                  <span className="text-[#0055FF] font-bold">crypto</span>
                                  <span className="text-[#0055FF]">&gt;</span>
                                  <span className="text-[#a1a1aa]">SECP256K1 P2P channel handshake verified</span>
                                </div>
                                <div className="flex items-center gap-2 text-[#71717a]">
                                  <span className="text-[#555555]">[09:54:12.030]</span>
                                  <span className="text-white font-bold">status</span>
                                  <span className="text-[#0055FF]">&gt;</span>
                                  <span className="text-white">Vector clock [142, 89, 204] · Converged in 0.8ms</span>
                                </div>
                              </div>

                              <div className="pt-2 p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                                <span className="text-[#888888]">LINE-COLLISION RISK: <strong className="text-white">0.00%</strong></span>
                                <span className="text-[#888888]">SYNTAX TREE HEALTH: <strong className="text-[#0055FF]">100% VALID</strong></span>
                              </div>
                            </div>
                          </motion.div>
                        )}

                        {/* TAB 3: Autonomous @CruxAI Agents */}
                        {activeTab === "agent" && (
                          <motion.div
                            key="tab-agent"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ duration: 0.15 }}
                            className="h-full flex flex-col justify-between select-none"
                          >
                            <div className="space-y-2.5 font-mono text-xs sm:text-[12px]">
                              {/* Command line */}
                              <div>
                                <div className="flex items-center gap-2 text-[#71717a]">
                                  <span className="text-[#0055FF] font-bold">host@darwin</span>
                                  <span className="text-[#444444]">:</span>
                                  <span className="text-white">~/workspace</span>
                                  <span className="text-[#0055FF] font-bold">%</span>
                                  <span className="text-white font-medium">@CruxAI refactor ./src/parser.rs --optimize</span>
                                </div>
                              </div>

                              {/* Output steps */}
                              <div className="space-y-1.5 text-[11px] pl-2 border-l border-[#222222]">
                                <div className="text-[#888888]">
                                  <span className="text-[#0055FF]">[@CruxAI]</span> Ingested 14 source files in 1.4ms (zero cloud proxy)
                                </div>
                                <div className="text-[#888888]">
                                  <span className="text-[#0055FF]">[@CruxAI]</span> Applied SIMD token streaming pass (<span className="text-[#22c55e]">+48</span>, <span className="text-[#ef4444]">-12</span> lines)
                                </div>
                                <div className="text-[#888888]">
                                  <span className="text-[#0055FF]">[@CruxAI]</span> Running background compiler check:
                                </div>
                                <div className="pl-3 text-white">
                                  <span className="text-[#22c55e]">✓</span> cargo check --target=aarch64-apple-darwin: 0 warnings
                                </div>
                                <div className="text-[#888888]">
                                  <span className="text-[#0055FF]">[@CruxAI]</span> Generated atomic AST git commit: <code className="text-white">a9b42e1</code>
                                </div>
                              </div>

                              {/* Active Prompt with Blinking Hardware Cursor */}
                              <div className="pt-1 flex items-center gap-2 text-[#71717a]">
                                <span className="text-[#0055FF] font-bold">host@darwin</span>
                                <span className="text-[#444444]">:</span>
                                <span className="text-white">~/workspace</span>
                                <span className="text-[#0055FF] font-bold">%</span>
                                <motion.span
                                  animate={{ opacity: [1, 0, 1] }}
                                  transition={{ repeat: Infinity, duration: 0.9, ease: "linear" }}
                                  className="w-2 h-4 bg-white inline-block align-middle"
                                />
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>

                    {/* Bottom Console Footer */}
                    <div className="h-10 px-4 border-t border-[#222222] bg-[#0e0e12] flex items-center justify-between text-[11px] font-mono shrink-0">
                      <div className="flex items-center gap-2 text-[#71717a]">
                        <Terminal className="w-3.5 h-3.5 text-[#0055FF]" />
                        <span>
                          {activeTab === "multiplayer"
                            ? "MESH: P2P WEBRTC // TARIKA & PAVAN ACTIVE"
                            : activeTab === "silicon"
                            ? "RUNTIME: BARE-METAL POSIX / SILICON"
                            : activeTab === "crdt"
                            ? "PROTOCOL: ZERO-LOCK AST-CRDT SYNC"
                            : "KERNEL: @CRUXAI AUTONOMOUS AGENT"}
                        </span>
                      </div>
                      <span className="text-[#0055FF] font-bold">
                        {activeTab === "multiplayer" ? "SYNC: < 0.4ms" : "LATENCY: < 0.2ms"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Right Column: Title, Action Button, and Clean Continuous Vertical Rail */}
              <div className="lg:col-span-5 flex flex-col justify-between py-2">
                <div>
                  <h2 className="text-3xl sm:text-4xl lg:text-[44px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
                    Why Crux?
                    <span className="block text-[#888888]">Engineered for radical velocity.</span>
                  </h2>

                  <div className="mt-6 flex items-center gap-4">
                    <Link
                      href="#pricing"
                      className="inline-flex items-center gap-2.5 px-4 py-2.5 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none"
                    >
                      <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                      GET STARTED
                    </Link>
                    <div className="text-[11px] font-mono text-[#71717a] hidden sm:flex items-center gap-2">
                      <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                      <span>SCROLL TO ADVANCE // 0{activeIndex + 1} OF 04</span>
                    </div>
                  </div>
                </div>

                {/* Continuous Vertical Timeline Rail exactly as before with clean bounds */}
                <div className="mt-10 sm:mt-12 relative pl-8 select-none">
                  {/* Background Track Rail */}
                  <div className="absolute left-[8px] top-3 bottom-5 w-[2px] bg-[#1a1a1e]" />

                  {/* Continuous Smooth Electric Blue Fill */}
                  <div className="absolute left-[8px] top-3 bottom-5 w-[2px] overflow-hidden">
                    <motion.div
                      className="w-full bg-[#0055FF]"
                      style={{ height: verticalRailHeight }}
                    />
                  </div>

                  <div className="space-y-7 sm:space-y-8">
                    {tabs.map((tab, idx) => {
                      const isActive = activeTab === tab.id;

                      return (
                        <div
                          key={tab.id}
                          onClick={() => handleStepClick(idx)}
                          className="relative cursor-pointer group transition-none"
                        >
                          {/* Active Indicator Square Node sitting directly on the vertical line */}
                          <div
                            className={`absolute -left-[28px] top-1.5 w-2.5 h-2.5 transition-none z-10 ${
                              isActive
                                ? "bg-[#0055FF] border border-white shadow-[0_0_8px_#0055FF]"
                                : "bg-[#222222] border border-[#333333] group-hover:bg-[#444444]"
                            }`}
                          />

                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] font-mono font-semibold transition-none ${
                                isActive ? "text-[#0055FF]" : "text-[#555555]"
                              }`}
                            >
                              {tab.serial}
                            </span>
                            <h3
                              className={`text-lg sm:text-xl font-medium font-sans transition-none ${
                                isActive ? "text-[#0055FF] font-semibold" : "text-[#71717a] group-hover:text-white"
                              }`}
                            >
                              {tab.label}
                            </h3>
                          </div>

                          <p
                            className={`mt-1.5 text-xs sm:text-sm font-sans leading-relaxed transition-none ${
                              isActive ? "text-white" : "text-[#666666] group-hover:text-[#888888]"
                            }`}
                          >
                            {tab.desc}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
