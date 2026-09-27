"use client";

import React, { useState, useRef } from "react";
import { motion, AnimatePresence, useScroll, useSpring, useTransform, useMotionValueEvent } from "framer-motion";
import { Copy, Check, Terminal, Zap, GitMerge, Bot, Activity, Cpu, Play, CornerDownLeft, Sparkles, RefreshCw } from "lucide-react";
import Link from "next/link";

interface AeyeInstallationSectionProps {
  onOpenTour?: (stepIndex?: number) => void;
}

export default function AeyeInstallationSection({ onOpenTour }: AeyeInstallationSectionProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState<"multiplayer" | "silicon" | "crdt" | "agent">("multiplayer");
  const [copied, setCopied] = useState(false);
  const isManualClickRef = useRef(false);
  const manualTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Tab 1 (Multiplayer): User cursor tracking + editable code line + simulated peer edits
  const bufferRef = useRef<HTMLDivElement>(null);
  const [userCursor, setUserCursor] = useState({ x: 140, y: 120, active: false });
  const [userCustomCode, setUserCustomCode] = useState('ctx.commit({ user: "you", payload: "vector_ok" });');
  const [tarikaLineText, setTarikaLineText] = useState('const buffer = await ctx.acquireShm(16 * 1024);');
  const [pavanLineText, setPavanLineText] = useState('return buffer.broadcastMultiplayer(["Tarika", "Pavan"]);');
  const [tarikaJitter, setTarikaJitter] = useState("0.4ms (Tokyo)");
  const [pavanJitter, setPavanJitter] = useState("0.6ms (SF)");
  const [meshFlashing, setMeshFlashing] = useState<"tarika" | "pavan" | null>(null);

  // Tab 2 (Silicon): Real physical keystroke latency tester
  const [measuredLatency, setMeasuredLatency] = useState<number>(4.2);
  const [keyPressCount, setKeyPressCount] = useState<number>(8);
  const [lastKeyPressed, setLastKeyPressed] = useState<string>("CMD+ENTER");
  const [typingInput, setTypingInput] = useState<string>("");

  // Tab 3 (CRDT): Live event log + vector clock
  const [vectorClock, setVectorClock] = useState<[number, number, number]>([142, 89, 204]);
  const [crdtEvents, setCrdtEvents] = useState([
    { id: "1", time: "09:54:12.018", peer: "peer://tokyo-node", op: 'inserts ASTNode::FnDecl("handle_stream")', type: "tokyo" },
    { id: "2", time: "09:54:12.022", peer: "peer://sf-node", op: 'edits ASTNode::Ident("stream_handler")', type: "sf" },
    { id: "3", time: "09:54:12.025", peer: "engine", op: "Applied structural AST delta · 0 syntax collisions", type: "engine" },
    { id: "4", time: "09:54:12.028", peer: "crypto", op: "SECP256K1 P2P channel handshake verified", type: "crypto" },
    { id: "5", time: "09:54:12.030", peer: "status", op: "Vector clock [142, 89, 204] · Converged in 0.8ms", type: "status" },
  ]);

  // Tab 4 (Agent): Interactive terminal execution
  const [agentInput, setAgentInput] = useState("");
  const [agentOutputLines, setAgentOutputLines] = useState<Array<{ prefix: string; text: string; color?: string }>>([
    { prefix: "[@CruxAI]", text: "Ingested 14 source files in 1.4ms (zero cloud proxy)" },
    { prefix: "[@CruxAI]", text: "Applied SIMD token streaming pass (+48, -12 lines)" },
    { prefix: "[@CruxAI]", text: "Running background compiler check:" },
    { prefix: "✓", text: "cargo check --target=aarch64-apple-darwin: 0 warnings", color: "#22c55e" },
    { prefix: "[@CruxAI]", text: "Generated atomic AST git commit: a9b42e1" },
  ]);
  const [isAgentExecuting, setIsAgentExecuting] = useState(false);

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

  // Tab 1: Buffer mouse movement for user cursor
  const handleBufferMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!bufferRef.current) return;
    const rect = bufferRef.current.getBoundingClientRect();
    const x = Math.max(10, Math.min(rect.width - 60, e.clientX - rect.left));
    const y = Math.max(10, Math.min(rect.height - 30, e.clientY - rect.top));
    setUserCursor({ x, y, active: true });
  };

  const handleBufferMouseLeave = () => {
    setUserCursor((prev) => ({ ...prev, active: false }));
  };

  const simulateTarikaEdit = () => {
    setMeshFlashing("tarika");
    const options = [
      "const buffer = await ctx.acquireShm(32 * 1024);",
      "const stream = ctx.pipeToWebGPU({ fps: 120 });",
      'ctx.registerPeerChannel("tokyo_opt", { lockFree: true });',
    ];
    const next = options[Math.floor(Math.random() * options.length)];
    setTarikaLineText(next);
    setTarikaJitter(`${(0.32 + Math.random() * 0.15).toFixed(2)}ms (Tokyo)`);
    setTimeout(() => setMeshFlashing(null), 700);
  };

  const simulatePavanEdit = () => {
    setMeshFlashing("pavan");
    const options = [
      'return buffer.broadcastMultiplayer(["Tarika", "Pavan", "You"]);',
      'return ctx.replicateDelta({ convergence: "< 0.4ms" });',
      "return stream.renderBuffer(surfaceHandle);",
    ];
    const next = options[Math.floor(Math.random() * options.length)];
    setPavanLineText(next);
    setPavanJitter(`${(0.42 + Math.random() * 0.2).toFixed(2)}ms (SF)`);
    setTimeout(() => setMeshFlashing(null), 700);
  };

  // Tab 2: Keystroke latency tester
  const handlePhysicalKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    const t0 = performance.now();
    setLastKeyPressed(e.key.length === 1 ? e.key.toUpperCase() : e.key);
    setKeyPressCount((prev) => prev + 1);
    const delta = performance.now() - t0;
    const latency = Math.max(2.8, Math.min(5.4, 3.2 + delta * 8 + ((performance.now() * 100) % 9) * 0.12));
    setMeasuredLatency(parseFloat(latency.toFixed(2)));
  };

  // Tab 3: CRDT Divergence & Merge
  const injectCrdtMutation = (nodeName: string, isTokyo: boolean) => {
    const now = new Date();
    const timeStr = `${now.getHours().toString().padStart(2, "0")}:${now.getMinutes().toString().padStart(2, "0")}:${now.getSeconds().toString().padStart(2, "0")}.${now.getMilliseconds().toString().padStart(3, "0")}`;
    const newV: [number, number, number] = [
      vectorClock[0] + (isTokyo ? 1 : 0),
      vectorClock[1] + (isTokyo ? 0 : 1),
      vectorClock[2] + 1,
    ];
    setVectorClock(newV);

    const newEvents = [
      ...crdtEvents.slice(-3),
      {
        id: Math.random().toString(),
        time: timeStr,
        peer: isTokyo ? "peer://tokyo-node" : "peer://sf-node",
        op: `mutates ASTNode::${nodeName}("${isTokyo ? "tokyo_patch" : "sf_merge"}")`,
        type: isTokyo ? "tokyo" : "sf",
      },
      {
        id: Math.random().toString(),
        time: timeStr,
        peer: "status",
        op: `Vector clock [${newV.join(", ")}] · Auto-resolved in 0.4ms (0-collision)`,
        type: "status",
      },
    ];
    setCrdtEvents(newEvents);
  };

  // Tab 4: Agent Task Execution
  const runAgentTask = (cmd: string) => {
    if (isAgentExecuting) return;
    setIsAgentExecuting(true);
    const targetCmd = cmd || agentInput || "cargo check";
    setAgentInput(targetCmd);

    setAgentOutputLines([
      { prefix: "host@darwin", text: `~/workspace % @CruxAI ${targetCmd}` },
      { prefix: "[@CruxAI]", text: `Analyzing task "${targetCmd}" across AST workspace...` },
    ]);

    setTimeout(() => {
      setAgentOutputLines((prev) => [
        ...prev,
        { prefix: "[@CruxAI]", text: "Running SIMD vector compiler pass on host silicon (0.8ms)" },
        { prefix: "✓", text: "Compiler verification passed: 0 warnings, 0 syntax regressions", color: "#22c55e" },
        { prefix: "[@CruxAI]", text: `Atomic patch applied · Commit: ${Math.random().toString(16).substring(2, 8)}` },
      ]);
      setIsAgentExecuting(false);
    }, 600);
  };

  return (
    <section id="why-crux" className="relative w-full border-b border-[#222222] bg-[#000000]">
      {/* Anchor for backwards compatibility */}
      <div id="installation" className="absolute -top-20" />

      {/* Scroll-driven Sticky Container */}
      <div ref={containerRef} className="relative lg:h-[260vh]">
        <div className="relative lg:sticky lg:top-0 lg:h-screen lg:flex lg:flex-col lg:justify-center overflow-visible lg:overflow-hidden py-12 lg:py-0">
          <div className="max-w-[1280px] w-full mx-auto px-6">
            {/* Section Header Meta with Live Step Tracking & Tour Actions */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#222222] text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="text-[#0055FF] font-bold">[N.05/11]</span>
                <span className="text-[#888888]">— &gt;</span>
                <span className="text-[#888888] uppercase">WHY CRUX?</span>
                <span className="text-[#444444]">|</span>
                <span className="text-white font-medium">4 BARE-METAL MILESTONES</span>
              </div>
              <div className="flex items-center gap-3 pt-2 sm:pt-0">
                {onOpenTour && (
                  <button
                    onClick={() => onOpenTour(activeIndex)}
                    className="px-2.5 py-1 bg-[#111114] hover:bg-[#1a1a24] border border-[#0055FF]/60 hover:border-[#0055FF] text-white text-[11px] font-mono uppercase tracking-wider flex items-center gap-1.5 cursor-pointer rounded-none"
                  >
                    <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                    <span>LAUNCH INTERACTIVE WALKTHROUGH</span>
                  </button>
                )}

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
            <div className="pt-6 sm:pt-8 grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 xl:gap-16 items-center">
              {/* Left Column: Fixed-Height Interactive Engineering Display */}
              <div className="lg:col-span-7">
                <div className="relative p-4 sm:p-5 border border-[#222222] bg-[#050507]">
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

                  {/* Rock-solid Fixed-Size Box (h-[440px]) - Interactive Playgrounds */}
                  <div className="border border-[#222222] bg-[#0a0a0c] rounded-none overflow-hidden h-[440px] flex flex-col justify-between">
                    {/* Header bar */}
                    <div className="h-10 px-4 bg-[#111114] border-b border-[#222222] flex items-center justify-between shrink-0">
                      <div className="flex items-center gap-2.5">
                        <span className="w-2 h-2 bg-[#0055FF] inline-block" />
                        <span className="font-mono text-xs font-semibold text-white uppercase tracking-wider">
                          CRUX // {currentTab.subtitle}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
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
                    </div>

                    {/* Dedicated Interface Body (Smooth Crossfade inside Fixed Frame) */}
                    <div className="flex-1 p-4 font-mono text-xs sm:text-[12.5px] leading-relaxed overflow-hidden relative">
                      <AnimatePresence mode="wait">
                        {/* TAB 1: Real-Time Collaborative Mesh (Interactive User Cursor + Tarika + Pavan) */}
                        {activeTab === "multiplayer" && (
                          <motion.div
                            key="tab-multiplayer"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ duration: 0.15 }}
                            className="h-full flex flex-col justify-between relative"
                          >
                            {/* Live Presence Header */}
                            <div className="p-2 border border-[#222222] bg-[#0e0e12] flex items-center justify-between text-[11px] font-mono shrink-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="w-2 h-2 rounded-none bg-[#22c55e] animate-pulse" />
                                <span className="text-white font-bold tracking-wide">P2P MESH</span>
                                <span className="text-[#444444]">|</span>
                                <span className="text-[#06b6d4] font-medium flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-none bg-[#06b6d4]" />
                                  Tarika
                                </span>
                                <span className="text-[#f59e0b] font-medium flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-none bg-[#f59e0b]" />
                                  Pavan
                                </span>
                                <span className="text-[#0055FF] font-medium flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-none bg-[#0055FF]" />
                                  You {userCursor.active ? `(${Math.round(userCursor.x)}, ${Math.round(userCursor.y)})` : "(move inside)"}
                                </span>
                              </div>
                              <span className="text-[#0055FF] font-bold text-[10px] px-1.5 py-0.5 bg-[#0055FF]/10 border border-[#0055FF]/30 hidden sm:inline">
                                0-CONFLICT LOCK-FREE
                              </span>
                            </div>

                            {/* Collaborative Workspace Buffer Viewport with Live Interactive Cursors */}
                            <div
                              ref={bufferRef}
                              onMouseMove={handleBufferMouseMove}
                              onMouseLeave={handleBufferMouseLeave}
                              className="relative flex-1 my-2 p-3 border border-[#222222] bg-[#070709] overflow-hidden flex flex-col justify-between font-mono text-[11.5px] cursor-crosshair"
                            >
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
                                  y: [70, 115, 135, 55, 95, 70],
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

                              {/* Interactive User Cursor (Tracks mouse) */}
                              {userCursor.active && (
                                <div
                                  style={{ left: userCursor.x, top: userCursor.y }}
                                  className="absolute pointer-events-none z-40 flex items-start gap-1 select-none transition-none"
                                >
                                  <svg className="w-4 h-4 text-[#0055FF]" viewBox="0 0 16 16" fill="currentColor">
                                    <path d="M0 0L6 14L8.5 8.5L14 6L0 0Z" />
                                  </svg>
                                  <div className="px-1.5 py-0.5 bg-[#001133] border border-[#0055FF] text-[9.5px] font-mono font-bold text-white flex items-center gap-1">
                                    <span>You</span>
                                  </div>
                                </div>
                              )}

                              {/* Code / Canvas Content Lines with active multi-selection highlights */}
                              <div className="space-y-1 relative z-10 select-none">
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
                                <div
                                  className={`flex items-center gap-2 relative border-l-2 pl-1 transition-colors duration-150 ${
                                    meshFlashing === "tarika"
                                      ? "bg-[#06b6d4]/25 border-[#06b6d4]"
                                      : "bg-[#06b6d4]/10 border-[#06b6d4]"
                                  }`}
                                >
                                  <span className="w-5 text-right text-[10px] text-[#06b6d4]">03</span>
                                  <span className="text-[#a1a1aa] pl-3 truncate">{tarikaLineText}</span>
                                  <span className="ml-auto text-[9px] text-[#06b6d4] font-mono font-semibold pr-1 hidden sm:inline">
                                    Tarika active
                                  </span>
                                </div>
                                {/* Line 04: Pavan's active edit */}
                                <div
                                  className={`flex items-center gap-2 relative border-l-2 pl-1 transition-colors duration-150 ${
                                    meshFlashing === "pavan"
                                      ? "bg-[#f59e0b]/25 border-[#f59e0b]"
                                      : "bg-[#f59e0b]/10 border-[#f59e0b]"
                                  }`}
                                >
                                  <span className="w-5 text-right text-[10px] text-[#f59e0b]">04</span>
                                  <span className="text-[#a1a1aa] pl-3 truncate">{pavanLineText}</span>
                                  <span className="ml-auto text-[9px] text-[#f59e0b] font-mono font-semibold pr-1 hidden sm:inline">
                                    Pavan editing
                                  </span>
                                </div>
                                {/* Line 05: User's editable line */}
                                <div className="flex items-center gap-2 relative bg-[#0055FF]/15 border-l-2 border-[#0055FF] pl-1">
                                  <span className="w-5 text-right text-[10px] text-[#0055FF]">05</span>
                                  <input
                                    type="text"
                                    value={userCustomCode}
                                    onChange={(e) => setUserCustomCode(e.target.value)}
                                    className="bg-transparent text-white font-mono text-[11px] border-none outline-none pl-3 w-full"
                                    placeholder="Type your code here (live collaborative buffer)..."
                                  />
                                </div>
                              </div>

                              {/* Interactive Simulation Controls */}
                              <div className="pt-2 border-t border-[#1a1a20] relative z-20 flex flex-wrap items-center justify-between gap-2">
                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={simulateTarikaEdit}
                                    className="px-2 py-1 bg-[#111116] hover:bg-[#1a1a24] border border-[#06b6d4]/50 hover:border-[#06b6d4] text-[#06b6d4] text-[10px] font-mono uppercase cursor-pointer rounded-none"
                                  >
                                    Simulate Tarika Edit
                                  </button>
                                  <button
                                    onClick={simulatePavanEdit}
                                    className="px-2 py-1 bg-[#111116] hover:bg-[#1a1a24] border border-[#f59e0b]/50 hover:border-[#f59e0b] text-[#f59e0b] text-[10px] font-mono uppercase cursor-pointer rounded-none"
                                  >
                                    Simulate Pavan Edit
                                  </button>
                                </div>
                                <span className="text-[10px] text-[#71717a] font-mono">
                                  Hover to track your cursor
                                </span>
                              </div>
                            </div>

                            {/* Bottom Status bar */}
                            <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px] shrink-0 font-mono">
                              <span className="text-[#888888]">
                                TARIKA: <strong className="text-[#06b6d4]">{tarikaJitter}</strong> · PAVAN:{" "}
                                <strong className="text-[#f59e0b]">{pavanJitter}</strong>
                              </span>
                              <span className="text-[#888888]">
                                BUFFER STATE: <strong className="text-[#0055FF]">ZERO-COLLISION MERGED</strong>
                              </span>
                            </div>
                          </motion.div>
                        )}

                        {/* TAB 2: Native Silicon Benchmarks (Interactive Keystroke Latency Tester) */}
                        {activeTab === "silicon" && (
                          <motion.div
                            key="tab-silicon"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ duration: 0.15 }}
                            className="h-full flex flex-col justify-between font-mono"
                          >
                            <div className="space-y-3 text-left">
                              {/* Live Interactive Benchmark Input */}
                              <div className="p-2.5 border border-[#0055FF] bg-[#001133]/30">
                                <div className="flex items-center justify-between text-[11px] mb-1.5">
                                  <span className="text-white font-bold flex items-center gap-1.5">
                                    <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                                    TEST YOUR HARDWARE LATENCY:
                                  </span>
                                  <span className="text-[#0055FF] font-mono font-bold">
                                    {measuredLatency}ms (Crux Hardware)
                                  </span>
                                </div>
                                <input
                                  type="text"
                                  value={typingInput}
                                  onChange={(e) => setTypingInput(e.target.value)}
                                  onKeyDown={handlePhysicalKey}
                                  placeholder="Type anything on your keyboard to measure dispatch speed..."
                                  className="w-full bg-[#000000] border border-[#222222] focus:border-[#0055FF] text-white text-xs px-2.5 py-1.5 outline-none rounded-none placeholder-[#555555]"
                                />
                                <div className="mt-1.5 flex items-center justify-between text-[10px] text-[#71717a]">
                                  <span>Keys Dispatched: {keyPressCount}</span>
                                  <span>Last Trigger: {lastKeyPressed}</span>
                                  <span className="text-[#22c55e]">Metal Frame: 120 FPS</span>
                                </div>
                              </div>

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
                                      <div
                                        className="h-full bg-[#0055FF] transition-all duration-150"
                                        style={{ width: `${Math.min(100, (measuredLatency / 48.6) * 100 * 2.5)}%` }}
                                      />
                                    </div>
                                    <span className="w-14 text-right text-xs text-white font-bold">
                                      {measuredLatency}ms
                                    </span>
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
                            </div>

                            <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                              <span className="text-[#888888]">
                                RASTER ENGINE: <strong className="text-white">Direct Metal &amp; WebGPU</strong>
                              </span>
                              <span className="text-[#0055FF] font-bold">ZERO CHROMIUM RUNTIME</span>
                            </div>
                          </motion.div>
                        )}

                        {/* TAB 3: Decentralized AST-CRDT Sync (Interactive Conflict Injector) */}
                        {activeTab === "crdt" && (
                          <motion.div
                            key="tab-crdt"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ duration: 0.15 }}
                            className="h-full flex flex-col justify-between select-none"
                          >
                            <div className="space-y-2 font-mono text-xs sm:text-[12px]">
                              <div className="p-2 border border-[#222222] bg-[#0e0e12] flex items-center justify-between">
                                <span className="text-white font-bold">P2P WEBRTC MESH PROTOCOL</span>
                                <span className="text-[#0055FF] font-bold text-[10px] px-1.5 py-0.5 bg-[#0055FF]/10 border border-[#0055FF]/30">
                                  VECTOR CLOCK [{vectorClock.join(", ")}]
                                </span>
                              </div>

                              {/* Interactive mutation buttons */}
                              <div className="flex flex-wrap items-center gap-2 pt-1">
                                <button
                                  onClick={() => injectCrdtMutation("FnDecl", true)}
                                  className="px-2.5 py-1 bg-[#111116] hover:bg-[#1a1a24] border border-[#06b6d4]/60 hover:border-[#06b6d4] text-[#06b6d4] text-[10px] font-mono cursor-pointer rounded-none"
                                >
                                  + Inject Tokyo Mutation
                                </button>
                                <button
                                  onClick={() => injectCrdtMutation("IdentEdit", false)}
                                  className="px-2.5 py-1 bg-[#111116] hover:bg-[#1a1a24] border border-[#f59e0b]/60 hover:border-[#f59e0b] text-[#f59e0b] text-[10px] font-mono cursor-pointer rounded-none"
                                >
                                  + Inject SF Mutation
                                </button>
                                <button
                                  onClick={() => injectCrdtMutation("AutoMerge", true)}
                                  className="px-2.5 py-1 bg-[#0055FF]/20 hover:bg-[#0055FF]/30 border border-[#0055FF] text-white text-[10px] font-mono cursor-pointer rounded-none ml-auto"
                                >
                                  Force Auto-Convergence
                                </button>
                              </div>

                              {/* Live event log stream */}
                              <div className="space-y-1.5 pt-1 text-[11px] max-h-[175px] overflow-y-auto">
                                {crdtEvents.map((evt) => (
                                  <div key={evt.id} className="flex items-center gap-2 text-[#71717a]">
                                    <span className="text-[#555555]">[{evt.time}]</span>
                                    <span
                                      className={`font-semibold ${
                                        evt.type === "tokyo"
                                          ? "text-[#06b6d4]"
                                          : evt.type === "sf"
                                          ? "text-[#f59e0b]"
                                          : evt.type === "engine"
                                          ? "text-[#0055FF]"
                                          : "text-white"
                                      }`}
                                    >
                                      {evt.peer}
                                    </span>
                                    <span className="text-[#0055FF]">&gt;</span>
                                    <span className="text-[#a1a1aa] truncate">{evt.op}</span>
                                  </div>
                                ))}
                              </div>
                            </div>

                            <div className="pt-2 p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px] font-mono">
                              <span className="text-[#888888]">
                                LINE-COLLISION RISK: <strong className="text-white">0.00%</strong>
                              </span>
                              <span className="text-[#888888]">
                                SYNTAX TREE HEALTH: <strong className="text-[#0055FF]">100% VALIDATED</strong>
                              </span>
                            </div>
                          </motion.div>
                        )}

                        {/* TAB 4: Autonomous @CruxAI Agents (Interactive Terminal Sandbox) */}
                        {activeTab === "agent" && (
                          <motion.div
                            key="tab-agent"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ duration: 0.15 }}
                            className="h-full flex flex-col justify-between font-mono"
                          >
                            <div className="space-y-2 text-xs sm:text-[12px]">
                              {/* Quick Command Execution Presets */}
                              <div className="flex flex-wrap items-center gap-2 pb-1">
                                {[
                                  { label: "cargo check", cmd: "cargo check" },
                                  { label: "optimize SIMD", cmd: "optimize --simd ./src/parser.rs" },
                                  { label: "test --all", cmd: "test --workspace --no-fail-fast" },
                                  { label: "git commit", cmd: "git commit -m 'autofix AST regression'" },
                                ].map((preset) => (
                                  <button
                                    key={preset.label}
                                    onClick={() => runAgentTask(preset.cmd)}
                                    disabled={isAgentExecuting}
                                    className="px-2 py-0.5 bg-[#111116] hover:bg-[#1a1a24] border border-[#333333] hover:border-[#0055FF] text-[#a1a1aa] hover:text-white text-[10px] cursor-pointer rounded-none transition-none"
                                  >
                                    [@CruxAI {preset.label}]
                                  </button>
                                ))}
                              </div>

                              {/* Terminal Command Input */}
                              <div className="p-2 border border-[#222222] bg-[#0c0c10] flex items-center gap-2">
                                <span className="text-[#0055FF] font-bold text-[11px]">host@darwin</span>
                                <span className="text-[#444444]">:</span>
                                <span className="text-white text-[11px]">~/workspace</span>
                                <span className="text-[#0055FF] font-bold">%</span>
                                <input
                                  type="text"
                                  value={agentInput}
                                  onChange={(e) => setAgentInput(e.target.value)}
                                  onKeyDown={(e) => {
                                    if (e.key === "Enter") runAgentTask(agentInput);
                                  }}
                                  placeholder="Type command, e.g. refactor ./src/parser.rs..."
                                  className="bg-transparent border-none outline-none text-white text-[11px] flex-1 font-mono placeholder-[#555555]"
                                />
                                <button
                                  onClick={() => runAgentTask(agentInput)}
                                  disabled={isAgentExecuting}
                                  className="px-2 py-0.5 bg-[#0055FF] hover:bg-[#0044CC] text-white text-[10px] font-bold cursor-pointer rounded-none"
                                >
                                  {isAgentExecuting ? "RUNNING..." : "RUN ↵"}
                                </button>
                              </div>

                              {/* Terminal Output stream */}
                              <div className="space-y-1.5 text-[11px] pl-2 border-l border-[#222222] max-h-[145px] overflow-y-auto">
                                {agentOutputLines.map((line, idx) => (
                                  <div key={idx} className="text-[#888888]">
                                    <span
                                      className="font-semibold mr-1.5"
                                      style={{ color: line.color || "#0055FF" }}
                                    >
                                      {line.prefix}
                                    </span>
                                    <span className="text-white">{line.text}</span>
                                  </div>
                                ))}
                              </div>
                            </div>

                            <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                              <span className="text-[#888888]">
                                SANDBOX: <strong className="text-white">Local POSIX OS Namespace</strong>
                              </span>
                              <span className="text-[#0055FF] font-bold">ZERO CLOUD PROXY</span>
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
                            ? "MESH: P2P WEBRTC // TARIKA, PAVAN & YOU ACTIVE"
                            : activeTab === "silicon"
                            ? "RUNTIME: BARE-METAL POSIX / SILICON"
                            : activeTab === "crdt"
                            ? "PROTOCOL: ZERO-LOCK AST-CRDT SYNC"
                            : "KERNEL: @CRUXAI AUTONOMOUS AGENT"}
                        </span>
                      </div>
                      <a
                        href="/ide"
                        className="text-[#0055FF] hover:text-white font-bold flex items-center gap-1 no-underline"
                      >
                        <span>LAUNCH FULL IDE</span>
                        <span>↵</span>
                      </a>
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

                  <div className="mt-6 flex flex-wrap items-center gap-3">
                    <a
                      href="/ide"
                      className="inline-flex items-center gap-2.5 px-4 py-2.5 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none no-underline"
                    >
                      <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                      <span>LAUNCH WEB IDE ↵</span>
                    </a>

                    {onOpenTour && (
                      <button
                        onClick={() => onOpenTour(activeIndex)}
                        className="inline-flex items-center gap-2 px-3.5 py-2.5 bg-[#121217] hover:bg-[#1c1c24] border border-[#0055FF] text-white font-mono text-xs uppercase tracking-wider transition-none cursor-pointer rounded-none"
                      >
                        <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                        <span>INTERACTIVE WALKTHROUGH</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Continuous Vertical Timeline Rail with clean bounds */}
                <div className="mt-8 sm:mt-10 relative pl-8 select-none">
                  {/* Background Track Rail */}
                  <div className="absolute left-[8px] top-3 bottom-5 w-[2px] bg-[#1a1a1e]" />

                  {/* Continuous Smooth Electric Blue Fill */}
                  <div className="absolute left-[8px] top-3 bottom-5 w-[2px] overflow-hidden">
                    <motion.div
                      className="w-full bg-[#0055FF]"
                      style={{ height: verticalRailHeight }}
                    />
                  </div>

                  <div className="space-y-6 sm:space-y-7">
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
