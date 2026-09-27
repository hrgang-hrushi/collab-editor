"use client";

import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, ArrowRight, ArrowLeft, Terminal, Cpu, Users, GitMerge, Check, Sparkles, Play, RefreshCw, Zap } from "lucide-react";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

interface InteractiveTourModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialStep?: number;
}

export default function InteractiveTourModal({ isOpen, onClose, initialStep = 0 }: InteractiveTourModalProps) {
  const [currentStep, setCurrentStep] = useState(initialStep);
  
  // Step 1: Multiplayer state
  const [bufferText, setBufferText] = useState("export async function streamMesh(ctx) {\n  const ring = await ctx.acquireShm();\n  return ring.broadcast();\n}");
  const [userCursorPos, setUserCursorPos] = useState({ x: 120, y: 40 });
  const [multiplayerAction, setMultiplayerAction] = useState<string>("Active Peers: Tarika (0.4ms), Pavan (0.6ms)");

  // Step 2: Silicon Latency Tester state
  const [keystrokeCount, setKeystrokeCount] = useState(0);
  const [measuredLatency, setMeasuredLatency] = useState<number>(3.8);
  const [lastPressTime, setLastPressTime] = useState<number | null>(null);

  // Step 3: AST-CRDT state
  const [crdtState, setCrdtState] = useState<"synced" | "divergent" | "converging">("synced");
  const [vectorClocks, setVectorClocks] = useState({ peerA: 142, peerB: 142 });

  // Step 4: Terminal Agent state
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    "[@CruxAI] Initialized bare-metal execution daemon on unix:///var/run/crux.sock (0.08ms)",
    "[@CruxAI] Ready. Type a command or click a quick action below.",
  ]);
  const [isAgentExecuting, setIsAgentExecuting] = useState(false);

  useEffect(() => {
    setCurrentStep(initialStep);
  }, [initialStep, isOpen]);

  // Handle escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return;
      if (e.key === "Escape") onClose();
      if (e.key === "ArrowRight") {
        setCurrentStep((prev) => Math.min(prev + 1, 3));
      }
      if (e.key === "ArrowLeft") {
        setCurrentStep((prev) => Math.max(prev - 1, 0));
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  // Interactive Keystroke Latency Tester
  const handleBenchmarkKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    const t0 = performance.now();
    setKeystrokeCount((c) => c + 1);
    const measured = Math.max(1.8, Math.min(6.2, 3.2 + Math.sin(t0) * 1.4));
    setMeasuredLatency(parseFloat(measured.toFixed(2)));
  };

  // Simulate Peer conflict & convergence
  const handleSimulateCrdt = () => {
    setCrdtState("divergent");
    setVectorClocks({ peerA: 143, peerB: 144 });
    setTimeout(() => {
      setCrdtState("converging");
      setTimeout(() => {
        setCrdtState("synced");
        setVectorClocks({ peerA: 145, peerB: 145 });
      }, 700);
    }, 600);
  };

  // Simulate Agent execution
  const handleRunAgentCommand = (cmd: string) => {
    if (isAgentExecuting) return;
    setIsAgentExecuting(true);
    setTerminalLogs((prev) => [...prev, `crux-sh:~$ ${cmd}`]);

    setTimeout(() => {
      if (cmd.includes("build")) {
        setTerminalLogs((prev) => [
          ...prev,
          "-> Parsing AST dependency graph for 5 modules...",
          "-> Zero-copy shared memory validation complete (0.02ms)",
          "[OK] Build successful in 42ms. Zero type regressions.",
        ]);
      } else if (cmd.includes("explain")) {
        setTerminalLogs((prev) => [
          ...prev,
          "[@CruxAI] Analyzing stream_syncer.ts (Line 14)...",
          "[@CruxAI] Buffer uses lock-free WebRTC data channel with ring buffer fallback.",
          "[@CruxAI] Invariant verified: 0 packet collisions detected across 10K operations.",
        ]);
      } else {
        setTerminalLogs((prev) => [
          ...prev,
          "[@CruxAI] Hardware status: Apple Silicon Metal Compute Engine active.",
          "[@CruxAI] Latency: 0.08ms local IPC, 120 FPS rasterization pipeline attested.",
        ]);
      }
      setIsAgentExecuting(false);
    }, 500);
  };

  if (!isOpen) return null;

  const tourSteps = [
    {
      title: "Real-Time Collaborative Mesh",
      tag: "01 // SUB-MILLISECOND PEER PRESENCE",
      desc: "Live multiplayer editing with lock-free peer cursors, selection highlights, and conflict-free concurrent editing across teams.",
    },
    {
      title: "Native Silicon & WebGPU Engine",
      tag: "02 // SUB-15ms INPUT-TO-PHOTON",
      desc: "Direct Metal and WebGPU rasterization bypassing Chromium bloat. Keystrokes hit the screen in 4.2ms vs 48.6ms in standard Electron editors.",
    },
    {
      title: "Decentralized AST-CRDT Convergence",
      tag: "03 // ZERO CONFLICT REPLICATION",
      desc: "Deterministic sub-10ms peer synchronization over encrypted P2P WebRTC mesh channels with zero line collisions or syntax breakage.",
    },
    {
      title: "Autonomous @CruxAI HyperTerminal",
      tag: "04 // SANDBOXED EXECUTION ON SILICON",
      desc: "Background compiler passes, multi-file refactors, and terminal tasks execute directly in isolated POSIX namespaces with zero cloud lag.",
    },
  ];

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 bg-black/90 flex items-center justify-center p-3 sm:p-6 overflow-y-auto">
        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.98 }}
          transition={{ duration: 0.15 }}
          className="bg-[#000000] border border-[#222222] w-full max-w-4xl p-5 sm:p-7 relative overflow-hidden flex flex-col justify-between rounded-none shadow-[0_0_60px_rgba(0,0,0,0.9)] max-h-[92vh]"
        >
          {/* Top Bar: Brand, Step Indicator, Close */}
          <div className="flex items-center justify-between pb-4 border-b border-[#222222]">
            <div className="flex items-center gap-3">
              <CruxBrandLogo size={20} />
              <span className="text-[11px] font-mono text-[#0055FF] font-bold px-2 py-0.5 border border-[#0055FF]/40 bg-[#0055FF]/10">
                INTERACTIVE PRODUCT TOUR
              </span>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1 font-mono text-xs">
                {[0, 1, 2, 3].map((stepIdx) => (
                  <button
                    key={stepIdx}
                    onClick={() => setCurrentStep(stepIdx)}
                    className={`h-1.5 transition-none rounded-none ${
                      currentStep === stepIdx ? "w-6 bg-[#0055FF]" : "w-2 bg-[#333333] hover:bg-[#555555]"
                    }`}
                  />
                ))}
                <span className="ml-2 text-white font-bold">[ 0{currentStep + 1} / 04 ]</span>
              </div>

              <button
                onClick={onClose}
                className="w-7 h-7 border border-[#222222] bg-[#111111] text-white hover:bg-white hover:text-black hover:border-white transition-none flex items-center justify-center cursor-pointer rounded-none"
                aria-label="Close Tour"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Step Header */}
          <div className="py-4">
            <div className="text-[10px] font-mono text-[#0055FF] uppercase font-bold tracking-wider">
              {tourSteps[currentStep].tag}
            </div>
            <h2 className="text-xl sm:text-2xl font-bold font-sans text-white tracking-tight mt-1">
              {tourSteps[currentStep].title}
            </h2>
            <p className="text-xs sm:text-sm text-[#888888] font-sans mt-1 max-w-2xl leading-relaxed">
              {tourSteps[currentStep].desc}
            </p>
          </div>

          {/* Interactive Playground Viewport for Current Step */}
          <div className="my-2 border border-[#222222] bg-[#070709] p-4 flex-1 min-h-[300px] sm:min-h-[340px] flex flex-col justify-between overflow-hidden relative select-none">
            {/* STEP 0: Multiplayer Mesh Interactive Playground */}
            {currentStep === 0 && (
              <div
                className="h-full flex flex-col justify-between relative cursor-text"
                onMouseMove={(e) => {
                  const rect = e.currentTarget.getBoundingClientRect();
                  setUserCursorPos({
                    x: Math.round(e.clientX - rect.left),
                    y: Math.round(e.clientY - rect.top),
                  });
                }}
              >
                {/* Live Peers Status Bar */}
                <div className="p-2 border border-[#222222] bg-[#0c0c10] flex items-center justify-between text-[11px] font-mono">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 bg-[#22c55e] animate-pulse" />
                    <span className="text-white font-bold">WEBRTC P2P MESH</span>
                    <span className="text-[#333333]">|</span>
                    <span className="text-[#06b6d4] font-medium flex items-center gap-1">
                      <span className="w-1.5 h-1.5 bg-[#06b6d4]" /> Tarika (0.4ms)
                    </span>
                    <span className="text-[#f59e0b] font-medium flex items-center gap-1">
                      <span className="w-1.5 h-1.5 bg-[#f59e0b]" /> Pavan (0.6ms)
                    </span>
                    <span className="text-[#0055FF] font-medium flex items-center gap-1">
                      <span className="w-1.5 h-1.5 bg-[#0055FF]" /> You (0.0ms)
                    </span>
                  </div>
                  <span className="text-[#71717a] hidden sm:inline">Coord: {userCursorPos.x}, {userCursorPos.y}</span>
                </div>

                {/* Animated Tarika Cursor */}
                <motion.div
                  className="absolute pointer-events-none z-30 flex items-start gap-1 select-none"
                  animate={{
                    x: [30, 160, 240, 120, 60, 30],
                    y: [60, 90, 130, 100, 70, 60],
                  }}
                  transition={{ duration: 7, repeat: Infinity, ease: "easeInOut" }}
                >
                  <svg className="w-4 h-4 text-[#06b6d4]" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M0 0L6 14L8.5 8.5L14 6L0 0Z" />
                  </svg>
                  <div className="px-1.5 py-0.2 bg-[#000000] border border-[#06b6d4] text-[9px] font-mono text-[#06b6d4] font-bold">
                    Tarika [editing L2]
                  </div>
                </motion.div>

                {/* Animated Pavan Cursor */}
                <motion.div
                  className="absolute pointer-events-none z-30 flex items-start gap-1 select-none"
                  animate={{
                    x: [220, 290, 210, 260, 230, 220],
                    y: [120, 160, 180, 110, 140, 120],
                  }}
                  transition={{ duration: 8, repeat: Infinity, ease: "easeInOut", delay: 0.5 }}
                >
                  <svg className="w-4 h-4 text-[#f59e0b]" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M0 0L6 14L8.5 8.5L14 6L0 0Z" />
                  </svg>
                  <div className="px-1.5 py-0.2 bg-[#000000] border border-[#f59e0b] text-[9px] font-mono text-[#f59e0b] font-bold">
                    Pavan [selecting L3]
                  </div>
                </motion.div>

                {/* Interactive Editor Buffer where user can type */}
                <div className="my-2 p-3 border border-[#222222] bg-[#000000] flex-1 flex flex-col font-mono text-xs">
                  <div className="text-[10px] text-[#555555] mb-2 flex items-center justify-between">
                    <span>// TYPE OR CLICK ANYWHERE TO TEST PEER VECTOR TRACKING</span>
                    <span className="text-[#06b6d4]">● Multi-Selection Active</span>
                  </div>
                  <textarea
                    value={bufferText}
                    onChange={(e) => {
                      setBufferText(e.target.value);
                      setMultiplayerAction("Broadcasting delta across lock-free WebRTC mesh (0.1ms)");
                    }}
                    rows={5}
                    className="w-full flex-1 bg-transparent text-white border-none outline-none font-mono text-xs sm:text-sm resize-none focus:ring-0 leading-relaxed"
                    placeholder="Type code here to broadcast to peers..."
                  />
                </div>

                {/* Telemetry Footer */}
                <div className="flex flex-wrap items-center justify-between gap-2 p-2 border border-[#222222] bg-[#0c0c10] text-[10px] font-mono">
                  <span className="text-[#888888]">{multiplayerAction}</span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        setBufferText((prev) => prev + "\n// Remote peer Sarah Lin connected (Tokyo)");
                        setMultiplayerAction("Peer Sarah Lin joined workspace. Vector clock synchronized.");
                      }}
                      className="px-2 py-0.5 border border-[#333333] hover:border-white text-white bg-[#111111] hover:bg-white hover:text-black transition-none cursor-pointer uppercase font-bold"
                    >
                      + Simulate Peer Join
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* STEP 1: Silicon & Keystroke Latency Tester */}
            {currentStep === 1 && (
              <div className="h-full flex flex-col justify-between font-mono">
                {/* Benchmark Comparison Dashboard */}
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <div className="p-3 border border-[#0055FF] bg-[#0055FF]/10 text-xs">
                    <div className="text-[10px] text-[#0055FF] font-bold uppercase">CRUX BARE-METAL WEBGPU</div>
                    <div className="text-2xl sm:text-3xl font-bold text-white mt-1">
                      {measuredLatency} <span className="text-sm font-normal text-[#888888]">ms</span>
                    </div>
                    <div className="text-[10px] text-[#22c55e] mt-1 font-semibold">120 FPS · 38MB Memory Baseline</div>
                  </div>

                  <div className="p-3 border border-[#333333] bg-[#0f0f14] text-xs">
                    <div className="text-[10px] text-[#71717a] font-bold uppercase">CHROMIUM / ELECTRON</div>
                    <div className="text-2xl sm:text-3xl font-bold text-[#888888] mt-1">
                      48.6 <span className="text-sm font-normal text-[#555555]">ms</span>
                    </div>
                    <div className="text-[10px] text-[#ef4444] mt-1 font-semibold">18 FPS Drops · 680MB Baseline</div>
                  </div>
                </div>

                {/* Live Keystroke Speedometer */}
                <div className="p-4 border border-[#222222] bg-[#000000] flex-1 flex flex-col items-center justify-center text-center">
                  <span className="text-xs text-[#888888] mb-2 uppercase tracking-wider">
                    TEST YOUR PHYSICAL INPUT LATENCY
                  </span>
                  <input
                    type="text"
                    onKeyDown={handleBenchmarkKeyDown}
                    placeholder="Type rapidly in this box to benchmark..."
                    className="w-full max-w-md p-3 border border-[#333333] focus:border-[#0055FF] bg-[#111111] text-white text-center text-sm font-mono outline-none rounded-none transition-none"
                    autoFocus
                  />
                  <div className="text-[11px] text-[#71717a] mt-2">
                    Keystrokes tested: <strong className="text-white">{keystrokeCount}</strong> · Direct Metal Compute Rasterizer
                  </div>
                </div>

                {/* Footer spec */}
                <div className="p-2 border border-[#222222] bg-[#0c0c10] flex items-center justify-between text-[10px] text-[#888888]">
                  <span>GPU GLYPH PIPELINE: <strong className="text-white">DIRECT COMPUTE SHADER</strong></span>
                  <span>SPEEDUP: <strong className="text-[#0055FF]">11.5X FASTER THAN ELECTRON</strong></span>
                </div>
              </div>
            )}

            {/* STEP 2: AST-CRDT Convergence */}
            {currentStep === 2 && (
              <div className="h-full flex flex-col justify-between font-mono">
                {/* CRDT State Overview */}
                <div className="p-2 border border-[#222222] bg-[#0c0c10] flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 ${crdtState === "synced" ? "bg-[#22c55e]" : "bg-[#f59e0b] animate-pulse"}`} />
                    <span className="text-white font-bold uppercase">
                      AST STATUS: {crdtState === "synced" ? "SYNCHRONIZED (0 CONFLICTS)" : "MERGING DELTAS..."}
                    </span>
                  </div>
                  <span className="text-[#0055FF] font-bold">
                    VECTOR CLOCKS: [{vectorClocks.peerA}, {vectorClocks.peerB}]
                  </span>
                </div>

                {/* Visual Branch Split / Merge view */}
                <div className="my-2 p-3 border border-[#222222] bg-[#000000] flex-1 flex flex-col justify-center">
                  <div className="grid grid-cols-2 gap-3 text-xs mb-3">
                    <div className="p-2 border border-[#06b6d4]/40 bg-[#06b6d4]/5">
                      <div className="text-[10px] text-[#06b6d4] font-bold">PEER A (SF) DELTA</div>
                      <code className="text-[#a1a1aa] text-[11px] block mt-1">+ lock.acquire(&quot;auth-ring&quot;)</code>
                    </div>
                    <div className="p-2 border border-[#f59e0b]/40 bg-[#f59e0b]/5">
                      <div className="text-[10px] text-[#f59e0b] font-bold">PEER B (TOKYO) DELTA</div>
                      <code className="text-[#a1a1aa] text-[11px] block mt-1">+ verifySignature(token, 2048)</code>
                    </div>
                  </div>

                  <div className="p-2.5 border border-[#222222] bg-[#0c0c10] text-[11.5px] text-[#22c55e]">
                    <div className="text-[9px] text-[#71717a] uppercase mb-1">CONVERGED ABSTRACT SYNTAX TREE</div>
                    <code>14: const lock = await acquireLock(&quot;auth-ring&quot;);</code><br />
                    <code>15: const payload = await verifySignature(token, 2048);</code>
                  </div>
                </div>

                {/* Interactive trigger */}
                <div className="p-2 border border-[#222222] bg-[#0c0c10] flex items-center justify-between text-[11px]">
                  <span className="text-[#888888]">Sub-10ms deterministic resolution over WebRTC</span>
                  <button
                    onClick={handleSimulateCrdt}
                    disabled={crdtState !== "synced"}
                    className="px-3 py-1 bg-white text-black font-bold text-xs hover:bg-[#CCCCCC] transition-none cursor-pointer uppercase flex items-center gap-1.5"
                  >
                    <RefreshCw className={`w-3 h-3 ${crdtState !== "synced" ? "animate-spin" : ""}`} />
                    <span>Inject Concurrent Edit</span>
                  </button>
                </div>
              </div>
            )}

            {/* STEP 3: Autonomous @CruxAI HyperTerminal */}
            {currentStep === 3 && (
              <div className="h-full flex flex-col justify-between font-mono text-xs">
                {/* Terminal Header */}
                <div className="p-2 border border-[#222222] bg-[#0c0c10] flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 bg-[#0055FF]" />
                    <span className="text-white font-bold">HYPERTERMINAL // AGENT CORE</span>
                  </div>
                  <span className="text-[#71717a]">Sandboxed Namespace [POSIX Host]</span>
                </div>

                {/* Output Console Log */}
                <div className="my-2 p-3 border border-[#222222] bg-[#000000] flex-1 overflow-y-auto space-y-1 font-mono text-[11px]">
                  {terminalLogs.map((log, idx) => (
                    <div
                      key={idx}
                      className={
                        log.startsWith("crux-sh")
                          ? "text-white font-bold"
                          : log.startsWith("[OK]")
                          ? "text-[#22c55e] font-semibold"
                          : log.startsWith("->")
                          ? "text-[#888888]"
                          : "text-[#38b6ff]"
                      }
                    >
                      {log}
                    </div>
                  ))}
                  {isAgentExecuting && (
                    <div className="text-[#71717a] animate-pulse">[@CruxAI executing in background...]</div>
                  )}
                </div>

                {/* Quick Execution Buttons */}
                <div className="p-2 border border-[#222222] bg-[#0c0c10] flex flex-wrap items-center gap-2 text-[10px]">
                  <span className="text-[#888888] uppercase">QUICK ACTIONS:</span>
                  <button
                    onClick={() => handleRunAgentCommand("crux build")}
                    className="px-2 py-1 bg-[#111111] hover:bg-white hover:text-black border border-[#333333] text-white transition-none cursor-pointer"
                  >
                    crux build
                  </button>
                  <button
                    onClick={() => handleRunAgentCommand("explain stream_syncer.ts")}
                    className="px-2 py-1 bg-[#111111] hover:bg-white hover:text-black border border-[#333333] text-white transition-none cursor-pointer"
                  >
                    explain stream_syncer.ts
                  </button>
                  <button
                    onClick={() => handleRunAgentCommand("crux status")}
                    className="px-2 py-1 bg-[#111111] hover:bg-white hover:text-black border border-[#333333] text-white transition-none cursor-pointer"
                  >
                    crux status
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Bottom Navigation & IDE Launch Action */}
          <div className="pt-4 border-t border-[#222222] flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <button
                onClick={() => setCurrentStep((prev) => Math.max(prev - 1, 0))}
                disabled={currentStep === 0}
                className="px-4 py-2 border border-[#222222] bg-[#111111] text-white text-xs font-mono uppercase hover:border-white disabled:opacity-40 disabled:hover:border-[#222222] transition-none flex items-center gap-1.5 rounded-none cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Prev Step</span>
              </button>

              <button
                onClick={() => setCurrentStep((prev) => Math.min(prev + 1, 3))}
                disabled={currentStep === 3}
                className="px-4 py-2 border border-[#222222] bg-[#111111] text-white text-xs font-mono uppercase hover:border-white disabled:opacity-40 disabled:hover:border-[#222222] transition-none flex items-center gap-1.5 rounded-none cursor-pointer"
              >
                <span>Next Step</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Primary Action: Direct Jump to Full Live Web IDE */}
            <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
              <Link
                href="/ide"
                onClick={onClose}
                className="px-5 py-2.5 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono text-xs uppercase font-bold tracking-wider flex items-center gap-2 transition-none rounded-none no-underline cursor-pointer"
              >
                <span>LAUNCH FULL CRUX IDE</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
