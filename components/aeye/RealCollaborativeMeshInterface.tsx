"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Files,
  FileCode2,
  GitBranch,
  Radio,
  Bot,
  Terminal,
  Settings,
  SplitSquareVertical,
  Play,
  Save,
  Share2,
  Check,
  Cpu,
  Wifi,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import CruxPointerCursor from "@/components/crux/CruxPointerCursor";

interface RealCollaborativeMeshInterfaceProps {
  showHeader?: boolean;
  showStatusBar?: boolean;
}

export default function RealCollaborativeMeshInterface({
  showHeader = false,
  showStatusBar = true,
}: RealCollaborativeMeshInterfaceProps) {
  // Marcus Vance typing simulation inside acquireLock
  const fullParamString = 'channel = "stream-mesh-primary"';
  const [typedChars, setTypedChars] = useState(fullParamString.length);
  const [isTyping, setIsTyping] = useState(true);

  // Real-time jitter telemetry for real peers
  const [sarahLatency, setSarahLatency] = useState("0.28ms");
  const [marcusLatency, setMarcusLatency] = useState("0.41ms");

  useEffect(() => {
    const jitterInterval = setInterval(() => {
      setSarahLatency(`${(0.24 + Math.random() * 0.08).toFixed(2)}ms`);
      setMarcusLatency(`${(0.36 + Math.random() * 0.10).toFixed(2)}ms`);
    }, 1400);
    return () => clearInterval(jitterInterval);
  }, []);

  // Character-by-character live typing loop for Marcus Vance
  useEffect(() => {
    let timeout: NodeJS.Timeout;
    let charIndex = fullParamString.length;
    let forward = false;

    const runTypingLoop = () => {
      if (forward) {
        if (charIndex < fullParamString.length) {
          charIndex += 1;
          setTypedChars(charIndex);
          setIsTyping(true);
          const typingDelay = 40 + Math.random() * 50;
          timeout = setTimeout(runTypingLoop, typingDelay);
        } else {
          setIsTyping(false);
          timeout = setTimeout(() => {
            forward = false;
            runTypingLoop();
          }, 3600);
        }
      } else {
        if (charIndex > 10) {
          charIndex -= 1;
          setTypedChars(charIndex);
          timeout = setTimeout(runTypingLoop, 35);
        } else {
          forward = true;
          timeout = setTimeout(runTypingLoop, 800);
        }
      }
    };

    timeout = setTimeout(runTypingLoop, 2000);
    return () => clearTimeout(timeout);
  }, []);

  return (
    <div className="w-full h-full bg-[#000000] flex flex-col justify-between font-mono select-none overflow-hidden text-xs">
      {/* 1. IDE TOP TITLEBAR & WORKSPACE BREADCRUMBS */}
      {showHeader && (
        <div className="h-8 px-3 bg-[#0a0a0d] border-b border-[#222222] flex items-center justify-between shrink-0">
          {/* Left: Window Controls + Breadcrumbs */}
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="flex items-center gap-1.5 shrink-0">
              <span className="w-2 h-2 bg-[#007AFF] rounded-none inline-block" />
              <span className="text-[11px] font-mono text-white font-bold tracking-tight">CRUX</span>
            </div>

            <div className="w-[1px] h-3 bg-[#222222]" />

            <div className="flex items-center gap-1 text-[11px] text-[#666666] truncate font-mono">
              <span className="text-[#888888]">crux-stream-sync</span>
              <span className="text-[#333333]">/</span>
              <span className="text-[#888888]">src</span>
              <span className="text-[#333333]">/</span>
              <span className="text-white font-medium flex items-center gap-1">
                <FileCode2 className="w-3 h-3 text-[#007AFF]" />
                stream_syncer.ts
              </span>
            </div>
          </div>

          {/* Right: Live Collaborative Presence Badges */}
          <div className="flex items-center gap-2 shrink-0">
            <div className="flex items-center -space-x-1">
              <div
                className="w-5 h-5 bg-[#007AFF] text-[9px] font-bold text-white flex items-center justify-center rounded-none z-30 border border-black"
                title="Hrushikesh Gangala (Host)"
              >
                HG
              </div>
              <div
                className="w-5 h-5 bg-[#38b6ff] text-[9px] font-bold text-black flex items-center justify-center rounded-none z-20 border border-black"
                title="Sarah Lin (Staff Infrastructure)"
              >
                SL
              </div>
              <div
                className="w-5 h-5 bg-[#ff914d] text-[9px] font-bold text-black flex items-center justify-center rounded-none z-10 border border-black"
                title="Marcus Vance (Systems Architect)"
              >
                MV
              </div>
              <div
                className="w-5 h-5 bg-[#ff5757] text-[9px] font-bold text-white flex items-center justify-center rounded-none z-0 border border-black"
                title="CruxAI (Speculative Co-Pilot)"
              >
                AI
              </div>
            </div>

            <div className="px-1.5 py-0.5 border border-[#22c55e]/40 bg-[#22c55e]/10 text-[9px] text-[#22c55e] font-mono flex items-center gap-1">
              <span className="w-1.5 h-1.5 bg-[#22c55e] animate-pulse rounded-none" />
              <span className="font-semibold hidden sm:inline">3 PEERS IN-SYNC</span>
            </div>
          </div>
        </div>
      )}

      {/* 2. MAIN WORKSPACE (ACTIVITY BAR + ZENITH FILE TREE + CODE EDITOR PANE) */}
      <div className="flex-1 flex overflow-hidden min-h-0 bg-[#000000]">
        {/* Left Activity Bar */}
        <div className="w-8 sm:w-9 bg-[#08080a] border-r border-[#222222] flex flex-col items-center justify-between py-2 shrink-0">
          <div className="flex flex-col items-center gap-3">
            <div className="w-full flex items-center justify-center relative cursor-pointer text-white">
              <div className="absolute left-0 top-1 bottom-1 w-[2px] bg-[#007AFF]" />
              <Files className="w-3.5 h-3.5 text-white" />
            </div>
            <GitBranch className="w-3.5 h-3.5 text-[#555555] hover:text-[#888888] cursor-pointer" />
            <div className="relative cursor-pointer">
              <Radio className="w-3.5 h-3.5 text-[#007AFF]" />
              <span className="absolute -top-1 -right-1 w-1 h-1 bg-[#22c55e] rounded-none animate-ping" />
            </div>
            <Bot className="w-3.5 h-3.5 text-[#555555] hover:text-[#888888] cursor-pointer" />
          </div>
          <div className="flex flex-col items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-[#555555]" />
            <Settings className="w-3.5 h-3.5 text-[#555555]" />
          </div>
        </div>

        {/* Real Zenith File Tree Sidebar */}
        <div className="w-28 sm:w-36 bg-[#0a0a0c] border-r border-[#222222] p-2 flex flex-col justify-between shrink-0 hidden sm:flex">
          <div>
            <div className="text-[9px] uppercase tracking-wider text-[#666666] font-semibold pb-1 border-b border-[#1c1c20] mb-1.5 flex items-center justify-between">
              <span>EXPLORER</span>
              <span className="text-[8px] text-[#444444]">CRUX</span>
            </div>
            <div className="space-y-0.5 text-[10px]">
              <div className="text-[#888888] flex items-center gap-1 py-0.5 px-1 font-mono text-[9px]">
                <span className="text-[8px]">▾</span>
                <span>crux-stream-sync</span>
              </div>
              <div className="bg-[#141418] border-l-2 border-[#007AFF] text-white flex items-center gap-1.5 py-0.5 pl-2 font-mono text-[9.5px]">
                <span className="w-1 h-1 bg-[#007AFF] rounded-none" />
                <span className="font-semibold truncate">stream_syncer.ts</span>
              </div>
              <div className="text-[#666666] flex items-center gap-1.5 py-0.5 pl-3 font-mono text-[9px] hover:text-white cursor-pointer">
                <span className="w-1 h-1 bg-[#333333] rounded-none" />
                <span className="truncate">database.ts</span>
              </div>
              <div className="text-[#666666] flex items-center gap-1.5 py-0.5 pl-3 font-mono text-[9px] hover:text-white cursor-pointer">
                <span className="w-1 h-1 bg-[#333333] rounded-none" />
                <span className="truncate">auth.ts</span>
              </div>
              <div className="text-[#666666] flex items-center gap-1.5 py-0.5 pl-3 font-mono text-[9px] hover:text-white cursor-pointer">
                <span className="w-1 h-1 bg-[#333333] rounded-none" />
                <span className="truncate">spatialEngine.ts</span>
              </div>
              <div className="text-[#555555] flex items-center gap-1.5 py-0.5 pl-2 font-mono text-[9px]">
                <span>package.json</span>
              </div>
            </div>
          </div>

          {/* Active Peers Micro-List */}
          <div className="pt-2 border-t border-[#1c1c20] text-[8.5px] space-y-1">
            <div className="text-[#555555] uppercase font-bold tracking-wider">LIVE MESH</div>
            <div className="flex items-center justify-between text-[#38b6ff]">
              <span className="flex items-center gap-1 truncate">
                <span className="w-1 h-1 bg-[#38b6ff] rounded-none" />
                Sarah Lin
              </span>
              <span className="text-[7.5px] text-[#666666] shrink-0">{sarahLatency}</span>
            </div>
            <div className="flex items-center justify-between text-[#ff914d]">
              <span className="flex items-center gap-1 truncate">
                <span className="w-1 h-1 bg-[#ff914d] rounded-none" />
                Marcus Vance
              </span>
              <span className="text-[7.5px] text-[#666666] shrink-0">{marcusLatency}</span>
            </div>
            <div className="flex items-center justify-between text-[#ff5757]">
              <span className="flex items-center gap-1 truncate">
                <span className="w-1 h-1 bg-[#ff5757] rounded-none" />
                @CruxAI
              </span>
              <span className="text-[7.5px] text-[#22c55e] shrink-0">ACTIVE</span>
            </div>
          </div>
        </div>

        {/* Main Code Editor Pane */}
        <div className="flex-1 flex flex-col min-w-0 bg-[#000000] relative">
          {/* Zenith Tab Bar */}
          <div className="h-7 bg-[#111111] border-b border-[#222222] flex items-center justify-between px-2 shrink-0 select-none">
            <div className="flex items-center h-full overflow-hidden">
              {/* Active Tab */}
              <div className="h-full px-3 bg-[#000000] border-r border-[#222222] text-white flex items-center gap-2 text-[11px] font-sans uppercase tracking-tight font-medium">
                <span>stream_syncer.ts</span>
                <span className="text-[9px] text-[#444444] font-mono shrink-0 hidden md:inline">14L</span>
                <span className="w-1.5 h-1.5 bg-white shrink-0" title="Unsaved changes" />
                <span className="text-[#444444] hover:text-white cursor-pointer ml-1">×</span>
              </div>
              {/* Inactive Tabs */}
              <div className="h-full px-3 bg-[#111111] text-[#444444] hover:text-white border-r border-[#222222] items-center gap-2 text-[11px] font-sans uppercase tracking-tight cursor-pointer hidden sm:flex">
                <span>database.ts</span>
              </div>
              <div className="h-full px-3 bg-[#111111] text-[#444444] hover:text-white border-r border-[#222222] items-center gap-2 text-[11px] font-sans uppercase tracking-tight cursor-pointer hidden md:flex">
                <span>auth.ts</span>
              </div>
            </div>

            {/* Tab Strip Right Controls */}
            <div className="flex items-center gap-1 text-[#888888]">
              <div className="px-1.5 py-0.5 text-[9px] font-mono border border-[#222222] text-[#888888] uppercase hidden sm:block">
                HARDWARE VIEW
              </div>
              <div className="px-2 py-0.5 border border-[#222222] bg-[#000000] text-[#007AFF] hover:text-white flex items-center gap-1 font-mono text-[9px] uppercase font-bold cursor-pointer">
                <Play className="w-2.5 h-2.5 fill-current text-[#007AFF]" />
                <span>RUN ↵</span>
              </div>
            </div>
          </div>

          {/* Real Code Buffer Canvas with Live Cursor Motion */}
          <div className="flex-1 p-2 sm:p-3 overflow-hidden relative font-mono text-[11px] sm:text-[11.5px] leading-[1.65] bg-[#000000]">
            {/* Subtle Hardware Matrix Background Pattern */}
            <div className="absolute inset-0 opacity-[0.025] bg-[linear-gradient(to_right,#ffffff_1px,transparent_1px),linear-gradient(to_bottom,#ffffff_1px,transparent_1px)] bg-[size:16px_16px] pointer-events-none" />

            {/* ============================================================== */}
            {/* COLLABORATOR 1: SARAH LIN LIVE CURSOR (HOVERING ACQUIRELOCK)  */}
            {/* ============================================================== */}
            <motion.div
              className="absolute pointer-events-none z-30 select-none"
              animate={{
                x: [80, 160, 240, 190, 110, 80],
                y: [142, 146, 168, 144, 138, 142],
              }}
              transition={{
                duration: 7.2,
                repeat: Infinity,
                ease: "easeInOut",
              }}
            >
              <CruxPointerCursor
                name="Sarah Lin"
                uid="CRX-9941-SL"
                color="#38b6ff"
              />
            </motion.div>

            {/* ============================================================== */}
            {/* COLLABORATOR 2: MARCUS VANCE LIVE CURSOR (LIVE TYPING PARAM)   */}
            {/* ============================================================== */}
            <motion.div
              className="absolute pointer-events-none z-30 select-none"
              animate={{
                x: [180, 260, 310, 280, 210, 180],
                y: [98, 100, 102, 100, 98, 98],
              }}
              transition={{
                duration: 6.5,
                repeat: Infinity,
                ease: "easeInOut",
                delay: 0.2,
              }}
            >
              <CruxPointerCursor
                name="Marcus Vance"
                uid="CRX-5520-MV"
                color="#ff914d"
                status={isTyping ? "typing" : undefined}
              />
            </motion.div>

            {/* ============================================================== */}
            {/* COLLABORATOR 3: @CRUXAI CO-PILOT DRONE CURSOR                 */}
            {/* ============================================================== */}
            <motion.div
              className="absolute pointer-events-none z-20 select-none hidden md:block"
              animate={{
                x: [240, 270, 250, 230, 240],
                y: [180, 184, 188, 182, 180],
              }}
              transition={{
                duration: 8.5,
                repeat: Infinity,
                ease: "easeInOut",
                delay: 1.0,
              }}
            >
              <CruxPointerCursor
                name="@CruxAI"
                uid="CRX-0001-AI"
                color="#ff5757"
              />
            </motion.div>

            {/* CODE LINES WITH REAL CRUX SYNTAX & MULTIPLAYER HIGHLIGHTS */}
            <div className="space-y-0.5 relative z-10">
              {/* Line 01 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">01</span>
                <span className="text-white">
                  <span className="text-[#007AFF] font-semibold">import</span> &#123; LocalDaemonClient &#125; <span className="text-[#007AFF] font-semibold">from</span> <span className="text-[#22c55e]">"@crux/daemon"</span>;
                </span>
              </div>

              {/* Line 02 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">02</span>
                <span></span>
              </div>

              {/* Line 03 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">03</span>
                <span className="text-white">
                  <span className="text-[#007AFF] font-semibold">export class</span> <span className="text-white font-bold">StreamSyncer</span> &#123;
                </span>
              </div>

              {/* Line 04 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">04</span>
                <span className="text-white pl-3">
                  timeout = <span className="text-[#22c55e]">5000</span>;
                </span>
              </div>

              {/* Line 05 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">05</span>
                <span className="text-white pl-3">
                  daemon = <span className="text-[#007AFF]">new</span> LocalDaemonClient(&#123; port: <span className="text-[#22c55e]">7447</span> &#125;);
                </span>
              </div>

              {/* Line 06: Marcus Vance Live Typing Line */}
              <div className="flex items-center relative bg-[#ff914d]/10 border-l-2 border-[#ff914d] pl-0.5">
                <span className="w-6 text-right text-[10px] text-[#ff914d] font-bold select-none pr-3">06</span>
                <span className="text-white pl-3 font-mono">
                  <span className="text-[#007AFF]">async</span> acquireLock(
                  <span className="text-[#e4e4e7]">{fullParamString.slice(0, typedChars)}</span>
                  {/* Blinking 1px Caret */}
                  <motion.span
                    animate={{ opacity: [1, 0, 1] }}
                    transition={{ repeat: Infinity, duration: 0.5 }}
                    className="inline-block w-1.5 h-3 bg-[#ff914d] ml-0.5 align-middle select-none"
                  />
                  ) &#123;
                </span>
                <span className="ml-auto text-[8.5px] font-mono text-[#ff914d] uppercase tracking-wider font-semibold pr-2 hidden md:inline select-none">
                  [Marcus Vance typing]
                </span>
              </div>

              {/* Line 07 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">07</span>
                <span className="text-[#888888] pl-6 italic">
                  console.log(<span className="text-[#22c55e]">"[StreamSyncer] Requesting mutual exclusion lock..."</span>);
                </span>
              </div>

              {/* Line 08: Sarah Lin Active Selection Highlight */}
              <div className="flex items-center relative bg-[#38b6ff]/15 border-l-2 border-[#38b6ff] pl-0.5">
                <span className="w-6 text-right text-[10px] text-[#38b6ff] font-bold select-none pr-3">08</span>
                <span className="text-white pl-6">
                  <span className="text-[#007AFF]">const</span> ticket = <span className="text-[#007AFF]">await</span> <span className="text-white font-medium">this.daemon.acquireLock(channel);</span>
                </span>
                <span className="ml-auto text-[8.5px] font-mono text-[#38b6ff] uppercase tracking-wider font-semibold pr-2 hidden md:inline select-none">
                  [Sarah Lin selecting]
                </span>
              </div>

              {/* Line 09 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">09</span>
                <span className="text-white pl-6">
                  <span className="text-[#007AFF]">return</span> ticket;
                </span>
              </div>

              {/* Line 10: CruxAI Ghost Diff Recommendation */}
              <div className="flex items-center relative bg-[#ff5757]/10 border-l-2 border-[#ff5757] pl-0.5 py-0.5">
                <span className="w-6 text-right text-[10px] text-[#ff5757] font-bold select-none pr-3">+</span>
                <span className="text-[#ff5757] pl-6 text-[10.5px]">
                  // @CruxAI: Sub-millisecond mutual exclusion lock verified (0.08ms IPC)
                </span>
                <span className="ml-auto text-[8px] font-mono text-[#ff5757] border border-[#ff5757]/40 px-1 py-0.5 uppercase tracking-wider font-semibold pr-1 hidden sm:inline select-none">
                  [TAB TO ACCEPT]
                </span>
              </div>

              {/* Line 11 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">11</span>
                <span className="text-[#71717a] pl-3">&#125;</span>
              </div>

              {/* Line 12 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">12</span>
                <span className="text-[#71717a]">&#125;</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 3. REAL CRUX STATUS BAR */}
      {showStatusBar && (
        <div className="h-6 px-3 bg-[#08080a] border-t border-[#222222] flex items-center justify-between text-[10px] font-mono text-[#888888] select-none shrink-0">
          {/* Left Telemetry matching CruxStatusBar.tsx */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-white">
              <span className="w-1.5 h-1.5 rounded-none bg-[#007AFF]" />
              <span className="font-medium">Crux Daemon</span>
              <span className="text-white text-[9px] px-1 bg-black border border-[#222222] rounded-none">
                0.08ms IPC
              </span>
            </div>

            <span className="text-[#333333]">·</span>

            <div className="hidden sm:flex items-center gap-1 text-[#888888]">
              <Cpu className="w-3 h-3 text-[#007AFF]" />
              <span>Apple Silicon Metal Compute</span>
            </div>
          </div>

          {/* Right Telemetry matching CruxStatusBar.tsx */}
          <div className="flex items-center gap-3">
            <div className="hidden md:flex items-center gap-1 text-[#888888]">
              <ShieldCheck className="w-3 h-3 text-[#888888]" />
              <span>Zero-Knowledge CRDT Vector</span>
            </div>

            <span className="text-[#333333] hidden md:inline">·</span>

            <div className="flex items-center gap-1.5 text-white">
              <Wifi className="w-3 h-3 text-[#007AFF]" />
              <span>3 Peers In-Sync</span>
            </div>

            <span className="text-[#333333]">·</span>

            <div className="text-[#007AFF] font-bold">
              <span>120 FPS</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
