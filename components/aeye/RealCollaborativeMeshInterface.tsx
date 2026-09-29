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
  Check,
  Cpu,
  Activity,
  Wifi,
} from "lucide-react";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

interface RealCollaborativeMeshInterfaceProps {
  showHeader?: boolean;
  showStatusBar?: boolean;
}

export default function RealCollaborativeMeshInterface({
  showHeader = false,
  showStatusBar = false,
}: RealCollaborativeMeshInterfaceProps) {
  // Pavan typing simulation
  const targetCodeToType = "ring.broadcast_crdt_delta(&ast_delta).await?;";
  const [typedChars, setTypedChars] = useState(targetCodeToType.length);
  const [isTyping, setIsTyping] = useState(true);

  // Real-time jitter telemetry
  const [tarikaLatency, setTarikaLatency] = useState("0.42ms");
  const [pavanLatency, setPavanLatency] = useState("0.58ms");

  useEffect(() => {
    const jitterInterval = setInterval(() => {
      setTarikaLatency(`${(0.38 + Math.random() * 0.08).toFixed(2)}ms`);
      setPavanLatency(`${(0.52 + Math.random() * 0.12).toFixed(2)}ms`);
    }, 1200);
    return () => clearInterval(jitterInterval);
  }, []);

  // Character-by-character live typing loop for Pavan
  useEffect(() => {
    let timeout: NodeJS.Timeout;
    let charIndex = 0;
    let forward = true;

    const runTypingLoop = () => {
      if (forward) {
        if (charIndex < targetCodeToType.length) {
          charIndex += 1;
          setTypedChars(charIndex);
          setIsTyping(true);
          const typingDelay = 45 + Math.random() * 55;
          timeout = setTimeout(runTypingLoop, typingDelay);
        } else {
          // Pause when full line is typed
          setIsTyping(false);
          timeout = setTimeout(() => {
            forward = false;
            runTypingLoop();
          }, 3200);
        }
      } else {
        // Backspace a chunk and retype
        if (charIndex > 15) {
          charIndex -= 2;
          setTypedChars(Math.max(15, charIndex));
          timeout = setTimeout(runTypingLoop, 30);
        } else {
          forward = true;
          timeout = setTimeout(runTypingLoop, 600);
        }
      }
    };

    timeout = setTimeout(runTypingLoop, 1000);
    return () => clearTimeout(timeout);
  }, []);

  return (
    <div className="w-full h-full bg-[#000000] flex flex-col justify-between font-mono select-none overflow-hidden text-xs">
      {/* 1. IDE TOP TITLEBAR & PRESENCE BAR */}
      {showHeader && (
        <div className="h-8 px-2.5 bg-[#0a0a0d] border-b border-[#222222] flex items-center justify-between shrink-0">
          {/* Left: Window Controls + Crux Logo + Breadcrumbs */}
          <div className="flex items-center gap-2.5 min-w-0">
            {/* Hardware brutalist window notches */}
            <div className="flex items-center gap-1 shrink-0">
              <span className="w-2 h-2 bg-[#ff5f56] rounded-none inline-block opacity-80" />
              <span className="w-2 h-2 bg-[#ffbd2e] rounded-none inline-block opacity-80" />
              <span className="w-2 h-2 bg-[#27c93f] rounded-none inline-block opacity-80" />
            </div>

            <div className="w-[1px] h-3 bg-[#222222]" />

            {/* Crux Logo */}
            <div className="flex items-center gap-1.5 shrink-0">
              <CruxBrandLogo size={14} withText={true} />
            </div>

            <div className="w-[1px] h-3 bg-[#222222] hidden sm:block" />

            {/* Breadcrumbs */}
            <div className="hidden sm:flex items-center gap-1 text-[10px] text-[#666666] truncate font-mono">
              <span>core</span>
              <span className="text-[#333333]">/</span>
              <span>engine</span>
              <span className="text-[#333333]">/</span>
              <span className="text-white font-medium flex items-center gap-1">
                <FileCode2 className="w-3 h-3 text-[#0055FF]" />
                crdt_sync.rs
              </span>
            </div>
          </div>

          {/* Right: Live Collaborative Presence Badges */}
          <div className="flex items-center gap-2 shrink-0">
            {/* Peer Presence Cluster */}
            <div className="flex items-center -space-x-1.5">
              {/* Operator (Self) */}
              <div className="w-5 h-5 bg-[#0055FF] border border-[#0055FF] text-[9px] font-bold text-white flex items-center justify-center rounded-none z-30" title="You (Host)">
                OP
              </div>
              {/* Tarika (Peer 1) */}
              <div className="w-5 h-5 bg-[#06b6d4] border border-[#06b6d4] text-[9px] font-bold text-black flex items-center justify-center rounded-none z-20" title="Tarika (Tokyo)">
                TK
              </div>
              {/* Pavan (Peer 2) */}
              <div className="w-5 h-5 bg-[#f59e0b] border border-[#f59e0b] text-[9px] font-bold text-black flex items-center justify-center rounded-none z-10" title="Pavan (San Francisco)">
                PV
              </div>
            </div>

            {/* Live P2P Mesh Ping Indicator */}
            <div className="px-1.5 py-0.5 border border-[#22c55e]/40 bg-[#22c55e]/10 text-[9px] text-[#22c55e] font-mono flex items-center gap-1">
              <span className="w-1.5 h-1.5 bg-[#22c55e] animate-pulse rounded-none" />
              <span className="font-semibold hidden sm:inline">P2P MESH</span>
            </div>
          </div>
        </div>
      )}

      {/* 2. MAIN WORKSPACE (ACTIVITY BAR + FILE TREE + CODE CANVAS) */}
      <div className="flex-1 flex overflow-hidden min-h-0 bg-[#000000]">
        {/* Left Activity Bar */}
        <div className="w-8 sm:w-9 bg-[#08080a] border-r border-[#222222] flex flex-col items-center justify-between py-2 shrink-0">
          <div className="flex flex-col items-center gap-3">
            {/* Files active switch */}
            <div className="w-full flex items-center justify-center relative cursor-pointer text-white">
              <div className="absolute left-0 top-1 bottom-1 w-[2px] bg-[#0055FF]" />
              <Files className="w-3.5 h-3.5 text-white" />
            </div>
            <GitBranch className="w-3.5 h-3.5 text-[#555555] hover:text-[#888888] cursor-pointer" />
            <div className="relative cursor-pointer">
              <Radio className="w-3.5 h-3.5 text-[#0055FF]" />
              <span className="absolute -top-1 -right-1 w-1 h-1 bg-[#22c55e] rounded-none animate-ping" />
            </div>
            <Bot className="w-3.5 h-3.5 text-[#555555] hover:text-[#888888] cursor-pointer" />
          </div>
          <div className="flex flex-col items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-[#555555]" />
            <Settings className="w-3.5 h-3.5 text-[#555555]" />
          </div>
        </div>

        {/* Mini File Tree Sidebar (hidden on very small viewports) */}
        <div className="w-24 sm:w-28 bg-[#0a0a0c] border-r border-[#222222] p-2 flex flex-col justify-between shrink-0 hidden sm:flex">
          <div>
            <div className="text-[9px] uppercase tracking-wider text-[#666666] font-semibold pb-1 border-b border-[#1c1c20] mb-1.5 flex items-center justify-between">
              <span>EXPLORER</span>
              <span className="text-[8px] text-[#444444]">V0.1</span>
            </div>
            <div className="space-y-0.5 text-[10px]">
              <div className="text-[#888888] flex items-center gap-1 py-0.5 px-1 font-sans">
                <span className="text-[8px]">▾</span>
                <span>src</span>
              </div>
              <div className="bg-[#141418] border-l-2 border-[#0055FF] text-white flex items-center gap-1.5 py-0.5 pl-2 font-mono text-[9.5px]">
                <span className="w-1 h-1 bg-[#0055FF] rounded-none" />
                <span className="font-semibold truncate">crdt_sync.rs</span>
              </div>
              <div className="text-[#666666] flex items-center gap-1.5 py-0.5 pl-3 font-mono text-[9px] hover:text-white cursor-pointer">
                <span className="w-1 h-1 bg-[#333333] rounded-none" />
                <span className="truncate">peer_mesh.rs</span>
              </div>
              <div className="text-[#666666] flex items-center gap-1.5 py-0.5 pl-3 font-mono text-[9px] hover:text-white cursor-pointer">
                <span className="w-1 h-1 bg-[#333333] rounded-none" />
                <span className="truncate">webgpu.rs</span>
              </div>
              <div className="text-[#555555] flex items-center gap-1.5 py-0.5 pl-2 font-mono text-[9px]">
                <span>Cargo.toml</span>
              </div>
            </div>
          </div>

          {/* Active Peers Micro-List */}
          <div className="pt-2 border-t border-[#1c1c20] text-[8.5px] space-y-1">
            <div className="text-[#555555] uppercase font-bold tracking-wider">LIVE MESH</div>
            <div className="flex items-center justify-between text-[#06b6d4]">
              <span className="flex items-center gap-1">
                <span className="w-1 h-1 bg-[#06b6d4] rounded-none" />
                Tarika
              </span>
              <span className="text-[7.5px] text-[#666666]">{tarikaLatency}</span>
            </div>
            <div className="flex items-center justify-between text-[#f59e0b]">
              <span className="flex items-center gap-1">
                <span className="w-1 h-1 bg-[#f59e0b] rounded-none" />
                Pavan
              </span>
              <span className="text-[7.5px] text-[#666666]">{pavanLatency}</span>
            </div>
          </div>
        </div>

        {/* Main Code Editor Pane */}
        <div className="flex-1 flex flex-col min-w-0 bg-[#000000] relative">
          {/* Tab Bar */}
          <div className="h-6 bg-[#09090c] border-b border-[#222222] flex items-center justify-between px-2 shrink-0">
            <div className="flex items-center h-full">
              {/* Active Tab */}
              <div className="h-full px-2.5 bg-[#000000] border-r border-[#222222] border-t-2 border-t-[#0055FF] text-white flex items-center gap-1.5 text-[10px] font-mono">
                <FileCode2 className="w-3 h-3 text-[#0055FF]" />
                <span className="font-semibold">crdt_sync.rs</span>
                <span className="w-1.5 h-1.5 rounded-full bg-[#f59e0b] ml-1" title="Live peer editing" />
                <span className="text-[#666666] hover:text-white cursor-pointer ml-1">×</span>
              </div>
              {/* Inactive Tab */}
              <div className="h-full px-2.5 text-[#666666] hover:text-white flex items-center gap-1.5 text-[10px] font-mono cursor-pointer border-r border-[#222222]/40 hidden sm:flex">
                <span>peer_mesh.rs</span>
              </div>
            </div>

            <div className="flex items-center gap-2 text-[#666666]">
              <SplitSquareVertical className="w-3 h-3 hover:text-white cursor-pointer" />
              <Play className="w-3 h-3 hover:text-[#0055FF] cursor-pointer text-[#0055FF]" />
            </div>
          </div>

          {/* Real Code Buffer Canvas with Live Cursor Motion */}
          <div className="flex-1 p-2 sm:p-3 overflow-hidden relative font-mono text-[11px] leading-[1.65] bg-[#000000]">
            {/* Subtle Hardware Matrix Background Pattern */}
            <div className="absolute inset-0 opacity-[0.025] bg-[linear-gradient(to_right,#ffffff_1px,transparent_1px),linear-gradient(to_bottom,#ffffff_1px,transparent_1px)] bg-[size:16px_16px] pointer-events-none" />

            {/* ============================================================== */}
            {/* COLLABORATOR 1: TARIKA'S LIVE DART CURSOR & SELECTION HIGHLIGHT */}
            {/* ============================================================== */}
            <motion.div
              className="absolute pointer-events-none z-30 flex items-start gap-1 select-none"
              animate={{
                x: [68, 140, 220, 160, 92, 68],
                y: [42, 46, 64, 44, 40, 42],
              }}
              transition={{
                duration: 6.8,
                repeat: Infinity,
                ease: "easeInOut",
              }}
            >
              {/* Precision Vector Dart Arrow with crisp 1.4px white border */}
              <svg width="18" height="20" viewBox="0 0 16 16" fill="none" className="overflow-visible drop-shadow-[0_2px_6px_rgba(0,0,0,0.9)]">
                <path
                  d="M0 0L6 14L8.5 8.5L14 6L0 0Z"
                  fill="#06b6d4"
                  stroke="#FFFFFF"
                  strokeWidth="1.4"
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              </svg>
              {/* Collaborator Pill Tag */}
              <div className="px-1.5 py-[2px] bg-[#06b6d4] text-black text-[9px] font-sans font-bold uppercase tracking-wider flex items-center gap-1 border border-white shadow-[0_2px_8px_rgba(6,182,212,0.4)]">
                <span>Tarika</span>
              </div>
            </motion.div>

            {/* ============================================================== */}
            {/* COLLABORATOR 2: PAVAN'S LIVE DART CURSOR & REAL-TIME TYPING     */}
            {/* ============================================================== */}
            <motion.div
              className="absolute pointer-events-none z-30 flex items-start gap-1 select-none"
              animate={{
                x: [110, 175, 260, 210, 150, 110],
                y: [86, 88, 92, 90, 86, 86],
              }}
              transition={{
                duration: 7.6,
                repeat: Infinity,
                ease: "easeInOut",
                delay: 0.3,
              }}
            >
              {/* Precision Vector Dart Arrow with crisp 1.4px white border */}
              <svg width="18" height="20" viewBox="0 0 16 16" fill="none" className="overflow-visible drop-shadow-[0_2px_6px_rgba(0,0,0,0.9)]">
                <path
                  d="M0 0L6 14L8.5 8.5L14 6L0 0Z"
                  fill="#f59e0b"
                  stroke="#FFFFFF"
                  strokeWidth="1.4"
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              </svg>
              {/* Collaborator Pill Tag with Typing Bounce */}
              <div className="px-1.5 py-[2px] bg-[#f59e0b] text-black text-[9px] font-sans font-bold uppercase tracking-wider flex items-center gap-1 border border-white shadow-[0_2px_8px_rgba(245,158,11,0.4)]">
                <span>Pavan</span>
                {isTyping && (
                  <span className="flex items-center gap-0.5 ml-0.5">
                    <span className="w-1 h-1 bg-black rounded-none animate-bounce [animation-delay:-0.3s]" />
                    <span className="w-1 h-1 bg-black rounded-none animate-bounce [animation-delay:-0.15s]" />
                    <span className="w-1 h-1 bg-black rounded-none animate-bounce" />
                  </span>
                )}
              </div>
            </motion.div>

            {/* CODE LINES WITH REAL HIGH-CONTRAST SYNTAX & MULTIPLAYER HIGHLIGHTS */}
            <div className="space-y-0.5 relative z-10">
              {/* Line 01 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">01</span>
                <span className="text-[#555555] italic">// Crux AST-CRDT Mesh Synchronization</span>
              </div>

              {/* Line 02 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">02</span>
                <span className="text-[#0055FF] font-semibold">pub async fn</span>
                <span className="text-white font-medium pl-1.5">replicate_ast_stream</span>
                <span className="text-[#71717a]">(ctx: &amp;mut MeshCtx) -&gt; Result&lt;()&gt; &#123;</span>
              </div>

              {/* Line 03: Tarika's Active Multi-line Selection Highlight */}
              <div className="flex items-center relative bg-[#06b6d4]/10 border-l-2 border-[#06b6d4] pl-0.5">
                <span className="w-6 text-right text-[10px] text-[#06b6d4] font-bold select-none pr-3">03</span>
                <span className="text-white pl-3">
                  <span className="text-[#0055FF]">let mut</span> ring = ctx.acquire_ring_buffer(<span className="text-[#22c55e]">64 * 1024</span>).<span className="text-[#0055FF]">await</span>?;
                </span>
                <span className="ml-auto text-[8.5px] font-mono text-[#06b6d4] uppercase tracking-wider font-semibold pr-2 hidden md:inline select-none">
                  [Tarika selecting]
                </span>
              </div>

              {/* Line 04 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">04</span>
                <span className="text-white pl-4">
                  <span className="text-[#0055FF]">let</span> ast_delta = ring.converge_peer_mutations()?;
                </span>
              </div>

              {/* Line 05: Pavan's Live Typing Line with Real Characters & Blinking Caret */}
              <div className="flex items-center relative bg-[#f59e0b]/10 border-l-2 border-[#f59e0b] pl-0.5">
                <span className="w-6 text-right text-[10px] text-[#f59e0b] font-bold select-none pr-3">05</span>
                <span className="text-white pl-4 font-mono">
                  <span className="text-[#e4e4e7]">{targetCodeToType.slice(0, typedChars)}</span>
                  {/* Blinking 1px Caret */}
                  <motion.span
                    animate={{ opacity: [1, 0, 1] }}
                    transition={{ repeat: Infinity, duration: 0.5 }}
                    className="inline-block w-1.5 h-3.5 bg-[#f59e0b] ml-0.5 align-middle select-none"
                  />
                </span>
                <span className="ml-auto text-[8.5px] font-mono text-[#f59e0b] uppercase tracking-wider font-semibold pr-2 hidden md:inline select-none">
                  [Pavan typing]
                </span>
              </div>

              {/* Line 06 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">06</span>
                <span className="text-white pl-4">
                  <span className="text-[#0055FF]">Ok</span>(())
                </span>
              </div>

              {/* Line 07 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">07</span>
                <span className="text-[#71717a]">&#125;</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 3. REAL CRUX STATUS BAR */}
      {showStatusBar && (
        <div className="h-6 px-3 bg-[#08080a] border-t border-[#222222] flex items-center justify-between text-[10px] font-mono text-[#888888] select-none shrink-0">
          {/* Left Telemetry */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-white font-medium">
              <GitBranch className="w-3 h-3 text-[#0055FF]" />
              <span>main*</span>
            </div>

            <span className="text-[#333333]">|</span>

            <div className="flex items-center gap-1.5 text-[#22c55e]">
              <span className="w-1.5 h-1.5 bg-[#22c55e] rounded-none animate-pulse" />
              <span className="font-semibold">0 CONFLICTS</span>
            </div>

            <span className="text-[#333333] hidden sm:inline">|</span>

            <div className="hidden sm:flex items-center gap-1 text-[#888888]">
              <Wifi className="w-3 h-3 text-[#0055FF]" />
              <span>2 PEERS IN-SYNC</span>
            </div>
          </div>

          {/* Right Telemetry */}
          <div className="flex items-center gap-3">
            <div className="text-[#0055FF] font-semibold">
              <span>RTT: {tarikaLatency}</span>
            </div>

            <span className="text-[#333333] hidden sm:inline">|</span>

            <div className="hidden sm:inline text-[#71717a]">
              <span>Ln 5, Col {typedChars}</span>
            </div>

            <span className="text-[#333333]">|</span>

            <div className="flex items-center gap-1 text-white font-bold">
              <Cpu className="w-3 h-3 text-[#0055FF]" />
              <span>120 FPS</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
