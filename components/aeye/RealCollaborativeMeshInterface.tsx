"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  FolderOpen,
  Plus,
  Download,
  Search,
  Share2,
  Clock,
  GitBranch,
} from "lucide-react";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";
import CruxPointerCursor from "@/components/crux/CruxPointerCursor";

export type CruxIdeMode =
  | "multiplayer"
  | "silicon"
  | "crdt"
  | "agents"
  | "context"
  | "processing"
  | "output";

interface RealCollaborativeMeshInterfaceProps {
  mode?: CruxIdeMode;
  showHeader?: boolean;
  showStatusBar?: boolean;
}

export default function RealCollaborativeMeshInterface({
  mode = "multiplayer",
  showHeader = true,
  showStatusBar = true,
}: RealCollaborativeMeshInterfaceProps) {
  // Live typing simulation on line 6 by Muhaymin (for multiplayer/crdt/processing)
  const [typedSuffix, setTypedSuffix] = useState("");
  const [muhayminStatus, setMuhayminStatus] = useState<"idle" | "typing" | "selecting">("idle");
  const [cursorPosCol, setCursorPosCol] = useState(22);

  // Cycling interaction loop directly mirroring real live collaborative typing
  useEffect(() => {
    let timeout: NodeJS.Timeout;
    const targetText = " Hr";
    let index = 0;
    let loopMode: "typing" | "pausing" | "erasing" | "selecting" = "typing";

    const runLoop = () => {
      if (loopMode === "typing") {
        setMuhayminStatus("typing");
        if (index < targetText.length) {
          index += 1;
          setTypedSuffix(targetText.slice(0, index));
          setCursorPosCol(22 + index);
          timeout = setTimeout(runLoop, 220);
        } else {
          loopMode = "pausing";
          setMuhayminStatus("idle");
          timeout = setTimeout(runLoop, 2400);
        }
      } else if (loopMode === "pausing") {
        loopMode = "selecting";
        setMuhayminStatus("selecting");
        timeout = setTimeout(runLoop, 2200);
      } else if (loopMode === "selecting") {
        loopMode = "erasing";
        setMuhayminStatus("typing");
        timeout = setTimeout(runLoop, 400);
      } else if (loopMode === "erasing") {
        if (index > 0) {
          index -= 1;
          setTypedSuffix(targetText.slice(0, index));
          setCursorPosCol(22 + index);
          timeout = setTimeout(runLoop, 140);
        } else {
          loopMode = "typing";
          setMuhayminStatus("idle");
          timeout = setTimeout(runLoop, 1200);
        }
      }
    };

    timeout = setTimeout(runLoop, 800);
    return () => clearTimeout(timeout);
  }, []);

  // Determine active tab name, file tree highlights, and header badges per mode
  const getTabTitle = () => {
    switch (mode) {
      case "silicon":
        return "SPATIAL_ENGINE.TS";
      case "crdt":
        return "AST_CRDT_SYNC.TS";
      case "agents":
        return "DATABASE.TS";
      case "context":
        return "KERNEL_SIGNALS.TS";
      case "processing":
        return "STREAM_SYNCER.TS";
      case "output":
        return "AUTH.TS";
      case "multiplayer":
      default:
        return "STREAM_SYNCER.TS";
    }
  };

  const getSecondaryTabTitle = () => {
    switch (mode) {
      case "silicon":
        return "PHOSPHOR.METAL";
      case "crdt":
      case "context":
        return "TYPES.TS";
      case "agents":
      case "output":
        return "STREAM_SYNCER.TS";
      case "processing":
      case "multiplayer":
      default:
        return "DATABASE.TS";
    }
  };

  const getLiveBadge = () => {
    switch (mode) {
      case "silicon":
        return (
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#0055FF] pr-1 font-semibold">
            <span className="w-1.5 h-1.5 bg-[#0055FF] inline-block animate-pulse" />
            <span>120 FPS VSYNC</span>
          </div>
        );
      case "crdt":
        return (
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#22c55e] pr-1 font-semibold">
            <span className="w-1.5 h-1.5 bg-[#22c55e] inline-block animate-pulse" />
            <span>0 COLLISION MESH</span>
          </div>
        );
      case "agents":
        return (
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-white pr-1 font-semibold">
            <span className="w-1.5 h-1.5 bg-white inline-block animate-ping" />
            <span>@CRUXAI ACTIVE</span>
          </div>
        );
      case "context":
        return (
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#0055FF] pr-1 font-semibold">
            <span className="w-1.5 h-1.5 bg-[#0055FF] inline-block animate-pulse" />
            <span>RAW POSIX INGEST</span>
          </div>
        );
      case "processing":
        return (
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#22c55e] pr-1 font-semibold">
            <span className="w-1.5 h-1.5 bg-[#22c55e] inline-block animate-pulse" />
            <span>AST TRANSFORM</span>
          </div>
        );
      case "output":
        return (
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-white pr-1 font-semibold">
            <span className="w-1.5 h-1.5 bg-[#22c55e] inline-block" />
            <span>NATIVE ARM64 COMPILED</span>
          </div>
        );
      case "multiplayer":
      default:
        return (
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#22c55e] pr-1 font-semibold">
            <span className="w-1.5 h-1.5 bg-[#22c55e] inline-block animate-pulse" />
            <span>LIVE MESH</span>
          </div>
        );
    }
  };

  const getTelemetryBanner = () => {
    switch (mode) {
      case "silicon":
        return (
          <div className="h-6 bg-[#09090c] border-b border-[#222222] px-3 flex items-center justify-between text-[10px] font-mono shrink-0 select-none overflow-hidden">
            <div className="flex items-center gap-2 truncate text-[#888888]">
              <span className="text-[#0055FF] font-bold">SILICON RUNTIME</span>
              <span className="text-[#666666]">·</span>
              <span className="text-white">METAL DMA PIPELINE</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#22c55e] font-semibold">120.0 FPS [LOCKED]</span>
            </div>
            <div className="text-[9px] text-[#0055FF] font-bold uppercase shrink-0">
              FRAME TIME: 4.18ms
            </div>
          </div>
        );
      case "crdt":
        return (
          <div className="h-6 bg-[#09090c] border-b border-[#222222] px-3 flex items-center justify-between text-[10px] font-mono shrink-0 select-none overflow-hidden">
            <div className="flex items-center gap-2 truncate text-[#888888]">
              <span className="text-white font-bold">AST-CRDT ENGINE</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#22c55e]">0 SYNTAX COLLISIONS</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#a1a1aa]">DELTA: 124 BYTES</span>
            </div>
            <div className="text-[9px] text-[#22c55e] font-bold uppercase shrink-0">
              P2P VERIFIED
            </div>
          </div>
        );
      case "agents":
        return (
          <div className="h-6 bg-[#09090c] border-b border-[#222222] px-3 flex items-center justify-between text-[10px] font-mono shrink-0 select-none overflow-hidden">
            <div className="flex items-center gap-2 truncate text-[#888888]">
              <span className="text-white font-bold">@CRUXAI KERNEL</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#0055FF] font-semibold">INLINE ZERO-COPY REFACTOR</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#a1a1aa]">142 TOKENS/SEC</span>
            </div>
            <div className="text-[9px] text-[#22c55e] font-bold uppercase shrink-0">
              0 OVERRUNS
            </div>
          </div>
        );
      case "context":
        return (
          <div className="h-6 bg-[#09090c] border-b border-[#222222] px-3 flex items-center justify-between text-[10px] font-mono shrink-0 select-none overflow-hidden">
            <div className="flex items-center gap-2 truncate text-[#888888]">
              <span className="text-white font-bold">CONTEXT AWARENESS</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#0055FF]">POSIX DIRECT INGEST</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#a1a1aa]">1,420 TOKENS/SEC</span>
            </div>
            <div className="text-[9px] text-[#0055FF] font-bold uppercase shrink-0">
              LATENCY: &lt;15ms
            </div>
          </div>
        );
      case "processing":
        return (
          <div className="h-6 bg-[#09090c] border-b border-[#222222] px-3 flex items-center justify-between text-[10px] font-mono shrink-0 select-none overflow-hidden">
            <div className="flex items-center gap-2 truncate text-[#888888]">
              <span className="text-white font-bold">PROCESSING KERNEL</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#22c55e]">AST SYNTHESIS: 100% VALID</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#a1a1aa]">ZERO LOCKS</span>
            </div>
            <div className="text-[9px] text-[#22c55e] font-bold uppercase shrink-0">
              3 PEERS SYNCED
            </div>
          </div>
        );
      case "output":
        return (
          <div className="h-6 bg-[#09090c] border-b border-[#222222] px-3 flex items-center justify-between text-[10px] font-mono shrink-0 select-none overflow-hidden">
            <div className="flex items-center gap-2 truncate text-[#888888]">
              <span className="text-white font-bold">ACTIONABLE OUTPUT</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#22c55e]">ARM64 MACH-O COMPILED</span>
              <span className="text-[#666666]">·</span>
              <span className="text-[#a1a1aa]">ATOMIC GIT DIFF</span>
            </div>
            <div className="text-[9px] text-white font-bold uppercase shrink-0">
              SHA256: 2784...
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  const getStatusBarText = () => {
    switch (mode) {
      case "silicon":
        return {
          left: "WEBGPU / METAL DMA",
          mid: "120.0 FPS [LOCKED]",
          right: "38MB RSS",
        };
      case "crdt":
        return {
          left: "P2P WEBRTC MESH",
          mid: "AST SYNC: 0.4ms",
          right: "ZERO LOCKS",
        };
      case "agents":
        return {
          left: "@CRUXAI KERNEL",
          mid: "4/4 SWARM DISPATCHED",
          right: "0ms IPC",
        };
      case "context":
        return {
          left: "POSIX DIRECT INGEST",
          mid: "14 FILES INDEXED",
          right: "SUB-15ms IO",
        };
      case "processing":
        return {
          left: "AST CONVERGENCE",
          mid: "0 COLLISIONS",
          right: "3 PEERS SYNCED",
        };
      case "output":
        return {
          left: "ARM64 NATIVE COMPILE",
          mid: "GIT HEAD (main*)",
          right: "0 ERRORS",
        };
      case "multiplayer":
      default:
        return {
          left: "DISK IN-SYNC 36ms",
          mid: "HISTORY (41)",
          right: `Ln 6, Col ${cursorPosCol}`,
        };
    }
  };

  const status = getStatusBarText();

  return (
    <div className="w-full h-full bg-[#000000] flex flex-col justify-between font-sans select-none overflow-hidden text-xs">
      {/* 1. CRUX DESKTOP TOP BAR (Clean, Minimalist Brutalism) */}
      {showHeader && (
        <header className="h-9 px-3 bg-[#0a0a0c] border-b border-[#222222] flex items-center justify-between shrink-0 select-none">
          {/* Left: Window Dots + Crux Logo + Mode Switcher */}
          <div className="flex items-center gap-3">
            {/* Brutalist window control dots */}
            <div className="flex items-center gap-1.5 shrink-0">
              <span className="w-2.5 h-2.5 rounded-full bg-[#ff5f56]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#27c93f]" />
            </div>

            <div className="w-[1px] h-3.5 bg-[#222222]" />

            {/* Crux Wordmark */}
            <div className="flex items-center gap-2">
              <CruxBrandLogo size={16} withText={true} />
            </div>

            {/* Mode Switcher: [EDITOR] [CANVAS] */}
            <div className="flex items-center border border-[#222222] bg-[#000000] text-[10px] font-mono">
              <span className="px-2 py-0.5 bg-[#141418] text-white font-bold border-r border-[#222222]">
                EDITOR
              </span>
              <span className="px-2 py-0.5 text-[#555555] hover:text-white cursor-pointer">
                CANVAS
              </span>
            </div>
          </div>

          {/* Right: Active Collaborators (Hrushikesh Gangala & Muhaymin) + Share */}
          <div className="flex items-center gap-2">
            {/* Peer 1: Hrushikesh Gangala (Host) */}
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#111114] border border-[#222222] text-[11px] text-white font-sans">
              <div className="w-3.5 h-3.5 rounded-full bg-[#007AFF] flex items-center justify-center text-[8px] font-bold text-white shrink-0">
                HG
              </div>
              <span className="truncate max-w-[120px] font-medium hidden sm:inline">Hrushikesh Gangala</span>
            </div>

            {/* Peer 2: Muhaymin (Active in multiplayer/crdt/processing modes) */}
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#111114] border border-[#222222] text-[11px] text-white font-sans">
              <div className="w-3.5 h-3.5 rounded-full bg-white text-black flex items-center justify-center text-[8px] font-bold shrink-0">
                M
              </div>
              <span className="truncate max-w-[80px] font-medium hidden sm:inline">Muhaymin</span>
            </div>

            {/* Share Button */}
            <div className="px-2.5 py-0.5 bg-[#000000] border border-white text-white font-sans text-[10px] font-semibold uppercase flex items-center gap-1 cursor-pointer hover:bg-white hover:text-black transition-none ml-1">
              <Share2 className="w-2.5 h-2.5" />
              <span>SHARE</span>
            </div>
          </div>
        </header>
      )}

      {/* 2. CRUX MENU BAR */}
      <div className="h-5 bg-[#060608] border-b border-[#1a1a1e] flex items-center px-3 gap-3 text-[11px] font-sans text-[#777777] select-none shrink-0 overflow-x-auto">
        <span className="text-white hover:text-white cursor-pointer">File</span>
        <span className="hover:text-white cursor-pointer">Edit</span>
        <span className="hover:text-white cursor-pointer">Selection</span>
        <span className="hover:text-white cursor-pointer">View</span>
        <span className="hover:text-white cursor-pointer">Go</span>
        <span className="hover:text-white cursor-pointer">Run</span>
        <span className="hover:text-white cursor-pointer">Terminal</span>
        <span className="hover:text-white cursor-pointer">Help</span>
      </div>

      {/* 3. MAIN WORKSPACE (EXPLORER SIDEBAR + FULL CODE EDITOR PANE) */}
      <div className="flex-1 flex overflow-hidden min-h-0 bg-[#000000]">
        {/* Left Explorer Sidebar */}
        <div className="w-36 sm:w-44 bg-[#0a0a0c] border-r border-[#222222] p-2 flex flex-col justify-between shrink-0 select-none hidden sm:flex">
          <div>
            {/* Explorer Header */}
            <div className="text-[10px] font-mono text-[#888888] font-bold pb-1.5 border-b border-[#1a1a1e] flex items-center justify-between mb-2">
              <span>EXPLORER</span>
              <div className="flex items-center gap-1.5 text-[#555555]">
                <Plus className="w-3 h-3 hover:text-white cursor-pointer" />
                <Download className="w-3 h-3 hover:text-white cursor-pointer" />
                <Search className="w-3 h-3 hover:text-white cursor-pointer" />
              </div>
            </div>

            {/* Quick Import Buttons */}
            <div className="space-y-1 mb-2">
              <div className="w-full py-1 px-1.5 bg-[#ffffff] text-black text-[9px] font-mono font-bold uppercase flex items-center gap-1 cursor-pointer">
                <span>+ IMPORT FOLDER</span>
              </div>
              <div className="w-full py-1 px-1.5 border border-[#333333] text-white text-[9px] font-mono font-bold uppercase flex items-center gap-1 cursor-pointer">
                <span>+ IMPORT FILES</span>
              </div>
            </div>

            {/* File Tree */}
            <div className="space-y-1 text-[10px] font-mono">
              {/* SRC Folder */}
              <div>
                <div className="text-[#888888] flex items-center gap-1 py-0.5">
                  <FolderOpen className="w-3 h-3 text-[#666666]" />
                  <span className="font-semibold text-white">SRC</span>
                </div>
                <div className="pl-3 space-y-0.5 text-[#777777]">
                  {/* spatialEngine.ts */}
                  <div
                    className={`flex items-center gap-1.5 py-0.5 px-1 truncate cursor-pointer ${
                      mode === "silicon"
                        ? "bg-[#141418] border-l-2 border-[#007AFF] text-white font-semibold"
                        : "hover:text-white text-[#777777]"
                    }`}
                  >
                    <span className="text-[9px] text-[#007AFF]">JS</span>
                    <span className="truncate">canvas/spatialEngine.ts</span>
                  </div>
                  <div className="flex items-center gap-1.5 py-0.5 hover:text-white cursor-pointer truncate">
                    <span className="text-[9px] text-[#444444]">☕</span>
                    <span className="truncate">Practice.java</span>
                  </div>
                  {/* types.ts */}
                  <div
                    className={`flex items-center gap-1.5 py-0.5 px-1 truncate cursor-pointer ${
                      mode === "crdt" || mode === "context"
                        ? "bg-[#141418] border-l-2 border-[#007AFF] text-white font-semibold"
                        : "hover:text-white text-[#777777]"
                    }`}
                  >
                    <span className="text-[9px] text-[#007AFF]">JS</span>
                    <span className="truncate">types.ts</span>
                  </div>
                </div>
              </div>

              {/* ROOT FILES Folder */}
              <div className="pt-1">
                <div className="text-[#888888] flex items-center gap-1 py-0.5">
                  <FolderOpen className="w-3 h-3 text-[#666666]" />
                  <span className="font-semibold text-white">ROOT FILES</span>
                </div>
                <div className="pl-3 space-y-0.5">
                  {/* auth.ts */}
                  <div
                    className={`flex items-center gap-1.5 py-0.5 px-1 truncate cursor-pointer ${
                      mode === "output"
                        ? "bg-[#141418] border-l-2 border-[#007AFF] text-white font-semibold"
                        : "hover:text-white text-[#777777]"
                    }`}
                  >
                    <span className="text-[9px] text-[#007AFF]">JS</span>
                    <span className="truncate">auth.ts</span>
                  </div>
                  {/* database.ts */}
                  <div
                    className={`flex items-center gap-1.5 py-0.5 px-1 truncate cursor-pointer ${
                      mode === "multiplayer" || mode === "agents"
                        ? "bg-[#141418] border-l-2 border-[#007AFF] text-white font-semibold"
                        : "hover:text-white text-[#777777]"
                    }`}
                  >
                    <span className="text-[9px] text-[#007AFF]">JS</span>
                    <span className="truncate">database.ts</span>
                  </div>
                  {/* stream_syncer.ts */}
                  <div
                    className={`flex items-center gap-1.5 py-0.5 px-1 truncate cursor-pointer ${
                      mode === "processing"
                        ? "bg-[#141418] border-l-2 border-[#007AFF] text-white font-semibold"
                        : "hover:text-white text-[#777777]"
                    }`}
                  >
                    <span className="text-[9px] text-[#007AFF]">JS</span>
                    <span className="truncate">stream_syncer.ts</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Main Code Editor Pane */}
        <div className="flex-1 flex flex-col min-w-0 bg-[#000000] relative">
          {/* Tab Strip - Clean, minimalist */}
          <div className="h-7 bg-[#111114] border-b border-[#222222] flex items-center justify-between px-2 shrink-0 select-none">
            <div className="flex items-center h-full">
              <div className="h-full px-3 bg-[#000000] border-r border-[#222222] text-white flex items-center gap-2 text-[11px] font-sans uppercase font-bold tracking-tight">
                <span>{getTabTitle()}</span>
                <span className="w-1.5 h-1.5 bg-white shrink-0" title="Active" />
              </div>
              <div className="h-full px-3 text-[#555555] hover:text-white hidden sm:flex items-center gap-2 text-[11px] font-sans uppercase tracking-tight cursor-pointer">
                <span>{getSecondaryTabTitle()}</span>
              </div>
            </div>

            {/* Subtle live sync status */}
            {getLiveBadge()}
          </div>

          {/* Optional Telemetry Banner */}
          {getTelemetryBanner()}

          {/* Real Code Buffer Canvas with Live Multiplayer Cursor Motion */}
          <div className="flex-1 p-3 overflow-hidden relative font-mono text-[11px] sm:text-[12px] leading-[1.7] bg-[#000000]">
            {/* Subtle Hardware Matrix Pattern */}
            <div className="absolute inset-0 opacity-[0.02] bg-[linear-gradient(to_right,#ffffff_1px,transparent_1px),linear-gradient(to_bottom,#ffffff_1px,transparent_1px)] bg-[size:16px_16px] pointer-events-none" />

            {/* REMOTE PEER 1: MUHAYMIN DART CURSOR (Rendered in multiplayer, crdt, and processing modes) */}
            {(mode === "multiplayer" || mode === "crdt" || mode === "processing") && (
              <motion.div
                className="absolute pointer-events-none z-30 select-none"
                animate={{
                  x: [180, 240, 290, 260, 200, 180],
                  y: [86, 88, 92, 90, 88, 86],
                }}
                transition={{
                  duration: 6.8,
                  repeat: Infinity,
                  ease: "easeInOut",
                }}
              >
                <CruxPointerCursor
                  name="Muhaymin"
                  uid="MUHAYMIN"
                  color="#FFFFFF"
                  status={muhayminStatus === "typing" ? "typing" : muhayminStatus === "selecting" ? "selecting" : undefined}
                />
              </motion.div>
            )}

            {/* REMOTE PEER 2: HRUSHIKESH GANGALA DART CURSOR */}
            <motion.div
              className="absolute pointer-events-none z-30 select-none hidden md:block"
              animate={{
                x: [240, 310, 380, 330, 260, 240],
                y: [168, 172, 178, 174, 170, 168],
              }}
              transition={{
                duration: 7.4,
                repeat: Infinity,
                ease: "easeInOut",
                delay: 0.4,
              }}
            >
              <CruxPointerCursor
                name="Hrushikesh Gangala"
                uid="CRX-7447-HG"
                color="#007AFF"
                status="typing"
              />
            </motion.div>

            {/* ============================================================== */}
            {/* DYNAMIC CODE BUFFER BASED ON ACTIVE MODE                        */}
            {/* ============================================================== */}
            <div className="space-y-0.5 relative z-10 text-[11px] sm:text-[12px] leading-[1.65]">
              {/* MODE 1: MULTIPLAYER (Live Database WAL persistent store) */}
              {mode === "multiplayer" && (
                <>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">import</span> &#123; <span className="text-white font-medium">LocalWriteAheadLog</span> &#125; <span className="text-[#007AFF] font-semibold">from</span> <span className="text-[#ff914d]">"@crux/wal"</span>;
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">import</span> &#123; <span className="text-white font-medium">SyncVector</span> &#125; <span className="text-[#007AFF] font-semibold">from</span> <span className="text-[#ff914d]">"./types"</span>;
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">3</span>
                    <span className="text-[#888888] italic">// Monotonic local-first persistent write-ahead store</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">4</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">export const</span> wal = <span className="text-[#007AFF] font-semibold">new</span> LocalWriteAheadLog(&#123;
                    </span>
                  </div>
                  <div className="flex items-center relative bg-[#ffffff]/5 pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">5</span>
                    <span className="text-white pl-3 font-mono">
                      path: <span className="text-[#ff914d]">"/var/crux/wal.bin"</span>,{typedSuffix}
                      <motion.span
                        animate={{ opacity: [1, 0, 1] }}
                        transition={{ repeat: Infinity, duration: 0.6 }}
                        className="w-1.5 h-3.5 bg-white inline-block ml-0.5 align-middle"
                      />
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">6</span>
                    <span className="text-white pl-3">syncIntervalMs: <span className="text-[#ffbd2e]">16</span>, ringBufferSizeMb: <span className="text-[#ffbd2e]">64</span></span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">7</span>
                    <span className="text-white">&#125;);</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">8</span>
                    <span className="text-[#888888] italic">// Monotonic state vector persistence vector</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">9</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">export async function</span> <span className="text-[#ff914d]">persistStateVector</span>(
                    </span>
                  </div>
                  <div className={`flex items-center relative pl-0.5 ${muhayminStatus === "selecting" ? "bg-[#007AFF]/20 border-l-2 border-[#007AFF]" : ""}`}>
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">10</span>
                    <span className="text-white pl-3">docId: <span className="text-[#007AFF]">string</span>, vector: <span className="text-[#007AFF]">SyncVector</span></span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">11</span>
                    <span className="text-white">): <span className="text-[#007AFF]">Promise</span>&lt;<span className="text-[#ffbd2e]">number</span>&gt; &#123;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">12</span>
                    <span className="text-white pl-3">const bytes = vector.encode();</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">13</span>
                    <span className="text-white pl-3">const monotonicSequence = <span className="text-[#007AFF] font-semibold">await</span> wal.append(&#123; docId, payload: bytes &#125;);</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">14</span>
                    <span className="text-white pl-3"><span className="text-[#007AFF] font-semibold">return</span> monotonicSequence;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">15</span>
                    <span className="text-white">&#125;</span>
                  </div>
                </>
              )}

              {/* MODE 2: SILICON (Native Metal & WebGPU DMA Rasterization) */}
              {mode === "silicon" && (
                <>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">import</span> &#123; <span className="text-white font-medium">WebGPUDevice, MetalPipeline</span> &#125; <span className="text-[#007AFF] font-semibold">from</span> <span className="text-[#ff914d]">"@crux/engine"</span>;
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                    <span className="text-[#888888] italic">// Direct hardware rasterization bypassing Chromium DOM &amp; Electron</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">3</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">export class</span> <span className="text-white font-bold">SpatialEngine</span> &#123;
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">4</span>
                    <span className="text-white pl-3">private pipeline: <span className="text-[#007AFF]">MetalPipeline</span>;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">5</span>
                    <span className="text-white pl-3"><span className="text-[#007AFF] font-semibold">constructor</span>(device: <span className="text-[#007AFF]">WebGPUDevice</span>) &#123;</span>
                  </div>
                  <div className="flex items-center bg-[#0055FF]/10 border-l-2 border-[#0055FF] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">6</span>
                    <span className="text-white pl-6">
                      this.pipeline = device.createRenderPipeline(&#123;
                    </span>
                  </div>
                  <div className="flex items-center bg-[#0055FF]/10 border-l-2 border-[#0055FF] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">7</span>
                    <span className="text-white pl-9">
                      fragmentShader: <span className="text-[#ff914d]">"phosphor_mono.metal"</span>,
                    </span>
                  </div>
                  <div className="flex items-center bg-[#0055FF]/10 border-l-2 border-[#0055FF] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">8</span>
                    <span className="text-white pl-9">
                      frameRateTarget: <span className="text-[#22c55e] font-bold">120</span>, <span className="text-[#888888]">// Hardware vsync locked</span>
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">9</span>
                    <span className="text-white pl-6">&#125;);</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">10</span>
                    <span className="text-white pl-3">&#125;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">11</span>
                    <span className="text-white pl-3">
                      <span className="text-[#007AFF] font-semibold">renderBuffer</span>(buffer: <span className="text-[#007AFF]">Uint8Array</span>): <span className="text-[#007AFF]">void</span> &#123;
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">12</span>
                    <span className="text-white pl-6"><span className="text-[#888888]">// Zero-copy direct DMA blit to display phosphor at 120 FPS</span></span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">13</span>
                    <span className="text-white pl-6">this.pipeline.blitZeroCopy(buffer);</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">14</span>
                    <span className="text-white pl-3">&#125;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">15</span>
                    <span className="text-white">&#125;</span>
                  </div>
                </>
              )}

              {/* MODE 3: CRDT (Zero-Lock AST Delta Convergence) */}
              {mode === "crdt" && (
                <>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">import</span> &#123; <span className="text-white font-medium">ASTNode, SyncVector, applyStructuralDelta</span> &#125; <span className="text-[#007AFF] font-semibold">from</span> <span className="text-[#ff914d]">"./types"</span>;
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                    <span className="text-[#888888] italic">// Zero-lock AST-level conflict-free convergence over WebRTC</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">3</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">export function</span> <span className="text-[#ff914d]">mergeASTVectors</span>(
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">4</span>
                    <span className="text-white pl-3">localVector: <span className="text-[#007AFF]">SyncVector</span>, remoteDelta: <span className="text-[#007AFF]">Uint8Array</span></span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">5</span>
                    <span className="text-white">): <span className="text-[#007AFF]">ASTNode</span> &#123;</span>
                  </div>
                  <div className="flex items-center bg-[#22c55e]/10 border-l-2 border-[#22c55e] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">6</span>
                    <span className="text-white pl-3">
                      const delta = SyncVector.decode(remoteDelta);
                    </span>
                  </div>
                  <div className="flex items-center bg-[#22c55e]/10 border-l-2 border-[#22c55e] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">7</span>
                    <span className="text-white pl-3">
                      <span className="text-[#888888]">// Structural AST delta applied monotonically without syntax breakage</span>
                    </span>
                  </div>
                  <div className="flex items-center bg-[#22c55e]/10 border-l-2 border-[#22c55e] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">8</span>
                    <span className="text-white pl-3">
                      const convergedTree = applyStructuralDelta(localVector, delta);
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">9</span>
                    <span className="text-white pl-3"><span className="text-[#007AFF] font-semibold">return</span> convergedTree;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">10</span>
                    <span className="text-white">&#125;</span>
                  </div>
                </>
              )}

              {/* MODE 4: AGENTS (@CruxAI Autonomous Inline Refactor Swarm) */}
              {mode === "agents" && (
                <>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">export async function</span> <span className="text-[#ff914d]">persistStateVector</span>(docId: <span className="text-[#007AFF]">string</span>, bytes: <span className="text-[#007AFF]">Uint8Array</span>) &#123;
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                    <span className="text-[#888888] italic">// @CruxAI Speculative Optimization: Inlined memory-mapped buffer arena</span>
                  </div>
                  {/* Removed old line */}
                  <div className="flex items-center bg-[#ff5f56]/15 border-l-2 border-[#ff5f56] text-[#ff5f56]">
                    <span className="w-6 text-right text-[10px] text-[#ff5f56] select-none pr-3">-</span>
                    <span className="pl-3 line-through">const sequence = await wal.append(&#123; docId, payload: bytes &#125;);</span>
                  </div>
                  {/* Added optimized line */}
                  <div className="flex items-center bg-[#22c55e]/15 border-l-2 border-[#22c55e] text-[#22c55e] font-semibold">
                    <span className="w-6 text-right text-[10px] text-[#22c55e] select-none pr-3">+</span>
                    <span className="pl-3">const sequence = await wal.appendZeroCopyBuffer(docId, bytes, &#123; fsync: false &#125;);</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">3</span>
                    <span className="text-white pl-3"><span className="text-[#007AFF] font-semibold">return</span> sequence;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">4</span>
                    <span className="text-white">&#125;</span>
                  </div>
                </>
              )}

              {/* MODE 5: CONTEXT (Context Awareness: Raw POSIX Signals Ingest) */}
              {mode === "context" && (
                <>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">export interface</span> <span className="text-white font-bold">KernelSignal</span> &#123;
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                    <span className="text-white pl-3">type: <span className="text-[#ff914d]">"keystroke"</span> | <span className="text-[#ff914d]">"ast_token"</span> | <span className="text-[#ff914d]">"fs_buffer"</span>;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">3</span>
                    <span className="text-white pl-3">timestampNs: <span className="text-[#007AFF]">bigint</span>; payload: <span className="text-[#007AFF]">Uint8Array</span>;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">4</span>
                    <span className="text-white">&#125;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">5</span>
                    <span className="text-[#888888] italic">// Ingest raw filesystem buffers directly into native host memory</span>
                  </div>
                  <div className="flex items-center bg-[#0055FF]/10 border-l-2 border-[#0055FF] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">6</span>
                    <span className="text-white pl-3"><span className="text-[#007AFF] font-semibold">export function</span> ingestKernelSignals(event: <span className="text-[#007AFF]">KernelSignal</span>): <span className="text-[#007AFF]">void</span> &#123;</span>
                  </div>
                  <div className="flex items-center bg-[#0055FF]/10 border-l-2 border-[#0055FF] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">7</span>
                    <span className="text-white pl-6">nativeHostBridge.streamSignal(event);</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">8</span>
                    <span className="text-white pl-3">&#125;</span>
                  </div>
                </>
              )}

              {/* MODE 6: PROCESSING (Intelligent Processing: Concurrent AST Synthesis) */}
              {mode === "processing" && (
                <>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                    <span className="text-[#888888] italic">// Synthesizes concurrent edits into conflict-free structural AST</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                    <span className="text-white">
                      <span className="text-[#007AFF] font-semibold">export async function</span> <span className="text-[#ff914d]">convergeStream</span>(
                    </span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">3</span>
                    <span className="text-white pl-3">docId: <span className="text-[#007AFF]">string</span>, peerDeltas: <span className="text-[#007AFF]">Uint8Array[]</span></span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">4</span>
                    <span className="text-white">): <span className="text-[#007AFF]">Promise</span>&lt;<span className="text-[#ffbd2e]">ASTValidation</span>&gt; &#123;</span>
                  </div>
                  <div className="flex items-center bg-[#22c55e]/10 border-l-2 border-[#22c55e] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">5</span>
                    <span className="text-white pl-3">const ast = <span className="text-[#007AFF] font-semibold">await</span> parseSyntaxTree(docId);</span>
                  </div>
                  <div className="flex items-center bg-[#22c55e]/10 border-l-2 border-[#22c55e] pl-0.5">
                    <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">6</span>
                    <span className="text-white pl-3">for (const delta of peerDeltas) &#123; ast.applyAtomic(delta); &#125;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">7</span>
                    <span className="text-white pl-3"><span className="text-[#007AFF] font-semibold">return</span> ast.validate();</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">8</span>
                    <span className="text-white">&#125;</span>
                  </div>
                </>
              )}

              {/* MODE 7: OUTPUT (Actionable Output: Atomic Git Diff & Verified Machine Binary) */}
              {mode === "output" && (
                <>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                    <span className="text-[#888888] italic">// Actionable native machine attestation</span>
                  </div>
                  <div className="flex items-center bg-[#ff5f56]/15 border-l-2 border-[#ff5f56] text-[#ff5f56]">
                    <span className="w-6 text-right text-[10px] text-[#ff5f56] select-none pr-3">-</span>
                    <span className="pl-3 line-through">export function verifySession(token: string): boolean;</span>
                  </div>
                  <div className="flex items-center bg-[#22c55e]/15 border-l-2 border-[#22c55e] text-[#22c55e] font-semibold">
                    <span className="w-6 text-right text-[10px] text-[#22c55e] select-none pr-3">+</span>
                    <span className="pl-3">export async function verifyEd25519Peer(token: string): Promise&lt;boolean&gt; &#123;</span>
                  </div>
                  <div className="flex items-center bg-[#22c55e]/15 border-l-2 border-[#22c55e] text-[#22c55e] font-semibold">
                    <span className="w-6 text-right text-[10px] text-[#22c55e] select-none pr-3">+</span>
                    <span className="pl-6">const isAttested = await crypto.subtle.verify("Ed25519", key, sig, token);</span>
                  </div>
                  <div className="flex items-center bg-[#22c55e]/15 border-l-2 border-[#22c55e] text-[#22c55e] font-semibold">
                    <span className="w-6 text-right text-[10px] text-[#22c55e] select-none pr-3">+</span>
                    <span className="pl-6">return isAttested;</span>
                  </div>
                  <div className="flex items-center">
                    <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                    <span className="text-white pl-3">&#125;</span>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 4. REAL CRUX STATUS BAR (Clean, Minimalist) */}
      {showStatusBar && (
        <footer className="h-6 px-3 bg-[#08080a] border-t border-[#222222] flex items-center justify-between text-[10px] font-mono text-[#888888] select-none shrink-0">
          {/* Left: Branch + Disk sync */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1 text-white font-medium">
              <GitBranch className="w-3 h-3 text-[#007AFF]" />
              <span>main*</span>
            </div>

            <span className="text-[#333333]">·</span>

            <div className="flex items-center gap-1 text-[#22c55e]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] animate-pulse" />
              <span>{status.left}</span>
            </div>
          </div>

          {/* Center: Metric / History */}
          <div className="hidden sm:flex items-center gap-1 text-[#888888]">
            <Clock className="w-3 h-3" />
            <span>{status.mid}</span>
          </div>

          {/* Right: Telemetry, UTF-8, TYPESCRIPT */}
          <div className="flex items-center gap-3">
            <span>{status.right}</span>
            <span className="text-[#333333] hidden sm:inline">·</span>
            <span className="hidden sm:inline">UTF-8</span>
            <span className="text-[#333333]">·</span>
            <span className="text-white font-bold">TYPESCRIPT</span>
          </div>
        </footer>
      )}
    </div>
  );
}
