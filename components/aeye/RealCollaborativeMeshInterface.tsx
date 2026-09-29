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

interface RealCollaborativeMeshInterfaceProps {
  showHeader?: boolean;
  showStatusBar?: boolean;
}

export default function RealCollaborativeMeshInterface({
  showHeader = true,
  showStatusBar = true,
}: RealCollaborativeMeshInterfaceProps) {
  // Live typing simulation on line 6 by Muhaymin
  const [typedSuffix, setTypedSuffix] = useState("");
  const [muhayminStatus, setMuhayminStatus] = useState<"idle" | "typing" | "selecting">("idle");
  const [cursorPosCol, setCursorPosCol] = useState(22);

  // Cycling interaction loop directly mirroring real live collaborative typing
  useEffect(() => {
    let timeout: NodeJS.Timeout;
    const targetText = " Hr";
    let index = 0;
    let mode: "typing" | "pausing" | "erasing" | "selecting" = "typing";

    const runLoop = () => {
      if (mode === "typing") {
        setMuhayminStatus("typing");
        if (index < targetText.length) {
          index += 1;
          setTypedSuffix(targetText.slice(0, index));
          setCursorPosCol(22 + index);
          timeout = setTimeout(runLoop, 220);
        } else {
          mode = "pausing";
          setMuhayminStatus("idle");
          timeout = setTimeout(runLoop, 2400);
        }
      } else if (mode === "pausing") {
        mode = "selecting";
        setMuhayminStatus("selecting");
        timeout = setTimeout(runLoop, 2200);
      } else if (mode === "selecting") {
        mode = "erasing";
        setMuhayminStatus("typing");
        timeout = setTimeout(runLoop, 400);
      } else if (mode === "erasing") {
        if (index > 0) {
          index -= 1;
          setTypedSuffix(targetText.slice(0, index));
          setCursorPosCol(22 + index);
          timeout = setTimeout(runLoop, 140);
        } else {
          mode = "typing";
          setMuhayminStatus("idle");
          timeout = setTimeout(runLoop, 1200);
        }
      }
    };

    timeout = setTimeout(runLoop, 800);
    return () => clearTimeout(timeout);
  }, []);

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

            {/* Peer 2: Muhaymin */}
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
                  <div className="flex items-center gap-1.5 py-0.5 hover:text-white cursor-pointer truncate">
                    <span className="text-[9px] text-[#444444]">JS</span>
                    <span className="truncate">canvas/spatialEngine.ts</span>
                  </div>
                  <div className="flex items-center gap-1.5 py-0.5 hover:text-white cursor-pointer truncate">
                    <span className="text-[9px] text-[#444444]">☕</span>
                    <span className="truncate">Practice.java</span>
                  </div>
                  <div className="flex items-center gap-1.5 py-0.5 hover:text-white cursor-pointer truncate">
                    <span className="text-[9px] text-[#444444]">JS</span>
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
                  <div className="flex items-center gap-1.5 py-0.5 text-[#777777] hover:text-white cursor-pointer truncate">
                    <span className="text-[9px] text-[#444444]">JS</span>
                    <span className="truncate">auth.ts</span>
                  </div>
                  {/* database.ts (Active file) */}
                  <div className="flex items-center gap-1.5 py-0.5 px-1 bg-[#141418] border-l-2 border-[#007AFF] text-white font-semibold cursor-pointer truncate">
                    <span className="text-[9px] text-[#007AFF]">JS</span>
                    <span className="truncate">database.ts</span>
                  </div>
                  <div className="flex items-center gap-1.5 py-0.5 text-[#777777] hover:text-white cursor-pointer truncate">
                    <span className="text-[9px] text-[#444444]">JS</span>
                    <span className="truncate">stream_syncer.ts</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Main Code Editor Pane */}
        <div className="flex-1 flex flex-col min-w-0 bg-[#000000] relative">
          {/* Tab Strip - Clean, minimalist, without hardware view, run, share link */}
          <div className="h-7 bg-[#111114] border-b border-[#222222] flex items-center justify-between px-2 shrink-0 select-none">
            <div className="flex items-center h-full">
              <div className="h-full px-3 bg-[#000000] border-r border-[#222222] text-white flex items-center gap-2 text-[11px] font-sans uppercase font-bold tracking-tight">
                <span>STREAM_SYNCER.TS</span>
                <span className="w-1.5 h-1.5 bg-white shrink-0" title="Active" />
              </div>
              <div className="h-full px-3 text-[#555555] hover:text-white hidden sm:flex items-center gap-2 text-[11px] font-sans uppercase tracking-tight cursor-pointer">
                <span>DATABASE.TS</span>
              </div>
            </div>

            {/* Subtle live sync status */}
            <div className="flex items-center gap-2 text-[10px] font-mono text-[#71717a] pr-1">
              <span className="w-1.5 h-1.5 bg-[#22c55e] inline-block animate-pulse" />
              <span>LIVE MESH</span>
            </div>
          </div>

          {/* Real Code Buffer Canvas with Live Multiplayer Cursor Motion */}
          <div className="flex-1 p-3 overflow-hidden relative font-mono text-[11px] sm:text-[12px] leading-[1.7] bg-[#000000]">
            {/* Subtle Hardware Matrix Pattern */}
            <div className="absolute inset-0 opacity-[0.02] bg-[linear-gradient(to_right,#ffffff_1px,transparent_1px),linear-gradient(to_bottom,#ffffff_1px,transparent_1px)] bg-[size:16px_16px] pointer-events-none" />

            {/* ============================================================== */}
            {/* REMOTE PEER 1: MUHAYMIN LIVE CANVA DART CURSOR                 */}
            {/* ============================================================== */}
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

            {/* ============================================================== */}
            {/* REMOTE PEER 2: HRUSHIKESH GANGALA LIVE BLUE DART CURSOR       */}
            {/* ============================================================== */}
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

            {/* CODE LINES (Exact database.ts from video recording) */}
            <div className="space-y-0.5 relative z-10 text-[11px] sm:text-[12px] leading-[1.65]">
              {/* Line 01 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                <span className="text-white">
                  <span className="text-[#007AFF] font-semibold">import</span> &#123; <span className="text-white font-medium">LocalWriteAheadLog</span> &#125; <span className="text-[#007AFF] font-semibold">from</span> <span className="text-[#ff914d]">"@crux/wal"</span>;
                </span>
              </div>

              {/* Line 02 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                <span className="text-white">
                  <span className="text-[#007AFF] font-semibold">import</span> &#123; <span className="text-white font-medium">SyncVector</span> &#125; <span className="text-[#007AFF] font-semibold">from</span> <span className="text-[#ff914d]">"./types"</span>;
                </span>
              </div>

              {/* Line 03 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">3</span>
                <span></span>
              </div>

              {/* Line 04 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">4</span>
                <span className="text-[#888888] italic">// Monotonic local-first persistent write-ahead store</span>
              </div>

              {/* Line 05 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">5</span>
                <span className="text-white">
                  <span className="text-[#007AFF] font-semibold">export const</span> wal = <span className="text-[#007AFF] font-semibold">new</span> LocalWriteAheadLog(&#123;
                </span>
              </div>

              {/* Line 06: Live typing simulation by Muhaymin */}
              <div className="flex items-center relative bg-[#ffffff]/5 pl-0.5">
                <span className="w-6 text-right text-[10px] text-white font-bold select-none pr-3">6</span>
                <span className="text-white pl-3 font-mono">
                  path: <span className="text-[#ff914d]">"/var/crux/wal.bin"</span>,{typedSuffix}
                  <motion.span
                    animate={{ opacity: [1, 0, 1] }}
                    transition={{ repeat: Infinity, duration: 0.6 }}
                    className="w-1.5 h-3.5 bg-white inline-block ml-0.5 align-middle"
                  />
                </span>
              </div>

              {/* Line 07 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">7</span>
                <span className="text-white pl-3">
                  syncIntervalMs: <span className="text-[#ffbd2e]">16</span>,
                </span>
              </div>

              {/* Line 08 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">8</span>
                <span className="text-white pl-3">
                  ringBufferSizeMb: <span className="text-[#ffbd2e]">64</span>,
                </span>
              </div>

              {/* Line 09 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">9</span>
                <span className="text-white">&#125;);</span>
              </div>

              {/* Line 10 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">10</span>
                <span></span>
              </div>

              {/* Line 11 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">11</span>
                <span className="text-[#888888] italic">// Monotonic state vector persistence vector</span>
              </div>

              {/* Line 12 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">12</span>
                <span className="text-white">
                  <span className="text-[#007AFF] font-semibold">export async function</span> <span className="text-[#ff914d]">persistStateVector</span>(
                </span>
              </div>

              {/* Line 13 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">13</span>
                <span className="text-white pl-3">
                  docId: <span className="text-[#007AFF]">string</span>,
                </span>
              </div>

              {/* Line 14: Hrushikesh Gangala editing cursor point */}
              <div className={`flex items-center relative pl-0.5 ${muhayminStatus === "selecting" ? "bg-[#007AFF]/20 border-l-2 border-[#007AFF]" : ""}`}>
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">14</span>
                <span className="text-white pl-3">
                  vector: <span className="text-[#007AFF]">SyncVector</span>
                </span>
              </div>

              {/* Line 15 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">15</span>
                <span className="text-white">): <span className="text-[#007AFF]">Promise</span>&lt;<span className="text-[#ffbd2e]">number</span>&gt; &#123;</span>
              </div>

              {/* Line 16 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">16</span>
                <span className="text-white pl-3">
                  <span className="text-[#007AFF] font-semibold">const</span> bytes = vector.encode();
                </span>
              </div>

              {/* Line 17 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">17</span>
                <span className="text-white pl-3">
                  <span className="text-[#007AFF] font-semibold">const</span> monotonicSequence = <span className="text-[#007AFF] font-semibold">await</span> wal.append(&#123;
                </span>
              </div>

              {/* Line 18 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">18</span>
                <span className="text-white pl-6">docId, payload: bytes,</span>
              </div>

              {/* Line 19 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">19</span>
                <span className="text-white pl-3">&#125;);</span>
              </div>

              {/* Line 20 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">20</span>
                <span className="text-white pl-3">
                  <span className="text-[#007AFF] font-semibold">return</span> monotonicSequence;
                </span>
              </div>

              {/* Line 21 */}
              <div className="flex items-center">
                <span className="w-6 text-right text-[10px] text-[#444444] select-none pr-3">21</span>
                <span className="text-white">&#125;</span>
              </div>
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
              <span>DISK IN-SYNC 36ms</span>
            </div>
          </div>

          {/* Center: History counter */}
          <div className="hidden sm:flex items-center gap-1 text-[#888888]">
            <Clock className="w-3 h-3" />
            <span>HISTORY (41)</span>
          </div>

          {/* Right: Line/Col, UTF-8, TYPESCRIPT */}
          <div className="flex items-center gap-3">
            <span>Ln 6, Col {cursorPosCol}</span>
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
