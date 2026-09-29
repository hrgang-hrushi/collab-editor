"use client";

import React, { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Plus,
  Download,
  Search,
  FolderPlus,
  FolderDown,
  ChevronRight,
  FileCode2,
  GitBranch,
  Terminal,
  Zap,
  Cpu,
  CheckCircle2,
  ShieldCheck,
  Bot,
  Activity,
  GitMerge,
  Code2,
  Database,
  History,
  Check,
} from "lucide-react";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";
import CruxPointerCursor from "@/components/crux/CruxPointerCursor";
import BranchedMenu, { BranchedMenuItem } from "@/components/crux/zenith/BranchedMenu";
import { BotAvatar } from "bot-avatars";
import { avatarMotionSeed } from "@/components/crux/avatars/avatarMotion";
import {
  Folder01Icon,
  JavaScriptIcon,
  CodeIcon,
  File01Icon,
} from "@hugeicons/core-free-icons";
import { HugeiconsIcon } from "@hugeicons/react";

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
  // Multiplayer live typing simulation by Muhaymin
  const [typedSuffix, setTypedSuffix] = useState("");
  const [muhayminStatus, setMuhayminStatus] = useState<"idle" | "typing" | "selecting">("idle");
  const [cursorPosCol, setCursorPosCol] = useState(22);

  // Cycling interaction loop for multiplayer
  useEffect(() => {
    if (mode !== "multiplayer") return;
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

    timeout = setTimeout(runLoop, 600);
    return () => clearTimeout(timeout);
  }, [mode]);

  // Telemetry jitter per mode
  const [fps, setFps] = useState(120.0);
  const [tokRate, setTokRate] = useState(184);
  const [crdtConvergenceTime, setCrdtConvergenceTime] = useState("0.38");

  useEffect(() => {
    const interval = setInterval(() => {
      if (mode === "silicon") {
        setFps(parseFloat((119.8 + Math.random() * 0.4).toFixed(1)));
      } else if (mode === "processing") {
        setTokRate(170 + Math.floor(Math.random() * 28));
      } else if (mode === "crdt") {
        setCrdtConvergenceTime((0.34 + Math.random() * 0.08).toFixed(2));
      }
    }, 900);
    return () => clearInterval(interval);
  }, [mode]);

  // Active File and Breadcrumbs based on active mode
  const fileMeta = useMemo(() => {
    switch (mode) {
      case "silicon":
        return {
          name: "spatial_engine.metal",
          folder: "kernel",
          crumb: "metal",
          secondary: "profiler_dma.rs",
          isMetal: true,
          lines: 24,
        };
      case "crdt":
        return {
          name: "ast_crdt_sync.ts",
          folder: "crdt",
          crumb: "replication",
          secondary: "vector_clock.rs",
          isMetal: false,
          lines: 32,
        };
      case "agents":
        return {
          name: "stream_syncer.ts",
          folder: "agent",
          crumb: "refactor",
          secondary: "diff_view.patch",
          isMetal: false,
          lines: 18,
        };
      case "context":
        return {
          name: "kernel_signals.ts",
          folder: "posix",
          crumb: "buffer",
          secondary: "inodes.bin",
          isMetal: false,
          lines: 48,
        };
      case "processing":
        return {
          name: "crdt_synthesis.ts",
          folder: "synthesis",
          crumb: "transform",
          secondary: "peer_attest.sec",
          isMetal: false,
          lines: 28,
        };
      case "output":
        return {
          name: "compiler_output.ts",
          folder: "build",
          crumb: "aarch64",
          secondary: "macho_arm64.bin",
          isMetal: false,
          lines: 36,
        };
      case "multiplayer":
      default:
        return {
          name: "stream_syncer.ts",
          folder: "core",
          crumb: "daemon",
          secondary: "types.ts",
          isMetal: false,
          lines: 15,
        };
    }
  }, [mode]);

  // Actual BranchedMenu Tree Data exactly mirroring ZenithFileTree
  const branchedMenuItems: BranchedMenuItem[] = useMemo(() => {
    return [
      {
        label: "SRC",
        value: "src",
        icon: Folder01Icon,
        children: [
          {
            value: "stream_syncer.ts",
            label: "stream_syncer.ts",
            icon: JavaScriptIcon,
          },
          {
            value: "types.ts",
            label: "types.ts",
            icon: JavaScriptIcon,
          },
          {
            value: "database.ts",
            label: "database.ts",
            icon: JavaScriptIcon,
          },
        ],
      },
      {
        label: "KERNEL",
        value: "kernel",
        icon: Folder01Icon,
        children: [
          {
            value: "spatial_engine.metal",
            label: "spatial_engine.metal",
            icon: CodeIcon,
          },
          {
            value: "ast_crdt_sync.ts",
            label: "ast_crdt_sync.ts",
            icon: JavaScriptIcon,
          },
          {
            value: "kernel_signals.ts",
            label: "kernel_signals.ts",
            icon: CodeIcon,
          },
        ],
      },
      {
        label: "BUILD",
        value: "build",
        icon: Folder01Icon,
        children: [
          {
            value: "compiler_output.ts",
            label: "compiler_output.ts",
            icon: JavaScriptIcon,
          },
          {
            value: "Cargo.toml",
            label: "Cargo.toml",
            icon: File01Icon,
          },
        ],
      },
    ];
  }, []);

  return (
    <div className="w-full h-full bg-[#000000] text-white flex flex-col select-none overflow-hidden font-sans border-0">
      {/* 1. EXACT CRUX IDE TOP HEADER (CruxHeader.tsx layout) */}
      {showHeader && (
        <header className="w-full h-9 px-3 flex items-center justify-between border-b border-[#222222] bg-[#000000] select-none text-xs font-mono shrink-0 z-20">
          {/* Left: Brand + Breadcrumbs */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <CruxBrandLogo size={15} withText={true} />
              <span className="w-1.5 h-1.5 rounded-none bg-white ml-1" />
              <span className="text-[10px] text-[#888888] hidden sm:inline font-mono">
                0.08ms
              </span>
            </div>

            <div className="h-3 w-[1px] bg-[#222222] mx-0.5" />

            {/* File Breadcrumb */}
            <div className="flex items-center gap-1.5 text-xs text-[#888888]">
              <span className="text-[#888888]">{fileMeta.folder}</span>
              <ChevronRight className="w-3 h-3 text-[#333333]" />
              <span className="text-[#888888]">{fileMeta.crumb}</span>
              <ChevronRight className="w-3 h-3 text-[#333333]" />
              <div className="flex items-center gap-1.5 text-white px-1.5 py-0.5 bg-black border border-[#222222]">
                <FileCode2 className="w-3.5 h-3.5 text-white" />
                <span>{fileMeta.name}</span>
              </div>
            </div>
          </div>

          {/* Right: Authentic Collaborator Badges with Real BotAvatars + Share */}
          <div className="flex items-center gap-2">
            <div
              role="group"
              aria-label="Active Collaborators"
              className="flex items-center border border-[#222222] rounded-none select-none bg-black"
            >
              {/* Hrushikesh Gangala (Host) */}
              <div
                title="Hrushikesh Gangala (You)"
                className="px-1.5 py-0.5 flex items-center justify-center border-r border-[#222222] rounded-none bg-transparent text-white"
              >
                <BotAvatar
                  type="mech"
                  size={22}
                  state="default"
                  seed={avatarMotionSeed("Hrushikesh Gangala")}
                  interactive={false}
                  theme="dark"
                />
              </div>

              {/* Muhaymin (Remote Collaborator) */}
              <div
                title="Muhaymin (Remote Peer)"
                className="px-1.5 py-0.5 flex items-center justify-center border-r border-[#222222] rounded-none bg-transparent text-[#888888]"
              >
                <BotAvatar
                  type="alien"
                  size={22}
                  state="default"
                  seed={avatarMotionSeed("Muhaymin")}
                  interactive={false}
                  theme="dark"
                />
              </div>

              {/* @CruxAI (Agent) */}
              {mode === "agents" && (
                <div
                  title="@CruxAI (Local Droid)"
                  className="px-1.5 py-0.5 flex items-center justify-center border-r border-[#222222] rounded-none bg-transparent text-[#0055FF]"
                >
                  <BotAvatar
                    type="droid"
                    size={22}
                    state="default"
                    seed={avatarMotionSeed("@CruxAI")}
                    interactive={false}
                    theme="dark"
                  />
                </div>
              )}

              {/* Share button */}
              <div
                title="Share workspace or invite peers"
                className="px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider leading-none text-[#888888] hover:text-white transition-none"
              >
                + SHARE
              </div>
            </div>

            <div className="h-3 w-[1px] bg-[#222222] mx-0.5 hidden sm:block" />

            <div className="px-2 py-0.5 border text-[11px] rounded-none font-mono bg-black text-[#888888] border-[#222222] hidden sm:block">
              Direct Edit
            </div>
          </div>
        </header>
      )}

      {/* 2. BODY SPLIT: EXACT ZENITH FILE TREE + MAIN EDITOR CANVAS */}
      <div className="flex-1 flex min-h-0 bg-[#000000] overflow-hidden">
        {/* Left Vertical Explorer: EXACT ZenithFileTree Clone with Real BranchedMenu */}
        <aside className="w-52 sm:w-56 border-r border-[#222222] bg-[#000000] flex flex-col select-none shrink-0 h-full font-sans hidden sm:flex">
          {/* Explorer Header matching ZenithFileTree.tsx line 357 */}
          <div className="px-3 py-2 border-b border-[#222222] text-[10px] font-bold tracking-widest text-[#888888] uppercase flex items-center justify-between">
            <span>Explorer</span>
            <div className="flex items-center gap-1.5 text-[#888888]">
              <Plus className="w-3.5 h-3.5 hover:text-white cursor-pointer" />
              <Download className="w-3.5 h-3.5 hover:text-white cursor-pointer" />
              <Search className="w-3.5 h-3.5 hover:text-white cursor-pointer" />
            </div>
          </div>

          {/* Import Folder & Import Files Buttons matching ZenithFileTree.tsx lines 390-409 */}
          <div className="flex border-b border-[#222222] text-[9px] font-bold tracking-wide">
            <div className="flex-1 flex items-center justify-center gap-1 px-1.5 py-1.5 bg-white text-black hover:bg-[#CCCCCC] transition-none cursor-pointer">
              <FolderPlus className="w-3 h-3" />
              IMPORT FOLDER
            </div>
            <div className="flex-1 flex items-center justify-center gap-1 px-1.5 py-1.5 border-l border-[#222222] bg-black text-white hover:bg-[#111111] transition-none cursor-pointer">
              <FolderDown className="w-3 h-3" />
              IMPORT FILES
            </div>
          </div>

          {/* Real BranchedMenu: Tree with Connected Branches & Curved Lines */}
          <div className="flex-1 py-1 font-mono text-xs overflow-y-auto">
            <BranchedMenu
              items={branchedMenuItems}
              defaultOpen={[0, 1]}
              active={fileMeta.name}
              width="100%"
              rowHeight={26}
              indent={24}
              fontSize={11}
              color="#888888"
              accentColor="#ffffff"
              lineColor="#222222"
            />
          </div>

          {/* Sidebar Footer matching ZenithFileTree.tsx */}
          <div className="p-2 border-t border-[#222222] bg-[#050507] text-[9px] font-mono space-y-1">
            <div className="flex items-center justify-between text-[#71717a]">
              <span>INODES</span>
              <span className="text-white font-bold">64,280</span>
            </div>
            <div className="flex items-center justify-between text-[#71717a]">
              <span>MEMORY</span>
              <span className="text-[#0055FF] font-bold">38.2 MB</span>
            </div>
          </div>
        </aside>

        {/* Main Editor Pane: ZenithEditorPane clone */}
        <main className="flex-1 bg-[#000000] flex flex-col relative overflow-hidden font-sans">
          {/* Tab Strip matching ZenithEditorPane.tsx line 226 */}
          <div className="flex h-8 border-b border-[#222222] bg-[#111111] items-center justify-between select-none shrink-0 overflow-x-auto">
            <div className="flex items-center h-full overflow-x-auto">
              {/* Active Tab */}
              <div className="px-3 border-r border-[#222222] text-[11px] font-sans uppercase tracking-tight flex items-center gap-2 transition-none shrink-0 h-full bg-[#000000] text-white font-medium">
                {fileMeta.isMetal ? (
                  <HugeiconsIcon icon={CodeIcon} size={12} strokeWidth={2} className="text-[#0055FF]" />
                ) : (
                  <HugeiconsIcon icon={JavaScriptIcon} size={12} strokeWidth={2} className="text-[#0055FF]" />
                )}
                <span>{fileMeta.name}</span>
                <span className="text-[9px] text-[#444444] font-mono shrink-0 hidden md:inline">
                  {fileMeta.lines}L
                </span>
                <span className="w-1.5 h-1.5 bg-white shrink-0 ml-1" />
                <span className="text-[#444444] hover:text-white cursor-pointer ml-1">×</span>
              </div>

              {/* Secondary Inactive Tab */}
              <div className="px-3 border-r border-[#222222] text-[11px] font-sans uppercase tracking-tight flex items-center gap-2 transition-none shrink-0 h-full bg-[#111111] text-[#666666] hover:text-white hidden sm:flex">
                <span>{fileMeta.secondary}</span>
                <span className="text-[#444444] hover:text-white cursor-pointer ml-1">×</span>
              </div>
            </div>

            {/* Right Tab Meta Badge */}
            <div className="pr-3 text-[10px] font-mono text-[#0055FF] font-bold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
              <span>
                {mode === "multiplayer" && "WEBRTC MESH"}
                {mode === "silicon" && "120 FPS METAL"}
                {mode === "crdt" && "AST CONVERGED"}
                {mode === "agents" && "@CRUXAI ACTIVE"}
                {mode === "context" && "64K INODES"}
                {mode === "processing" && "SYNTHESIS"}
                {mode === "output" && "ARM64 READY"}
              </span>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* FEATURE 1: REAL-TIME COLLABORATIVE MESH (Multiplayer with Live Cursors)   */}
          {/* ========================================================================= */}
          {mode === "multiplayer" && (
            <div className="flex-1 p-3 overflow-hidden relative font-mono text-[11px] sm:text-[12px] leading-[1.65] bg-[#000000]">
              {/* REMOTE PEER 1: MUHAYMIN DART CURSOR */}
              <motion.div
                className="absolute pointer-events-none z-30 select-none"
                animate={{
                  x: [130, 200, 260, 230, 160, 130],
                  y: [122, 124, 128, 126, 124, 122],
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

              {/* REMOTE PEER 2: HRUSHIKESH GANGALA DART CURSOR */}
              <motion.div
                className="absolute pointer-events-none z-30 select-none hidden md:block"
                animate={{
                  x: [200, 280, 350, 300, 230, 200],
                  y: [194, 198, 204, 200, 196, 194],
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
                  color="#0055FF"
                  status="typing"
                />
              </motion.div>

              {/* Top Banner: WebRTC Mesh Presence Vector */}
              <div className="mb-2 p-1.5 border border-[#222222] bg-[#09090b] flex items-center justify-between text-[10px]">
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                  <span className="text-white font-bold">LOCK-FREE WEBRTC MESH</span>
                  <span className="text-[#555555]">|</span>
                  <span className="text-[#888888]">PEERS: 2 CONNECTED</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-[#71717a]">RTT: <strong className="text-white">0.28ms</strong></span>
                  <span className="text-[#71717a]">WAL BUFFER: <strong className="text-[#0055FF]">64 MB</strong></span>
                </div>
              </div>

              {/* Editor Buffer with Standard IDE Line Numbers Gutter */}
              <div className="space-y-0.5">
                <div className="flex items-center">
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                  <span className="text-white">
                    <span className="text-[#0055FF] font-semibold">import</span> &#123; <span className="text-white font-medium">LocalWriteAheadLog</span> &#125; <span className="text-[#0055FF] font-semibold">from</span> <span className="text-[#ff914d]">"@crux/wal"</span>;
                  </span>
                </div>
                <div className="flex items-center">
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                  <span className="text-white">
                    <span className="text-[#0055FF] font-semibold">import</span> &#123; <span className="text-white font-medium">SyncVector</span> &#125; <span className="text-[#007AFF] font-semibold">from</span> <span className="text-[#ff914d]">"./types"</span>;
                  </span>
                </div>
                <div className="flex items-center">
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">3</span>
                  <span className="text-[#71717a] italic">// Lock-free peer stream syncer</span>
                </div>
                <div className="flex items-center">
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">4</span>
                  <span className="text-white">
                    <span className="text-[#0055FF] font-semibold">export const</span> wal = <span className="text-[#0055FF] font-semibold">new</span> LocalWriteAheadLog(&#123;
                  </span>
                </div>
                <div className="flex items-center bg-[#ffffff]/5 pl-0.5">
                  <span className="w-8 text-right text-[10px] text-white font-bold select-none pr-3">5</span>
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
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">6</span>
                  <span className="text-white pl-3">syncIntervalMs: <span className="text-[#ffbd2e]">16</span>, ringBufferSizeMb: <span className="text-[#ffbd2e]">64</span></span>
                </div>
                <div className="flex items-center">
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">7</span>
                  <span className="text-white">&#125;);</span>
                </div>
                <div className={`flex items-center relative pl-0.5 ${muhayminStatus === "selecting" ? "bg-[#0055FF]/20 border-l-2 border-[#0055FF]" : ""}`}>
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">8</span>
                  <span className="text-white pl-3">
                    <span className="text-[#0055FF] font-semibold">export async function</span> <span className="text-[#ff914d]">persistStateVector</span>(
                  </span>
                </div>
                <div className={`flex items-center relative pl-0.5 ${muhayminStatus === "selecting" ? "bg-[#0055FF]/20 border-l-2 border-[#0055FF]" : ""}`}>
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">9</span>
                  <span className="text-white pl-6">docId: <span className="text-[#0055FF]">string</span>, vector: <span className="text-[#0055FF]">SyncVector</span></span>
                </div>
                <div className="flex items-center">
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">10</span>
                  <span className="text-white pl-3">): <span className="text-[#0055FF]">Promise</span>&lt;<span className="text-[#ffbd2e]">number</span>&gt; &#123;</span>
                </div>
                <div className="flex items-center">
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">11</span>
                  <span className="text-white pl-6">const monotonicSequence = <span className="text-[#0055FF] font-semibold">await</span> wal.append(&#123; docId, payload: vector.encode() &#125;);</span>
                </div>
                <div className="flex items-center">
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">12</span>
                  <span className="text-white pl-6"><span className="text-[#0055FF] font-semibold">return</span> monotonicSequence;</span>
                </div>
                <div className="flex items-center">
                  <span className="w-8 text-right text-[10px] text-[#444444] select-none pr-3">13</span>
                  <span className="text-white pl-3">&#125;</span>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* FEATURE 2: NATIVE SILICON RUNTIME (Hardware Acceleration & Profiler)      */}
          {/* ========================================================================= */}
          {mode === "silicon" && (
            <div className="flex-1 p-3 overflow-hidden flex flex-col justify-between font-mono bg-[#000000]">
              {/* Top Oscilloscope & Real-time Vsync Telemetry Strip */}
              <div className="border border-[#222222] bg-[#08080a] p-3 space-y-3">
                <div className="flex items-center justify-between text-xs pb-1.5 border-b border-[#222222]">
                  <div className="flex items-center gap-2">
                    <Zap className="w-4 h-4 text-[#0055FF]" />
                    <span className="text-white font-bold">WEBGPU / METAL TEXT RASTERIZER</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] text-[#0055FF] font-bold">
                    <span className="w-2 h-2 bg-[#0055FF] animate-pulse" />
                    <span>{fps} FPS (8.33ms VSYNC LOCKED)</span>
                  </div>
                </div>

                {/* 3 Metric Gauges Grid */}
                <div className="grid grid-cols-3 gap-2 text-left">
                  <div className="p-2 border border-[#222222] bg-[#0c0c0e]">
                    <div className="text-[9px] text-[#71717a] uppercase">Input-to-Photon</div>
                    <div className="text-base text-white font-bold mt-0.5">4.2 ms</div>
                    <div className="text-[9px] text-[#0055FF] font-semibold mt-1">11.5x vs Electron (48.6ms)</div>
                  </div>
                  <div className="p-2 border border-[#222222] bg-[#0c0c0e]">
                    <div className="text-[9px] text-[#71717a] uppercase">Unified VRAM</div>
                    <div className="text-base text-white font-bold mt-0.5">38.2 MB</div>
                    <div className="text-[9px] text-[#0055FF] font-semibold mt-1">17.8x leaner (vs 680MB)</div>
                  </div>
                  <div className="p-2 border border-[#222222] bg-[#0c0c0e]">
                    <div className="text-[9px] text-[#71717a] uppercase">Draw Calls</div>
                    <div className="text-base text-white font-bold mt-0.5">1 Call</div>
                    <div className="text-[9px] text-[#0055FF] font-semibold mt-1">per 50,000 text glyphs</div>
                  </div>
                </div>

                {/* Live 120Hz Oscilloscope Waveform */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-[10px] text-[#71717a]">
                    <span>FRAME TIME JITTER (120Hz VSYNC TIMELINE)</span>
                    <span className="text-[#0055FF] font-bold">ZERO FRAME DROPS</span>
                  </div>
                  <div className="flex items-end gap-1 h-6 bg-[#040406] border border-[#222222] px-1 py-0.5">
                    {[
                      0.85, 0.88, 0.84, 0.86, 0.87, 0.85, 0.89, 0.85, 0.86, 0.88,
                      0.85, 0.87, 0.86, 0.85, 0.88, 0.86, 0.87, 0.85, 0.88, 0.86,
                      0.85, 0.87, 0.86, 0.88, 0.85, 0.86, 0.87, 0.85, 0.88, 0.86,
                    ].map((val, idx) => (
                      <motion.div
                        key={idx}
                        className="flex-1 bg-[#0055FF]"
                        animate={{ height: [`${val * 100}%`, `${(val + (Math.random() * 0.1 - 0.05)) * 100}%`, `${val * 100}%`] }}
                        transition={{ duration: 1.2, repeat: Infinity, delay: idx * 0.03 }}
                      />
                    ))}
                  </div>
                </div>
              </div>

              {/* Lower Pane: Native Metal Shader Code */}
              <div className="p-2.5 border border-[#222222] bg-[#050507] text-[10px] sm:text-[11px] leading-relaxed text-[#888888] space-y-0.5">
                <div className="text-[#71717a] font-bold text-[9px] uppercase tracking-wider mb-1">// DIRECT MEMORY ACCESS (DMA) PIPELINE</div>
                <div className="text-white">
                  <span className="text-[#0055FF]">kernel void</span> <span className="text-[#ff914d]">rasterize_glyph_quads</span>(
                </div>
                <div className="pl-3 text-white">
                  device const GlyphVertex* vertices [[buffer(0)]],
                </div>
                <div className="pl-3 text-white">
                  texture2d&lt;float, access::sample&gt; fontAtlas [[texture(0)]]
                </div>
                <div className="text-white">) &#123; <span className="text-[#71717a] italic">/* Direct GPU Phosphor emission in 4.2ms */</span> &#125;</div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* FEATURE 3: DECENTRALIZED AST-CRDT (Syntax Tree & Vector Convergence)      */}
          {/* ========================================================================= */}
          {mode === "crdt" && (
            <div className="flex-1 p-3 overflow-hidden flex flex-col justify-between font-mono bg-[#000000]">
              {/* Top Bar: Vector Clock State */}
              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-2">
                  <GitMerge className="w-4 h-4 text-[#0055FF]" />
                  <span className="text-white font-bold">STRUCTURAL AST REPLICATION</span>
                </div>
                <div className="flex items-center gap-2 text-[10px]">
                  <span className="text-[#71717a]">VECTOR CLOCK:</span>
                  <span className="px-1.5 py-0.5 bg-[#141416] border border-[#222222] text-[#0055FF] font-bold">
                    [H: 142, M: 89, AI: 204]
                  </span>
                </div>
              </div>

              {/* Center Split: Concurrent Delta Stream vs AST Tree Visualizer */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 my-2 flex-1 min-h-0">
                {/* Left: Concurrent Mutations Stream */}
                <div className="p-2.5 border border-[#222222] bg-[#060608] flex flex-col justify-between text-[10px] space-y-1.5 overflow-hidden">
                  <div className="text-[#71717a] font-bold text-[9px] uppercase border-b border-[#222222] pb-1">
                    CONCURRENT PEER DELTAS
                  </div>
                  <div className="space-y-1.5 text-[10px]">
                    <div className="flex items-center gap-1.5 text-[#a1a1aa]">
                      <span className="text-[#0055FF] font-bold">peer://muhaymin</span>
                      <span className="text-[#555555]">&gt;</span>
                      <span className="truncate text-white">mutates acquireLockTicket()</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-[#a1a1aa]">
                      <span className="text-[#0055FF] font-bold">peer://hrushikesh</span>
                      <span className="text-[#555555]">&gt;</span>
                      <span className="truncate text-white">mutates persistStateVector()</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-[#22c55e]">
                      <span className="text-[#22c55e] font-bold">ast_engine</span>
                      <span className="text-[#555555]">&gt;</span>
                      <span className="truncate font-semibold">Converged in {crdtConvergenceTime}ms (0 collisions)</span>
                    </div>
                  </div>
                  <div className="pt-1.5 border-t border-[#222222] flex items-center justify-between text-[9px] text-[#71717a]">
                    <span>STATUS: <strong className="text-white">DETERMINISTIC</strong></span>
                    <span className="text-[#22c55e] font-bold">100% HEALTH</span>
                  </div>
                </div>

                {/* Right: Structural AST Token Tree Visualizer */}
                <div className="p-2.5 border border-[#222222] bg-[#060608] flex flex-col justify-between text-[10px] space-y-1">
                  <div className="text-[#71717a] font-bold text-[9px] uppercase border-b border-[#222222] pb-1">
                    SYNTAX TREE TOPOLOGY
                  </div>
                  <div className="space-y-1 font-mono text-[10px] text-white">
                    <div className="flex items-center gap-1.5 text-[#888888]">
                      <Code2 className="w-3 h-3 text-[#0055FF]" />
                      <span>Program [Root]</span>
                    </div>
                    <div className="pl-3 flex items-center gap-1.5 text-white">
                      <span className="text-[#555555]">├─</span>
                      <span className="text-[#ff914d]">FunctionDeclaration:</span>
                      <span>mergeASTVectors</span>
                    </div>
                    <div className="pl-6 flex items-center gap-1.5 text-[#22c55e] font-semibold bg-[#22c55e]/10 py-0.5 px-1 border border-[#22c55e]/30">
                      <span className="text-[#555555]">├─</span>
                      <span>LockFreeTicket [SYNCHRONIZED]</span>
                    </div>
                    <div className="pl-6 flex items-center gap-1.5 text-white">
                      <span className="text-[#555555]">└─</span>
                      <span>AtomicBitset [RESOLVED]</span>
                    </div>
                  </div>
                  <div className="pt-1 border-t border-[#222222] text-[9px] text-[#71717a]">
                    ABSTRACT SYNTAX TREE REPLICATION: <strong className="text-[#0055FF]">ZERO COLLISION</strong>
                  </div>
                </div>
              </div>

              {/* Bottom Metrics Bar */}
              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                <div className="flex items-center gap-3">
                  <span className="text-[#71717a]">LINE COLLISION RISK: <strong className="text-white">0.00%</strong></span>
                  <span className="text-[#71717a]">TREE HEALTH: <strong className="text-[#0055FF]">100% VALID</strong></span>
                </div>
                <div className="text-[#22c55e] font-bold">
                  ✓ SUB-10ms REPLICATION
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* FEATURE 4: AUTONOMOUS @CRUXAI AGENTS (Inline Diff & Compiler Check)       */}
          {/* ========================================================================= */}
          {mode === "agents" && (
            <div className="flex-1 p-3 overflow-hidden flex flex-col justify-between font-mono bg-[#000000]">
              {/* Agent Execution HUD Prompt */}
              <div className="p-2.5 border border-[#0055FF]/40 bg-[#0055FF]/10 space-y-1.5">
                <div className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-2">
                    <Bot className="w-4 h-4 text-[#0055FF]" />
                    <span className="text-white font-bold">@CruxAI AUTONOMOUS REFACTOR</span>
                  </div>
                  <span className="px-1.5 py-0.2 bg-[#0055FF] text-white text-[9px] font-bold">
                    LOCAL POSIX (0ms CLOUD)
                  </span>
                </div>
                <div className="text-[11px] text-white font-mono bg-[#000000] p-1.5 border border-[#222222]">
                  <span className="text-[#0055FF]">%</span> @CruxAI refactor ./src/stream_syncer.ts --optimize-atomic-locks
                </div>
              </div>

              {/* Inline Diff View: Red Deletions & Green Additions */}
              <div className="border border-[#222222] bg-[#060608] p-2 space-y-1 text-[11px] my-2 flex-1 overflow-hidden">
                <div className="text-[9px] text-[#71717a] uppercase font-bold border-b border-[#222222] pb-1">
                  INLINE AGENT DIFF PROPOSAL (+14, -6 LINES)
                </div>
                <div className="text-[#71717a]">
                  &nbsp;&nbsp;export async function syncPeerDelta(delta: PeerDelta) &#123;
                </div>
                <div className="bg-[#ef4444]/15 text-[#ef4444] px-1 line-through border-l-2 border-[#ef4444]">
                  -&nbsp;&nbsp;&nbsp;&nbsp;const mutex = new MutexLock();
                </div>
                <div className="bg-[#ef4444]/15 text-[#ef4444] px-1 line-through border-l-2 border-[#ef4444]">
                  -&nbsp;&nbsp;&nbsp;&nbsp;await mutex.acquire();
                </div>
                <div className="bg-[#22c55e]/15 text-[#22c55e] px-1 font-semibold border-l-2 border-[#22c55e]">
                  +&nbsp;&nbsp;&nbsp;&nbsp;const lockTicket = atomicBitset.claimTicket();
                </div>
                <div className="bg-[#22c55e]/15 text-[#22c55e] px-1 font-semibold border-l-2 border-[#22c55e]">
                  +&nbsp;&nbsp;&nbsp;&nbsp;await wal.commitLockFree(lockTicket);
                </div>
                <div className="text-[#71717a]">
                  &nbsp;&nbsp;&#125;
                </div>
              </div>

              {/* Sub-pane: Terminal Compiler Pass Output */}
              <div className="p-2 border border-[#222222] bg-[#0c0c0e] flex items-center justify-between text-[10px]">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#22c55e]" />
                  <span className="text-white font-medium">cargo/tsc check --target=aarch64-darwin: 0 errors</span>
                </div>
                <div className="flex items-center gap-2">
                  <button className="px-2 py-0.5 bg-white text-black font-bold text-[9px] uppercase hover:bg-[#dddddd] transition-none">
                    ACCEPT DIFF (⌘↵)
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* FEATURE 5: CONTEXT AWARENESS (Raw POSIX Buffer & Inodes Ingest)           */}
          {/* ========================================================================= */}
          {mode === "context" && (
            <div className="flex-1 p-3 overflow-hidden flex flex-col justify-between font-mono bg-[#000000]">
              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-2">
                  <Database className="w-4 h-4 text-[#0055FF]" />
                  <span className="text-white font-bold">KERNEL CONTEXT PIPELINE</span>
                </div>
                <span className="text-[#0055FF] font-bold text-[10px]">
                  INGEST RATE: 3.2 GB/s
                </span>
              </div>

              <div className="border border-[#222222] bg-[#060608] p-3 my-2 space-y-2 flex-1">
                <div className="text-[9px] text-[#71717a] font-bold uppercase border-b border-[#222222] pb-1 flex items-center justify-between">
                  <span>RAW POSIX BUFFER DESCRIPTORS</span>
                  <span className="text-[#0055FF]">ZERO-COPY MEMORY MAP</span>
                </div>
                <div className="space-y-1.5 text-[10px]">
                  <div className="flex items-center justify-between p-1.5 border border-[#222222] bg-[#0a0a0c]">
                    <div className="flex items-center gap-2">
                      <span className="text-[#0055FF] font-bold">0x7fff5fbff820</span>
                      <span className="text-white">Source Trees (.rs, .ts)</span>
                    </div>
                    <span className="text-[#22c55e] font-semibold">14,280 SYMBOLS</span>
                  </div>
                  <div className="flex items-center justify-between p-1.5 border border-[#222222] bg-[#0a0a0c]">
                    <div className="flex items-center gap-2">
                      <span className="text-[#0055FF] font-bold">0x7fff5fbff940</span>
                      <span className="text-white">Kernel kqueue / epoll</span>
                    </div>
                    <span className="text-white font-semibold">0.1ms LATENCY</span>
                  </div>
                  <div className="flex items-center justify-between p-1.5 border border-[#222222] bg-[#0a0a0c]">
                    <div className="flex items-center gap-2">
                      <span className="text-[#0055FF] font-bold">0x7fff5fbffa60</span>
                      <span className="text-white">Git Head &amp; AST Inodes</span>
                    </div>
                    <span className="text-[#0055FF] font-semibold">64,280 INODES</span>
                  </div>
                </div>
              </div>

              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                <span className="text-[#71717a]">I/O LATENCY: <strong className="text-white">0.41ms</strong></span>
                <span className="text-[#71717a]">CACHE HIT RATE: <strong className="text-[#0055FF]">99.8%</strong></span>
                <span className="text-[#22c55e] font-bold">NVMe DIRECT</span>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* FEATURE 6: INTELLIGENT PROCESSING (Multi-Peer AST Synthesis)              */}
          {/* ========================================================================= */}
          {mode === "processing" && (
            <div className="flex-1 p-3 overflow-hidden flex flex-col justify-between font-mono bg-[#000000]">
              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#0055FF]" />
                  <span className="text-white font-bold">AST DELTA SYNTHESIS ENGINE</span>
                </div>
                <div className="flex items-center gap-1.5 text-[#0055FF] font-bold text-[10px]">
                  <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                  <span>⚡ {tokRate} TOKENS / SEC</span>
                </div>
              </div>

              <div className="border border-[#222222] bg-[#060608] p-3 my-2 space-y-2 flex-1">
                <div className="text-[9px] text-[#71717a] font-bold uppercase border-b border-[#222222] pb-1 flex items-center justify-between">
                  <span>Ed25519 CRYPTOGRAPHIC ATTESTATION AUDIT</span>
                  <span className="text-[#22c55e]">VALID</span>
                </div>
                <div className="space-y-1.5 text-[10px]">
                  <div className="flex items-center justify-between text-[#888888]">
                    <span>[09:54:12.018] peer://muhaymin</span>
                    <span className="text-[#22c55e] font-semibold">SIG VERIFIED ✓</span>
                  </div>
                  <div className="flex items-center justify-between text-[#888888]">
                    <span>[09:54:12.022] peer://hrushikesh</span>
                    <span className="text-[#22c55e] font-semibold">SIG VERIFIED ✓</span>
                  </div>
                  <div className="flex items-center justify-between text-[#888888]">
                    <span>[09:54:12.025] AST Token Resolver</span>
                    <span className="text-white font-semibold">0 syntax collisions</span>
                  </div>
                  <div className="flex items-center justify-between text-[#888888]">
                    <span>[09:54:12.030] Ring Vector Clock [142, 89, 204]</span>
                    <span className="text-[#0055FF] font-semibold">Converged in 0.42ms</span>
                  </div>
                </div>
              </div>

              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-3.5 h-3.5 text-[#22c55e]" />
                  <span className="text-white">3 Authenticated Peers In Session</span>
                </div>
                <span className="text-[#0055FF] font-bold">SYNTAX HEALTH: 100%</span>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* FEATURE 7: ACTIONABLE OUTPUT (Bare-Metal ARM64 & 120 FPS WebGPU)          */}
          {/* ========================================================================= */}
          {mode === "output" && (
            <div className="flex-1 p-3 overflow-hidden flex flex-col justify-between font-mono bg-[#000000]">
              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-[#0055FF]" />
                  <span className="text-white font-bold">NATIVE HOST COMPILATION ARTIFACT</span>
                </div>
                <span className="px-1.5 py-0.5 bg-[#0055FF]/10 border border-[#0055FF]/30 text-[#0055FF] font-bold text-[10px]">
                  ARM64 / APPLE SILICON
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 my-2 flex-1 min-h-0">
                <div className="p-2.5 border border-[#222222] bg-[#060608] flex flex-col justify-between text-[10px]">
                  <div>
                    <div className="text-[9px] text-[#71717a] font-bold uppercase pb-1 border-b border-[#222222]">
                      MACH-O NATIVE BINARY
                    </div>
                    <div className="mt-2 space-y-1 text-white">
                      <div>Target: <strong className="text-[#0055FF]">aarch64-apple-darwin</strong></div>
                      <div>Build time: <strong className="text-white">140ms</strong></div>
                      <div className="text-[9px] text-[#71717a] truncate">SHA256: 7f8a9b2c4e11...</div>
                    </div>
                  </div>
                  <div className="pt-2 border-t border-[#222222] flex items-center justify-between text-[9px]">
                    <span className="text-[#71717a]">ZERO V8 CHROMIUM</span>
                    <span className="text-[#22c55e] font-bold">READY</span>
                  </div>
                </div>

                <div className="p-2.5 border border-[#222222] bg-[#060608] flex flex-col justify-between text-[10px]">
                  <div>
                    <div className="text-[9px] text-[#71717a] font-bold uppercase pb-1 border-b border-[#222222]">
                      WEBGPU 120 FPS CANVAS PREVIEW
                    </div>
                    <div className="mt-2 flex items-center justify-between">
                      <span className="text-white font-semibold">Instanced Quad Pipeline</span>
                      <span className="text-[#0055FF] font-bold">120 FPS</span>
                    </div>
                    <div className="flex items-end gap-1 h-5 mt-2 bg-[#000000] p-1 border border-[#222222]">
                      {[0.4, 0.9, 0.5, 1.0, 0.7, 0.9, 0.6].map((h, i) => (
                        <motion.div
                          key={i}
                          animate={{ height: [`${h * 100}%`, `${Math.max(20, (1 - h * 0.5) * 100)}%`, `${h * 100}%`] }}
                          transition={{ repeat: Infinity, duration: 0.7 + i * 0.15, ease: "easeInOut" }}
                          className="flex-1 bg-[#0055FF]"
                        />
                      ))}
                    </div>
                  </div>
                  <div className="pt-1 border-t border-[#222222] text-[9px] text-[#71717a]">
                    VSYNC LOCKED (8.33ms)
                  </div>
                </div>
              </div>

              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                <div className="flex items-center gap-2">
                  <GitBranch className="w-3 h-3 text-[#0055FF]" />
                  <span className="text-white">Atomic Commit: <code className="text-[#0055FF]">a9b42e1</code> (Lock-free AST refactor)</span>
                </div>
                <span className="text-[#22c55e] font-bold">SIGNED &amp; VERIFIED</span>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* 3. EXACT CRUX IDE STATUS BAR (CruxEditorView.tsx line 709) */}
      {showStatusBar && (
        <footer className="h-[22px] px-3 bg-[#000000] border-t border-[#222222] text-[#888888] flex items-center justify-between text-[10px] font-mono select-none shrink-0 z-30">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 hover:text-white cursor-pointer">
              <GitBranch className="w-3 h-3 text-[#71717a]" />
              <span className="text-white">main*</span>
            </div>
            <div className="hidden sm:flex items-center gap-1.5 cursor-pointer">
              <span className="w-1.5 h-1.5 bg-[#00FF66] rounded-none shadow-[0_0_6px_#00FF66]" />
              <span className="text-[10px] tracking-wider uppercase font-mono text-white">
                DISK IN-SYNC
              </span>
            </div>
            <span className="text-[10px] text-[#71717a] font-mono">0.08ms</span>

            {/* Revision History Badge */}
            <div className="hidden md:flex items-center gap-1 px-1.5 py-0.2 border border-[#222222] text-[#CCCCCC] text-[9px]">
              <History className="w-2.5 h-2.5" />
              <span className="font-bold uppercase tracking-wider">HISTORY</span>
              <span className="text-[8px] opacity-70">(14)</span>
            </div>
          </div>

          <div className="flex items-center gap-3 text-[#71717a]">
            <span>Ln 6, Col {cursorPosCol}</span>
            <span className="hidden sm:inline">UTF-8</span>
            <span className="uppercase text-white font-medium">
              {fileMeta.isMetal ? "METAL" : "TypeScript"}
            </span>
          </div>
        </footer>
      )}
    </div>
  );
}
