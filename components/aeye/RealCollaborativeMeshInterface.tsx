"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Plus,
  Download,
  Search,
  FolderPlus,
  FolderDown,
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
  Share2,
  PanelLeft,
  Sparkles,
  Unlock,
  GitBranch,
  Play,
  Save,
  Link2,
  SplitSquareVertical,
  Settings,
  Inbox,
  RefreshCw,
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
  className?: string;
}

export default function RealCollaborativeMeshInterface({
  mode = "multiplayer",
  className = "",
}: RealCollaborativeMeshInterfaceProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  // Mouse coordinate tracking for interactive Amoeba spotlight effect
  const [mousePos, setMousePos] = useState<{ x: number; y: number } | null>(null);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    setMousePos({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const handleMouseLeave = () => {
    setMousePos(null);
  };

  // State for user interactions inside the demo
  const [diffState, setDiffState] = useState<"pending" | "accepted" | "rejected">("pending");
  const [copiedLink, setCopiedLink] = useState(false);
  const [isSaved, setIsSaved] = useState(false);

  // Multiplayer live typing simulation by Muhaymin
  const [typedSuffix, setTypedSuffix] = useState("");
  const [muhayminStatus, setMuhayminStatus] = useState<"idle" | "typing" | "selecting">("idle");
  const [cursorPosCol, setCursorPosCol] = useState(22);

  // Cycling interaction loop for multiplayer
  useEffect(() => {
    if (mode !== "multiplayer") return;
    let timeout: NodeJS.Timeout;
    const targetText = " Hrushikesh";
    let index = 0;
    let loopMode: "typing" | "pausing" | "erasing" | "selecting" = "typing";

    const runLoop = () => {
      if (loopMode === "typing") {
        setMuhayminStatus("typing");
        if (index < targetText.length) {
          index += 1;
          setTypedSuffix(targetText.slice(0, index));
          setCursorPosCol(22 + index);
          timeout = setTimeout(runLoop, 180);
        } else {
          loopMode = "pausing";
          setMuhayminStatus("idle");
          timeout = setTimeout(runLoop, 2200);
        }
      } else if (loopMode === "pausing") {
        loopMode = "selecting";
        setMuhayminStatus("selecting");
        timeout = setTimeout(runLoop, 2000);
      } else if (loopMode === "selecting") {
        loopMode = "erasing";
        setMuhayminStatus("typing");
        timeout = setTimeout(runLoop, 350);
      } else if (loopMode === "erasing") {
        if (index > 0) {
          index -= 1;
          setTypedSuffix(targetText.slice(0, index));
          setCursorPosCol(22 + index);
          timeout = setTimeout(runLoop, 120);
        } else {
          loopMode = "typing";
          setMuhayminStatus("idle");
          timeout = setTimeout(runLoop, 1100);
        }
      }
    };

    timeout = setTimeout(runLoop, 500);
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

  // Active File and Window Meta based on active mode
  const fileMeta = useMemo(() => {
    switch (mode) {
      case "silicon":
        return {
          name: "spatial_engine.metal",
          folder: "kernel",
          path: "kernel/spatial_engine.metal",
          secondary: "profiler_dma.rs",
          isMetal: true,
          lines: 24,
          badge: "120 FPS METAL",
          spotlightPos: { x: "65%", y: "45%" },
        };
      case "crdt":
        return {
          name: "ast_crdt_sync.ts",
          folder: "crdt",
          path: "kernel/ast_crdt_sync.ts",
          secondary: "vector_clock.rs",
          isMetal: false,
          lines: 32,
          badge: "AST CONVERGED",
          spotlightPos: { x: "60%", y: "50%" },
        };
      case "agents":
        return {
          name: "stream_syncer.ts",
          folder: "agent",
          path: "src/stream_syncer.ts",
          secondary: "diff_view.patch",
          isMetal: false,
          lines: 18,
          badge: "@CRUXAI ACTIVE",
          spotlightPos: { x: "65%", y: "52%" },
        };
      case "context":
        return {
          name: "kernel_signals.ts",
          folder: "posix",
          path: "kernel/kernel_signals.ts",
          secondary: "inodes.bin",
          isMetal: false,
          lines: 48,
          badge: "64K INODES",
          spotlightPos: { x: "60%", y: "45%" },
        };
      case "processing":
        return {
          name: "crdt_synthesis.ts",
          folder: "synthesis",
          path: "kernel/crdt_synthesis.ts",
          secondary: "peer_attest.sec",
          isMetal: false,
          lines: 28,
          badge: "SYNTHESIS",
          spotlightPos: { x: "60%", y: "45%" },
        };
      case "output":
        return {
          name: "compiler_output.ts",
          folder: "build",
          path: "build/compiler_output.ts",
          secondary: "macho_arm64.bin",
          isMetal: false,
          lines: 36,
          badge: "ARM64 READY",
          spotlightPos: { x: "60%", y: "50%" },
        };
      case "multiplayer":
      default:
        return {
          name: "stream_syncer.ts",
          folder: "core",
          path: "src/stream_syncer.ts",
          secondary: "types.ts",
          isMetal: false,
          lines: 15,
          badge: "WEBRTC MESH",
          spotlightPos: { x: "62%", y: "46%" },
        };
    }
  }, [mode]);

  // Menu bar items matching CruxEditorView.tsx
  const menuItems = ["File", "Edit", "Selection", "View", "Go", "Run", "Terminal", "Help"];

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
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={`relative w-full h-full bg-[#000000] text-white flex flex-col select-none overflow-hidden font-sans border-0 ${className}`}
    >
      {/* ========================================================================= */}
      {/* AMOEBA SPOTLIGHT EFFECT: Interactive Radial Illumination Layer            */}
      {/* ========================================================================= */}
      <div
        className="absolute inset-0 pointer-events-none z-10 transition-opacity duration-500 ease-out"
        style={{
          background: mousePos
            ? `radial-gradient(550px circle at ${mousePos.x}px ${mousePos.y}px, rgba(0, 85, 255, 0.14) 0%, rgba(255, 255, 255, 0.03) 30%, transparent 70%)`
            : `radial-gradient(550px circle at ${fileMeta.spotlightPos.x} ${fileMeta.spotlightPos.y}, rgba(0, 85, 255, 0.14) 0%, rgba(255, 255, 255, 0.03) 30%, transparent 70%)`,
        }}
      />

      {/* ========================================================================= */}
      {/* 1. EXACT CRUX IDE TOP NAV (CruxEditorView.tsx lines 466-641)               */}
      {/* ========================================================================= */}
      <header className="h-10 px-3 border-b border-[#222222] bg-[#050507] flex items-center justify-between shrink-0 select-none z-30 font-sans">
        {/* Left: Brand + Quick Open Command Palette Search */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <CruxBrandLogo size={16} withText={true} />
            <span className="w-1.5 h-1.5 rounded-none bg-white ml-0.5" />
            <span className="text-[10px] text-[#888888] font-mono">0.08ms</span>
          </div>

          {/* Quick Open Command Palette Search matching line 474 */}
          <div className="hidden sm:flex items-center gap-2 px-2 py-0.5 bg-[#000000] border border-[#222222] text-[#888888] text-[10px]">
            <Search className="w-3 h-3 text-[#71717a]" />
            <span className="font-mono text-[#888888]">{fileMeta.name}</span>
            <kbd className="text-[9px] bg-[#111111] text-[#71717a] px-1 border border-[#222222] font-mono">⌘P</kbd>
          </div>
        </div>

        {/* Center: Segmented Control: Editor vs Canvas matching line 486 */}
        <div className="flex items-center bg-[#000000] border border-[#222222] p-0.5">
          <span className="px-3 py-0.5 text-[10px] font-medium tracking-wide uppercase bg-[#222222] text-white font-bold">
            Editor
          </span>
          <span className="px-3 py-0.5 text-[10px] font-medium tracking-wide uppercase text-[#71717a]">
            Canvas
          </span>
        </div>

        {/* Right Status & Actions matching lines 512-640 */}
        <div className="flex items-center gap-1.5">
          {/* Identity Pill Button */}
          <div className="hidden md:flex items-center gap-1.5 px-2 py-0.5 bg-[#000000] border border-[#222222] text-white text-[10px] font-mono">
            <BotAvatar
              type="mech"
              size={18}
              state="default"
              seed={avatarMotionSeed("Hrushikesh Gangala")}
              interactive={false}
              theme="dark"
            />
            <span className="truncate max-w-[85px] font-medium">Hrushikesh</span>
          </div>

          {/* Viewer Lock Quick Toggle */}
          <div className="hidden lg:flex items-center gap-1 px-1.5 py-0.5 text-[9px] font-mono uppercase tracking-wider border border-[#222222] bg-[#000000] text-[#888888]">
            <Unlock className="w-2.5 h-2.5" />
            <span>UNLOCKED</span>
          </div>

          {/* High-Density Multiplayer Presence matching lines 595 */}
          <div className="flex items-center border border-[#222222] rounded-none select-none bg-black">
            {/* Host Avatar: Hrushikesh Gangala */}
            <div
              title="Hrushikesh Gangala (Host)"
              className="px-1.5 py-0.5 flex items-center justify-center border-r border-[#222222] bg-transparent"
            >
              <BotAvatar
                type="mech"
                size={18}
                state="default"
                seed={avatarMotionSeed("Hrushikesh Gangala")}
                interactive={false}
                theme="dark"
              />
            </div>

            {/* Collaborator Avatar: Muhaymin */}
            <div
              title="Muhaymin (Remote Collaborator)"
              className="px-1.5 py-0.5 flex items-center justify-center border-r border-[#222222] bg-transparent"
            >
              <BotAvatar
                type="alien"
                size={18}
                state="default"
                seed={avatarMotionSeed("Muhaymin")}
                interactive={false}
                theme="dark"
              />
            </div>

            {/* AI Agent Avatar when in agents mode */}
            {mode === "agents" && (
              <div
                title="@CruxAI (Local Agent)"
                className="px-1.5 py-0.5 flex items-center justify-center border-r border-[#222222] bg-transparent"
              >
                <BotAvatar
                  type="droid"
                  size={18}
                  state="default"
                  seed={avatarMotionSeed("@CruxAI")}
                  interactive={false}
                  theme="dark"
                />
              </div>
            )}

            {/* Share Trigger */}
            <div className="px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider text-[#888888]">
              + SHARE
            </div>
          </div>

          {/* Window Layout Toggles matching lines 598-626 */}
          <div className="flex items-center gap-1">
            <div className="p-1 border border-[#222222] bg-[#222222] text-white">
              <PanelLeft className="w-3 h-3" />
            </div>
            <div className={`p-1 border border-[#222222] ${mode === "silicon" || mode === "output" ? "bg-[#222222] text-white" : "bg-[#000000] text-[#71717a]"}`}>
              <Terminal className="w-3 h-3" />
            </div>
            <div className={`p-1 border border-[#222222] ${mode === "agents" ? "bg-white text-black" : "bg-[#000000] text-[#71717a]"}`}>
              <Sparkles className="w-3 h-3" />
            </div>
          </div>

          {/* Share Button matching line 629 */}
          <div className="px-2.5 py-0.5 text-[10px] font-medium border border-[#222222] bg-[#000000] text-white uppercase flex items-center gap-1 hidden sm:flex">
            <Share2 className="w-3 h-3 text-current" />
            <span>Share</span>
          </div>
        </div>
      </header>

      {/* ========================================================================= */}
      {/* 1b. EXACT CRUX MENU BAR (CruxEditorView.tsx lines 643-655)                */}
      {/* ========================================================================= */}
      <div className="h-5 border-b border-[#111111] bg-[#050505] flex items-center px-3 shrink-0 select-none overflow-x-auto z-20">
        {menuItems.map((item) => (
          <span
            key={item}
            className="px-2.5 h-full text-[10px] text-[#71717a] hover:text-white flex items-center cursor-default font-sans"
          >
            {item}
          </span>
        ))}
      </div>

      {/* ========================================================================= */}
      {/* 2. MAIN LAYOUT: EXACT ZENITH FILE TREE + MAIN WORKBENCH                   */}
      {/* ========================================================================= */}
      <div className="flex-1 flex min-h-0 bg-[#000000] overflow-hidden z-20">
        {/* Left Sidebar: EXACT ZenithFileTree Clone with Real BranchedMenu */}
        <aside className="w-48 sm:w-52 border-r border-[#222222] bg-[#000000] flex flex-col select-none shrink-0 h-full font-sans">
          {/* Explorer Header matching ZenithFileTree.tsx line 357 */}
          <div className="px-3 py-1.5 border-b border-[#222222] text-[10px] font-bold tracking-widest text-[#888888] uppercase flex items-center justify-between">
            <span>Explorer</span>
            <div className="flex items-center gap-1.5 text-[#888888]">
              <Plus className="w-3 h-3 hover:text-white cursor-pointer" />
              <Download className="w-3 h-3 hover:text-white cursor-pointer" />
              <Search className="w-3 h-3 hover:text-white cursor-pointer" />
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
              rowHeight={28}
              indent={34}
              trunk={14}
              radius={6}
              lineWidth={1.2}
              fontSize={11}
              color="#888888"
              accentColor="#ffffff"
              lineColor="#222222"
            />
          </div>
        </aside>

        {/* Main Editor Pane: ZenithEditorPane clone */}
        <main className="flex-1 bg-[#000000] flex flex-col relative overflow-hidden font-sans min-w-0">
          {/* Tab Strip matching ZenithEditorPane.tsx line 226 */}
          <div className="flex h-7 border-b border-[#222222] bg-[#111111] items-center justify-between select-none shrink-0 overflow-x-auto">
            <div className="flex items-center h-full overflow-x-auto">
              {/* Active Tab */}
              <div className="px-3 border-r border-[#222222] text-[10px] font-sans uppercase tracking-tight flex items-center gap-1.5 transition-none shrink-0 h-full bg-[#000000] text-white font-medium">
                {fileMeta.isMetal ? (
                  <HugeiconsIcon icon={CodeIcon} size={11} strokeWidth={2} className="text-[#0055FF]" />
                ) : (
                  <HugeiconsIcon icon={JavaScriptIcon} size={11} strokeWidth={2} className="text-[#0055FF]" />
                )}
                <span>{fileMeta.name}</span>
                <span className="text-[9px] text-[#444444] font-mono shrink-0 hidden md:inline">
                  {fileMeta.lines}L
                </span>
                <span className="w-1.5 h-1.5 bg-white shrink-0 ml-1" />
                <span className="text-[#444444] hover:text-white cursor-pointer ml-1">×</span>
              </div>

              {/* Secondary Inactive Tab */}
              <div className="px-3 border-r border-[#222222] text-[10px] font-sans uppercase tracking-tight flex items-center gap-1.5 transition-none shrink-0 h-full bg-[#111111] text-[#666666] hover:text-white hidden sm:flex">
                <span>{fileMeta.secondary}</span>
                <span className="text-[#444444] hover:text-white cursor-pointer ml-1">×</span>
              </div>
            </div>

            {/* Tab Strip Right Controls matching ZenithEditorPane.tsx lines 265-342 */}
            <div className="flex items-center gap-1 px-2 shrink-0 bg-[#111111] h-full text-[10px] font-mono">
              <span className={`px-2 py-0.5 border text-[9px] uppercase ${mode === "silicon" ? "bg-white text-black font-bold border-white" : "border-[#222222] text-[#888888]"}`}>
                HARDWARE VIEW
              </span>
              <span className="px-2 py-0.5 border border-[#222222] bg-[#000000] text-white text-[9px] uppercase flex items-center gap-1 hidden md:flex font-bold">
                <Play className="w-2.5 h-2.5 fill-current text-[#0055FF]" />
                RUN ↵
              </span>
              <span className="text-[#0055FF] font-bold text-[9px] ml-1 flex items-center gap-1">
                <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                {fileMeta.badge}
              </span>
            </div>
          </div>

          {/* Breadcrumb Bar matching ZenithEditorPane.tsx line 346 */}
          <div className="h-6 px-3 border-b border-[#111111] bg-[#050505] flex items-center gap-1 text-[10px] font-mono text-[#555555] shrink-0 select-none overflow-hidden">
            <span className="text-[#444444]">WORKSPACE</span>
            <span className="text-[#333333] mx-1">/</span>
            <span className="text-[#888888]">{fileMeta.path}</span>
          </div>

          {/* ========================================================================= */}
          {/* FEATURE 1: REAL-TIME COLLABORATIVE MESH (Multiplayer with Live Cursors)   */}
          {/* ========================================================================= */}
          {mode === "multiplayer" && (
            <div className="flex-1 p-3 overflow-hidden relative font-mono text-[11px] leading-[1.65] bg-[#000000]">
              {/* REMOTE PEER 1: MUHAYMIN DART CURSOR */}
              <motion.div
                className="absolute pointer-events-none z-30 select-none"
                animate={{
                  x: [140, 210, 260, 230, 160, 140],
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
                  x: [210, 290, 360, 310, 240, 210],
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
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">1</span>
                  <span className="text-white">
                    <span className="text-[#0055FF] font-semibold">import</span> &#123; <span className="text-white font-medium">LocalWriteAheadLog</span> &#125; <span className="text-[#0055FF] font-semibold">from</span> <span className="text-[#ff914d]">"@crux/wal"</span>;
                  </span>
                </div>
                <div className="flex items-center">
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">2</span>
                  <span className="text-white">
                    <span className="text-[#0055FF] font-semibold">import</span> &#123; <span className="text-white font-medium">SyncVector</span> &#125; <span className="text-[#007AFF] font-semibold">from</span> <span className="text-[#ff914d]">"./types"</span>;
                  </span>
                </div>
                <div className="flex items-center">
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">3</span>
                  <span className="text-[#71717a] italic">// Lock-free peer stream syncer</span>
                </div>
                <div className="flex items-center">
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">4</span>
                  <span className="text-white">
                    <span className="text-[#0055FF] font-semibold">export const</span> wal = <span className="text-[#0055FF] font-semibold">new</span> LocalWriteAheadLog(&#123;
                  </span>
                </div>

                {/* Active Typing Line with Peer Tag */}
                <div className="flex items-center bg-[#ffffff]/5 pl-0.5 relative">
                  <span className="w-7 text-right text-[10px] text-white font-bold select-none pr-3">5</span>
                  <span className="text-white pl-3 font-mono relative">
                    path: <span className="text-[#ff914d]">"/var/crux/wal.bin"</span>,{typedSuffix}
                    <motion.span
                      animate={{ opacity: [1, 0, 1] }}
                      transition={{ repeat: Infinity, duration: 0.6 }}
                      className="w-1.5 h-3.5 bg-white inline-block ml-0.5 align-middle"
                    />
                  </span>
                </div>

                <div className="flex items-center">
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">6</span>
                  <span className="text-white pl-3">syncIntervalMs: <span className="text-[#ffbd2e]">16</span>, ringBufferSizeMb: <span className="text-[#ffbd2e]">64</span></span>
                </div>
                <div className="flex items-center">
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">7</span>
                  <span className="text-white">&#125;);</span>
                </div>

                {/* Active Selection Line with Hrushikesh Host Pill */}
                <div className={`flex items-center relative pl-0.5 ${muhayminStatus === "selecting" ? "bg-[#0055FF]/20 border-l-2 border-[#0055FF]" : ""}`}>
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">8</span>
                  <span className="text-white pl-3">
                    <span className="text-[#0055FF] font-semibold">export async function</span> <span className="text-[#ff914d]">persistStateVector</span>(
                  </span>
                </div>
                <div className={`flex items-center relative pl-0.5 ${muhayminStatus === "selecting" ? "bg-[#0055FF]/20 border-l-2 border-[#0055FF]" : ""}`}>
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">9</span>
                  <span className="text-white pl-6">docId: <span className="text-[#0055FF]">string</span>, vector: <span className="text-[#0055FF]">SyncVector</span></span>
                </div>
                <div className="flex items-center">
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">10</span>
                  <span className="text-white pl-3">): <span className="text-[#0055FF]">Promise</span>&lt;<span className="text-[#ffbd2e]">number</span>&gt; &#123;</span>
                </div>
                <div className="flex items-center">
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">11</span>
                  <span className="text-white pl-6">const monotonicSequence = <span className="text-[#0055FF] font-semibold">await</span> wal.append(&#123; docId, payload: vector.encode() &#125;);</span>
                </div>
                <div className="flex items-center">
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">12</span>
                  <span className="text-white pl-6"><span className="text-[#0055FF] font-semibold">return</span> monotonicSequence;</span>
                </div>
                <div className="flex items-center">
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3">13</span>
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
              <div className="border border-[#222222] bg-[#08080a] p-2.5 space-y-2.5">
                <div className="flex items-center justify-between text-xs pb-1 border-b border-[#222222]">
                  <div className="flex items-center gap-2">
                    <Zap className="w-3.5 h-3.5 text-[#0055FF]" />
                    <span className="text-white font-bold text-[11px]">WEBGPU / METAL TEXT RASTERIZER</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[10px] text-[#0055FF] font-bold">
                    <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                    <span>{fps} FPS (8.33ms VSYNC LOCKED)</span>
                  </div>
                </div>

                {/* 3 Metric Gauges Grid */}
                <div className="grid grid-cols-3 gap-2 text-left">
                  <div className="p-2 border border-[#222222] bg-[#0c0c0e]">
                    <div className="text-[9px] text-[#71717a] uppercase">Input-to-Photon</div>
                    <div className="text-sm sm:text-base text-white font-bold mt-0.5">4.2 ms</div>
                    <div className="text-[8px] sm:text-[9px] text-[#0055FF] font-semibold mt-0.5">11.5x vs Electron (48.6ms)</div>
                  </div>
                  <div className="p-2 border border-[#222222] bg-[#0c0c0e]">
                    <div className="text-[9px] text-[#71717a] uppercase">Unified VRAM</div>
                    <div className="text-sm sm:text-base text-white font-bold mt-0.5">38.2 MB</div>
                    <div className="text-[8px] sm:text-[9px] text-[#0055FF] font-semibold mt-0.5">17.8x leaner (vs 680MB)</div>
                  </div>
                  <div className="p-2 border border-[#222222] bg-[#0c0c0e]">
                    <div className="text-[9px] text-[#71717a] uppercase">Draw Calls</div>
                    <div className="text-sm sm:text-base text-white font-bold mt-0.5">1 Call</div>
                    <div className="text-[8px] sm:text-[9px] text-[#0055FF] font-semibold mt-0.5">per 50,000 text glyphs</div>
                  </div>
                </div>

                {/* Live 120Hz Oscilloscope Waveform */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-[9px] text-[#71717a]">
                    <span>FRAME TIME JITTER (120Hz VSYNC TIMELINE)</span>
                    <span className="text-[#0055FF] font-bold">ZERO FRAME DROPS</span>
                  </div>
                  <div className="flex items-end gap-1 h-5 bg-[#040406] border border-[#222222] px-1 py-0.5">
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
              <div className="p-2 border border-[#222222] bg-[#050507] text-[10px] leading-relaxed text-[#888888] space-y-0.5">
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
              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                <div className="flex items-center gap-2">
                  <GitMerge className="w-3.5 h-3.5 text-[#0055FF]" />
                  <span className="text-white font-bold">STRUCTURAL AST REPLICATION</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[#71717a]">VECTOR CLOCK:</span>
                  <span className="px-1.5 py-0.2 bg-[#141416] border border-[#222222] text-[#0055FF] font-bold">
                    [H: 142, M: 89, AI: 204]
                  </span>
                </div>
              </div>

              {/* Center Split: Concurrent Delta Stream vs AST Tree Visualizer */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 my-2 flex-1 min-h-0">
                {/* Left: Concurrent Mutations Stream */}
                <div className="p-2 border border-[#222222] bg-[#060608] flex flex-col justify-between text-[10px] space-y-1 overflow-hidden">
                  <div className="text-[#71717a] font-bold text-[9px] uppercase border-b border-[#222222] pb-1">
                    CONCURRENT PEER DELTAS
                  </div>
                  <div className="space-y-1 text-[10px]">
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
                  <div className="pt-1 border-t border-[#222222] flex items-center justify-between text-[9px] text-[#71717a]">
                    <span>STATUS: <strong className="text-white">DETERMINISTIC</strong></span>
                    <span className="text-[#22c55e] font-bold">100% HEALTH</span>
                  </div>
                </div>

                {/* Right: Structural AST Token Tree Visualizer */}
                <div className="p-2 border border-[#222222] bg-[#060608] flex flex-col justify-between text-[10px] space-y-1">
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
              <div className="p-1.5 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
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
          {/* FEATURE 4: AUTONOMOUS @CRUXAI AGENTS (Inline Diff View from Real IDE)     */}
          {/* ========================================================================= */}
          {mode === "agents" && (
            <div className="flex-1 p-3 overflow-hidden flex flex-col justify-between font-mono bg-[#000000]">
              {/* Agent Execution HUD Prompt matching ZenithTerminal.tsx */}
              <div className="p-2 border border-[#0055FF]/40 bg-[#0055FF]/10 space-y-1">
                <div className="flex items-center justify-between text-[10px]">
                  <div className="flex items-center gap-1.5">
                    <Bot className="w-3.5 h-3.5 text-[#0055FF]" />
                    <span className="text-white font-bold">@CruxAI AUTONOMOUS REFACTOR</span>
                  </div>
                  <span className="px-1.5 py-0.2 bg-[#0055FF] text-white text-[9px] font-bold">
                    LOCAL POSIX (0ms CLOUD)
                  </span>
                </div>
                <div className="text-[10px] text-white font-mono bg-[#000000] p-1.5 border border-[#222222]">
                  <span className="text-[#0055FF]">%</span> @CruxAI refactor ./src/stream_syncer.ts --optimize-atomic-locks
                </div>
              </div>

              {/* EXACT SUGGESTING MODE DIFF from ZenithEditorPane.tsx lines 448-472 */}
              <div className="my-2 border border-[#222222] bg-[#000000] flex-1 flex flex-col justify-between">
                <div className="flex justify-between items-center px-3 py-1 border-b border-[#222222] bg-[#08080a]">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 bg-[#0055FF] rounded-none" />
                    <span className="text-[10px] font-bold text-white tracking-wider uppercase font-mono">
                      @CruxAI Refactor Suggestion
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {diffState === "pending" ? (
                      <>
                        <button
                          type="button"
                          onClick={() => setDiffState("accepted")}
                          className="px-2 py-0.5 bg-white text-black font-mono text-[9px] uppercase font-bold hover:bg-[#CCCCCC] transition-none cursor-pointer"
                        >
                          Accept
                        </button>
                        <button
                          type="button"
                          onClick={() => setDiffState("rejected")}
                          className="px-2 py-0.5 border border-[#222222] bg-[#000000] text-[#888888] font-mono text-[9px] uppercase hover:text-white transition-none cursor-pointer"
                        >
                          Reject
                        </button>
                      </>
                    ) : (
                      <span className="text-[9px] font-mono text-[#22c55e] uppercase tracking-wider font-bold">
                        {diffState === "accepted" ? "[APPLIED ✓]" : "[REJECTED ✕]"}
                      </span>
                    )}
                  </div>
                </div>

                <div className="p-2.5 text-[11px] font-mono leading-relaxed space-y-1">
                  <div className="text-[#71717a]">
                    export async function syncPeerDelta(delta: PeerDelta) &#123;
                  </div>
                  <div className="bg-[#FF453A]/10 text-[#FF453A] px-2 py-0.5 border-l-2 border-[#FF453A] line-through">
                    - const lock = await this.daemon.acquireLock(channel);
                  </div>
                  <div className="bg-[#00FF66]/10 text-[#00FF66] px-2 py-0.5 border-l-2 border-[#00FF66] font-semibold">
                    + const ticket = await atomicBitset.claimTicket();
                  </div>
                  <div className="bg-[#00FF66]/10 text-[#00FF66] px-2 py-0.5 border-l-2 border-[#00FF66] font-semibold">
                    + await wal.commitLockFree(ticket);
                  </div>
                  <div className="text-[#71717a]">&#125;</div>
                </div>

                <div className="px-3 py-1 border-t border-[#222222] bg-[#050507] flex items-center justify-between text-[9px] text-[#71717a]">
                  <span>SANDBOX: <strong className="text-white">ISOLATED POSIX</strong></span>
                  <span className="text-[#22c55e] font-bold">CARGO/CLANG: 0 ERRORS</span>
                </div>
              </div>

              {/* Sub-pane: Terminal Compiler Pass Output */}
              <div className="p-1.5 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[9px]">
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-3 h-3 text-[#22c55e]" />
                  <span className="text-white">cargo check --target=aarch64-darwin: 0 errors (140ms)</span>
                </div>
                <span className="text-[#0055FF] font-mono font-bold">0ms CLOUD</span>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* FEATURE 5: CONTEXT AWARENESS (Raw POSIX Buffer & Inodes Ingest)           */}
          {/* ========================================================================= */}
          {mode === "context" && (
            <div className="flex-1 p-3 overflow-hidden flex flex-col justify-between font-mono bg-[#000000]">
              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                <div className="flex items-center gap-2">
                  <Database className="w-3.5 h-3.5 text-[#0055FF]" />
                  <span className="text-white font-bold">KERNEL CONTEXT PIPELINE</span>
                </div>
                <span className="text-[#0055FF] font-bold text-[9px]">
                  INGEST RATE: 3.2 GB/s
                </span>
              </div>

              <div className="border border-[#222222] bg-[#060608] p-2.5 my-2 space-y-1.5 flex-1">
                <div className="text-[9px] text-[#71717a] font-bold uppercase border-b border-[#222222] pb-1 flex items-center justify-between">
                  <span>RAW POSIX BUFFER DESCRIPTORS</span>
                  <span className="text-[#0055FF]">ZERO-COPY MEMORY MAP</span>
                </div>
                <div className="space-y-1 text-[10px]">
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

              <div className="p-1.5 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[9px]">
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
              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                <div className="flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-[#0055FF]" />
                  <span className="text-white font-bold">AST DELTA SYNTHESIS ENGINE</span>
                </div>
                <div className="flex items-center gap-1 text-[#0055FF] font-bold text-[9px]">
                  <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                  <span>⚡ {tokRate} TOKENS / SEC</span>
                </div>
              </div>

              <div className="border border-[#222222] bg-[#060608] p-2.5 my-2 space-y-1.5 flex-1">
                <div className="text-[9px] text-[#71717a] font-bold uppercase border-b border-[#222222] pb-1 flex items-center justify-between">
                  <span>Ed25519 CRYPTOGRAPHIC ATTESTATION AUDIT</span>
                  <span className="text-[#22c55e]">VALID</span>
                </div>
                <div className="space-y-1 text-[10px]">
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

              <div className="p-1.5 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[9px]">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-3 h-3 text-[#22c55e]" />
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
              <div className="p-2 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[10px]">
                <div className="flex items-center gap-2">
                  <Cpu className="w-3.5 h-3.5 text-[#0055FF]" />
                  <span className="text-white font-bold">NATIVE HOST COMPILATION ARTIFACT</span>
                </div>
                <span className="px-1.5 py-0.2 bg-[#0055FF]/10 border border-[#0055FF]/30 text-[#0055FF] font-bold text-[9px]">
                  ARM64 / APPLE SILICON
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 my-2 flex-1 min-h-0">
                <div className="p-2 border border-[#222222] bg-[#060608] flex flex-col justify-between text-[10px]">
                  <div>
                    <div className="text-[9px] text-[#71717a] font-bold uppercase pb-1 border-b border-[#222222]">
                      MACH-O NATIVE BINARY
                    </div>
                    <div className="mt-1.5 space-y-0.5 text-white">
                      <div>Target: <strong className="text-[#0055FF]">aarch64-apple-darwin</strong></div>
                      <div>Build time: <strong className="text-white">140ms</strong></div>
                      <div className="text-[9px] text-[#71717a] truncate">SHA256: 7f8a9b2c4e11...</div>
                    </div>
                  </div>
                  <div className="pt-1.5 border-t border-[#222222] flex items-center justify-between text-[9px]">
                    <span className="text-[#71717a]">ZERO V8 CHROMIUM</span>
                    <span className="text-[#22c55e] font-bold">READY</span>
                  </div>
                </div>

                <div className="p-2 border border-[#222222] bg-[#060608] flex flex-col justify-between text-[10px]">
                  <div>
                    <div className="text-[9px] text-[#71717a] font-bold uppercase pb-1 border-b border-[#222222]">
                      WEBGPU 120 FPS CANVAS PREVIEW
                    </div>
                    <div className="mt-1.5 flex items-center justify-between">
                      <span className="text-white font-semibold">Instanced Quad Pipeline</span>
                      <span className="text-[#0055FF] font-bold">120 FPS</span>
                    </div>
                    <div className="flex items-end gap-1 h-5 mt-1.5 bg-[#000000] p-1 border border-[#222222]">
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

              <div className="p-1.5 border border-[#222222] bg-[#08080a] flex items-center justify-between text-[9px]">
                <div className="flex items-center gap-1.5">
                  <GitBranch className="w-3 h-3 text-[#0055FF]" />
                  <span className="text-white">Atomic Commit: <code className="text-[#0055FF]">a9b42e1</code> (Lock-free AST refactor)</span>
                </div>
                <span className="text-[#22c55e] font-bold">SIGNED &amp; VERIFIED</span>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* ========================================================================= */}
      {/* 3. EXACT CRUX IDE STATUS BAR (CruxEditorView.tsx line 709)                */}
      {/* ========================================================================= */}
      <footer className="h-[22px] px-3 bg-[#000000] border-t border-[#222222] text-[#888888] flex items-center justify-between text-[10px] font-mono select-none shrink-0 z-30">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 hover:text-white cursor-pointer">
            <GitBranch className="w-3 h-3 text-[#71717a]" />
            <span className="text-white">main*</span>
          </div>
          <div className="hidden sm:flex items-center gap-1.5 cursor-pointer">
            <span className="w-1.5 h-1.5 bg-[#00FF66] rounded-none" />
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
    </div>
  );
}
