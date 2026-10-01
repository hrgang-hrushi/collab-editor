"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Search,
  Plus,
  Download,
  Play,
  Share2,
  Check,
  Layers,
  Cpu,
  Terminal,
  GitBranch,
  Zap,
} from "lucide-react";
import { motion } from "framer-motion";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";
import CruxPointerCursor from "@/components/crux/CruxPointerCursor";
import BranchedMenu, { BranchedMenuItem } from "@/components/crux/zenith/BranchedMenu";
import { BotAvatar } from "bot-avatars";
import {
  Folder01Icon,
  JavaScriptIcon,
  CodeIcon,
  File01Icon,
} from "@hugeicons/core-free-icons";
import { BorderBeam } from "@/components/ui/BorderBeam";

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

interface CleanCalloutCardProps {
  category: string;
  title: string;
  description: string;
  pill?: string;
  accentColor?: string;
  className?: string;
}

/**
 * Super straightforward, modern Callout Card with BorderBeam effect
 * Inspired by high-end design case-studies:
 * - Pure, minimal, frosted dark glass
 * - Crisp uppercase category header
 * - Concise, human-readable feature explanation
 * - Animated #0055FF border beam perimeter with slow, calm travel
 */
function CleanCalloutCard({
  category,
  title,
  description,
  pill,
  accentColor = "#0055FF",
  className = "",
}: CleanCalloutCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10, scale: 0.96 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: 6, scale: 0.98 }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      className={`relative ${className}`}
    >
      <BorderBeam
        size="md"
        colorVariant="ocean"
        strength={0.92}
        duration={12.0}
        theme="dark"
        borderRadius={8}
        className="w-full relative shadow-[0_25px_60px_rgba(0,0,0,0.95)]"
      >
        <div
          className="relative bg-[#05060b]/96 backdrop-blur-2xl border border-[#222222] p-3.5 sm:p-4 text-left select-none overflow-hidden"
          style={{ borderRadius: "8px" }}
        >
          {/* Top Decorative Micro-Accent */}
          <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-[#0055FF]/40 to-transparent" />

          {/* Header Row: Category Tag + Pill */}
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse" />
              <h3 className="text-[10px] font-mono font-bold uppercase tracking-[0.16em] text-[#a1a1aa]">
                {category}
              </h3>
            </div>
            {pill && (
              <span
                className="px-2 py-0.5 text-[8.5px] font-mono uppercase tracking-wider font-semibold rounded-[4px] border shrink-0 bg-[#0055FF]/10 text-[#0055FF] border-[#0055FF]/30"
              >
                {pill}
              </span>
            )}
          </div>

          {/* Title */}
          <h4 className="mt-1.5 text-[12.5px] sm:text-[13px] font-semibold text-white tracking-tight leading-snug">
            {title}
          </h4>

          {/* Description */}
          <p className="mt-1 text-[11px] sm:text-[11.5px] text-[#888888] leading-[1.55]">
            {description}
          </p>
        </div>
      </BorderBeam>
    </motion.div>
  );
}

export default function RealCollaborativeMeshInterface({
  mode = "multiplayer",
  className = "",
}: RealCollaborativeMeshInterfaceProps) {
  // Determine distinct active file per mode
  const initialFile = useMemo(() => {
    switch (mode) {
      case "context":
        return "workspace_index.ts";
      case "processing":
        return "ast_synthesis.ts";
      case "crdt":
        return "crdt_vector.rs";
      case "silicon":
        return "spatial_engine.metal";
      case "output":
        return "build_target.rs";
      case "agents":
      case "multiplayer":
      default:
        return "stream_syncer.ts";
    }
  }, [mode]);

  const [activeFile, setActiveFile] = useState(initialFile);
  const [diffState, setDiffState] = useState<"pending" | "accepted" | "rejected">("pending");
  const [copiedLink, setCopiedLink] = useState(false);

  // Sync activeFile when mode changes externally
  useEffect(() => {
    setActiveFile(initialFile);
  }, [initialFile]);

  // =========================================================================
  // MULTIPLAYER TYPING: 3 Avatars Advance in 100% Synchronized Velocity
  // Avatar 1: Blue (#0055FF) · "mech"
  // Avatar 2: Pink (#ff70a6) · "flower"
  // Avatar 3: Green (#16a34a) · "clover" (Deep emerald for optimal white text contrast)
  // All 3 use identical 23-char strings and 4px rectangle radii
  // =========================================================================
  const blueTarget = 'channel = "stream-mesh";'; // 23 chars
  const pinkTarget = "timeout = 2500; // fast";  // 23 chars
  const greenTarget = 'ticket.id + ":OK"; // 0ms'; // 23 chars

  const [typingStep, setTypingStep] = useState(0);

  useEffect(() => {
    if (mode !== "multiplayer") return;

    const targetLen = 23;
    let step = 0;
    let dir = 1;
    let pauseTicks = 0;

    const timer = setInterval(() => {
      if (dir === 1) {
        step++;
        if (step >= targetLen) {
          dir = 0;
          pauseTicks = 0;
        }
      } else if (dir === 0) {
        pauseTicks++;
        if (pauseTicks > 18) {
          dir = -1;
        }
      } else if (dir === -1) {
        step--;
        if (step <= 0) {
          dir = 2;
          pauseTicks = 0;
        }
      } else if (dir === 2) {
        pauseTicks++;
        if (pauseTicks > 4) {
          dir = 1;
        }
      }

      setTypingStep(step);
    }, 75);

    return () => clearInterval(timer);
  }, [mode]);

  const blueText = useMemo(
    () => blueTarget.slice(0, typingStep),
    [blueTarget, typingStep]
  );
  const pinkText = useMemo(
    () => pinkTarget.slice(0, typingStep),
    [pinkTarget, typingStep]
  );
  const greenText = useMemo(
    () => greenTarget.slice(0, typingStep),
    [greenTarget, typingStep]
  );

  // Context scanning animation (for mode="context")
  const [scanLine, setScanLine] = useState(2);
  useEffect(() => {
    if (mode !== "context") return;
    const interval = setInterval(() => {
      setScanLine((prev) => (prev >= 5 ? 2 : prev + 1));
    }, 600);
    return () => clearInterval(interval);
  }, [mode]);

  // AST Processing delta tokens animation (for mode="processing")
  const [resolvedToken, setResolvedToken] = useState(104);
  useEffect(() => {
    if (mode !== "processing") return;
    const interval = setInterval(() => {
      setResolvedToken((prev) => (prev >= 120 ? 104 : prev + 1));
    }, 800);
    return () => clearInterval(interval);
  }, [mode]);

  // CRDT Convergence sequence (for mode="crdt")
  const [crdtEpoch, setCrdtEpoch] = useState(42);
  useEffect(() => {
    if (mode !== "crdt") return;
    const interval = setInterval(() => {
      setCrdtEpoch((prev) => (prev >= 60 ? 42 : prev + 1));
    }, 1000);
    return () => clearInterval(interval);
  }, [mode]);

  const handleCopy = () => {
    if (typeof window !== "undefined") {
      navigator.clipboard?.writeText("https://codecrux.us/?session=mesh-p2p");
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    }
  };

  // BranchedMenu Tree Data
  const branchedMenuItems: BranchedMenuItem[] = useMemo(() => {
    return [
      {
        label: "src",
        value: "src",
        icon: Folder01Icon,
        children: [
          {
            value: "stream_syncer.ts",
            label: "stream_syncer.ts",
            icon: JavaScriptIcon,
          },
          {
            value: "workspace_index.ts",
            label: "workspace_index.ts",
            icon: JavaScriptIcon,
          },
          {
            value: "ast_synthesis.ts",
            label: "ast_synthesis.ts",
            icon: JavaScriptIcon,
          },
          {
            value: "types.ts",
            label: "types.ts",
            icon: JavaScriptIcon,
          },
        ],
      },
      {
        label: "kernel",
        value: "kernel",
        icon: Folder01Icon,
        children: [
          {
            value: "spatial_engine.metal",
            label: "spatial_engine.metal",
            icon: CodeIcon,
          },
          {
            value: "crdt_vector.rs",
            label: "crdt_vector.rs",
            icon: CodeIcon,
          },
        ],
      },
      {
        label: "build",
        value: "build",
        icon: Folder01Icon,
        children: [
          {
            value: "build_target.rs",
            label: "build_target.rs",
            icon: CodeIcon,
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
      className={`relative w-full h-full bg-[#000000] text-white flex flex-col select-none overflow-visible ${className}`}
      style={{
        fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
      }}
    >
      {/* ========================================================================= */}
      {/* 1. TOP WINDOW BAR: Three Avatars from Codebase (Blue, Pink, Green)        */}
      {/* ========================================================================= */}
      <header className="h-9 px-3 border-b border-[#222222] bg-[#0c0c0c] flex items-center justify-between shrink-0 select-none z-20">
        {/* Left: Brand + Search */}
        <div className="flex items-center gap-3">
          <CruxBrandLogo size={16} withText={true} />
          <div className="hidden sm:flex items-center gap-2 px-2 py-0.5 bg-[#000000] border border-[#222222] text-[#888888] text-[10px] rounded-[4px]">
            <Search className="w-3 h-3 text-[#71717a]" />
            <span className="font-mono text-[#888888]">{activeFile}</span>
            <kbd className="text-[9px] bg-[#111111] text-[#71717a] px-1 border border-[#222222] font-mono rounded-[2px]">⌘P</kbd>
          </div>
        </div>

        {/* Center: Editor / Canvas Toggle */}
        <div className="flex items-center bg-[#000000] border border-[#222222] p-0.5 rounded-[4px]">
          <span className="px-2.5 py-0.5 text-[10px] font-mono uppercase bg-[#222222] text-white font-bold rounded-[3px]">
            Editor
          </span>
          <span className="px-2.5 py-0.5 text-[10px] font-mono uppercase text-[#71717a] hidden sm:inline">
            Canvas
          </span>
        </div>

        {/* Right: Three Avatars from Codebase matching Colors + Actions */}
        <div className="flex items-center gap-2">
          {mode === "multiplayer" ? (
            <div className="flex items-center gap-2 px-2 py-0.5 border border-[#222226] rounded-[6px] bg-transparent">
              <div className="flex items-center -space-x-1.5">
                {/* Avatar 1: Blue Mech - no background, color matches editing blue */}
                <div
                  className="w-5 h-5 flex items-center justify-center bg-transparent"
                  title="Hrushi"
                >
                  <BotAvatar type="mech" color="#0055FF" size={19} state="default" interactive={false} theme="dark" />
                </div>
                {/* Avatar 2: Pink Flower - no background, color matches editing pink */}
                <div
                  className="w-5 h-5 flex items-center justify-center bg-transparent"
                  title="Erik"
                >
                  <BotAvatar type="flower" color="#ff70a6" size={19} state="default" interactive={false} theme="dark" />
                </div>
                {/* Avatar 3: Green Clover - no background, color matches editing green */}
                <div
                  className="w-5 h-5 flex items-center justify-center bg-transparent"
                  title="Muhaymin"
                >
                  <BotAvatar type="clover" color="#16a34a" size={19} state="default" interactive={false} theme="dark" />
                </div>
              </div>
              <span className="text-[10px] font-mono text-white font-medium pl-0.5 hidden sm:inline">
                3 Active
              </span>
            </div>
          ) : mode === "agents" ? (
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#111111] border border-[#222222] text-[10px] font-mono text-white rounded-[4px]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#16a34a]" />
              <span>@CruxAI Active</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#111111] border border-[#222222] text-[10px] font-mono text-white rounded-[4px]">
              <span className="w-1.5 h-1.5 rounded-full bg-white" />
              <span>Host</span>
            </div>
          )}

          <button
            type="button"
            className="px-2 py-0.5 border border-[#222222] hover:border-white bg-[#000000] hover:bg-white hover:text-black text-white font-mono text-[10px] uppercase transition-none cursor-pointer flex items-center gap-1 rounded-[4px]"
          >
            <Play className="w-2.5 h-2.5 fill-current text-white" />
            <span>Run ↵</span>
          </button>

          <button
            type="button"
            onClick={handleCopy}
            className="px-2 py-0.5 border border-[#222222] hover:border-white bg-[#000000] hover:bg-white hover:text-black text-white font-mono text-[10px] uppercase transition-none cursor-pointer hidden sm:flex items-center gap-1 rounded-[4px]"
          >
            {copiedLink ? <Check className="w-2.5 h-2.5" /> : <Share2 className="w-2.5 h-2.5" />}
            <span>{copiedLink ? "Copied" : "Share"}</span>
          </button>
        </div>
      </header>

      {/* ========================================================================= */}
      {/* 2. MAIN WORKBENCH: ZERO-SCROLL SPLIT CANVAS                                */}
      {/* ========================================================================= */}
      <div className="flex-1 flex min-h-0 bg-[#000000] overflow-visible">
        {/* Left Sidebar: Compact Explorer */}
        <aside className="w-36 sm:w-44 border-r border-[#222222] bg-[#000000] flex flex-col shrink-0 select-none">
          <div className="px-3 py-1.5 border-b border-[#222222] text-[9.5px] font-bold tracking-widest text-[#888888] uppercase flex items-center justify-between font-mono">
            <span>Explorer</span>
            <div className="flex items-center gap-1.5 text-[#666666]">
              <Plus className="w-3 h-3 hover:text-white cursor-pointer" />
              <Download className="w-3 h-3 hover:text-white cursor-pointer" />
            </div>
          </div>

          <div className="flex-1 py-1 font-mono text-xs overflow-hidden">
            <BranchedMenu
              items={branchedMenuItems}
              defaultOpen={[0, 1, 2]}
              active={activeFile}
              onSelect={(val) => {
                if (val && !val.includes("/")) {
                  setActiveFile(val);
                }
              }}
              width="100%"
              rowHeight={26}
              indent={24}
              trunk={10}
              radius={4}
              lineWidth={1.5}
              fontSize={10.5}
              color="#888888"
              accentColor="#ffffff"
              lineColor="#222222"
            />
          </div>
        </aside>

        {/* Right Main Editor Pane */}
        <main className="flex-1 bg-[#000000] flex flex-col min-w-0 overflow-visible relative">
          {/* Tab Strip */}
          <div className="flex h-7 border-b border-[#222222] bg-[#111111] items-center justify-between select-none shrink-0 px-1">
            <div className="flex items-center h-full">
              <div className="px-3 border-r border-[#222222] text-[10px] font-mono uppercase tracking-tight flex items-center gap-1.5 h-full bg-[#000000] text-white font-medium">
                <span>{activeFile}</span>
                <span className="text-[#444444] hover:text-white cursor-pointer ml-1">×</span>
              </div>
              <div className="px-3 border-r border-[#222222] text-[10px] font-mono uppercase tracking-tight flex items-center gap-1.5 h-full bg-[#111111] text-[#666666] hover:text-white hidden sm:flex">
                <span>types.ts</span>
                <span className="text-[#444444] hover:text-white cursor-pointer ml-1">×</span>
              </div>
            </div>
          </div>

          {/* Code Canvas Area: overflow-visible ensures floating card renders cleanly */}
          <div className="flex-1 p-3 sm:p-4 overflow-visible font-mono text-[11.5px] sm:text-[12px] leading-[1.65] bg-[#000000] relative flex flex-col justify-center">
            {/* =================================================================== */}
            {/* DEMO 1: REAL-TIME COLLABORATIVE MESH                                */}
            {/* 3 Peers typing with their names: Erik, Hrushi, Muhaymin             */}
            {/* No avatars while typing, just names; Rounded edges (4px)            */}
            {/* =================================================================== */}
            {mode === "multiplayer" && (
              <div className="space-y-1 relative">
                <div className="flex items-baseline whitespace-nowrap">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">1</span>
                  <span>
                    <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">LocalDaemonClient</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/daemon&quot;</span>;
                  </span>
                </div>
                <div className="flex items-baseline whitespace-nowrap">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">2</span>
                  <span>
                    <span className="text-[#569cd6]">export class</span> <span className="text-[#4ec9b0]">StreamSyncer</span> &#123;
                  </span>
                </div>

                {/* Line 3: Erik (Pink - no avatar while typing, just name) */}
                <div className="flex items-baseline bg-white/5 py-1 rounded-[4px] whitespace-nowrap">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none shrink-0">3</span>
                  <span className="pl-4 inline-flex items-center whitespace-nowrap">
                    <span className="text-[#9cdcfe]">timeout</span>&nbsp;=&nbsp;
                    <span className="relative inline-flex items-center h-[22px] bg-[#ff70a6]/15 border border-[#ff70a6] rounded-[4px] px-2 py-0.5 text-white mx-1">
                      <span className="inline-block min-w-[2px]">{pinkText}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#ff70a6] ml-1 rounded-[1px] align-middle animate-pulse shrink-0" />
                      {/* Cursor placed on right side UNDER the actual change */}
                      <span className="absolute top-full right-0 mt-1.5 pointer-events-none z-30 select-none">
                        <CruxPointerCursor
                          name="Erik"
                          color="#ff70a6"
                          borderRadius="4px"
                          status="editing"
                        />
                      </span>
                    </span>
                  </span>
                </div>

                <div className="flex items-baseline whitespace-nowrap">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">4</span>
                  <span className="pl-4 whitespace-nowrap">
                    <span className="text-[#9cdcfe]">daemon</span> = <span className="text-[#569cd6]">new</span> <span className="text-[#4ec9b0]">LocalDaemonClient</span>(&#123; <span className="text-[#9cdcfe]">port</span>: <span className="text-[#b5cea8]">7447</span> &#125;);
                  </span>
                </div>

                {/* Line 5: Hrushi (Blue - no avatar while typing, just name) */}
                <div className="flex items-baseline bg-white/5 py-1 rounded-[4px] whitespace-nowrap">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none shrink-0">5</span>
                  <span className="pl-4 inline-flex items-center whitespace-nowrap">
                    <span className="text-[#569cd6]">async</span>&nbsp;<span className="text-[#dcdcaa]">acquireLock</span>(
                    <span className="relative inline-flex items-center h-[22px] bg-[#0055FF]/15 border border-[#0055FF] rounded-[4px] px-2 py-0.5 text-white mx-1">
                      <span className="inline-block min-w-[2px]">{blueText}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#0055FF] ml-1 rounded-[1px] align-middle animate-pulse shrink-0" />
                      {/* Cursor placed on right side UNDER the actual change */}
                      <span className="absolute top-full right-0 mt-1.5 pointer-events-none z-30 select-none">
                        <CruxPointerCursor
                          name="Hrushi"
                          color="#0055FF"
                          borderRadius="4px"
                          status="typing"
                        />
                      </span>
                    </span>
                    )&nbsp;&#123;
                  </span>
                </div>

                <div className="flex items-baseline whitespace-nowrap">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">6</span>
                  <span className="pl-8 whitespace-nowrap">
                    <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">ticket</span> = <span className="text-[#569cd6]">await</span> <span className="text-[#569cd6]">this</span>.<span className="text-[#9cdcfe]">daemon</span>.<span className="text-[#dcdcaa]">acquireLock</span>(channel);
                  </span>
                </div>

                {/* Line 7: Muhaymin (Green - no avatar while typing, just name) */}
                <div className="flex items-baseline bg-white/5 py-1 rounded-[4px] whitespace-nowrap">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none shrink-0">7</span>
                  <span className="pl-8 inline-flex items-center whitespace-nowrap">
                    <span className="text-[#569cd6]">return</span>&nbsp;
                    <span className="relative inline-flex items-center h-[22px] bg-[#16a34a]/15 border border-[#16a34a] rounded-[4px] px-2 py-0.5 text-white mx-1">
                      <span className="inline-block min-w-[2px]">{greenText}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#16a34a] ml-1 rounded-[1px] align-middle animate-pulse shrink-0" />
                      {/* Cursor placed on right side UNDER the actual change */}
                      <span className="absolute top-full right-0 mt-1.5 pointer-events-none z-30 select-none">
                        <CruxPointerCursor
                          name="Muhaymin"
                          color="#16a34a"
                          borderRadius="4px"
                          status="sync"
                        />
                      </span>
                    </span>
                  </span>
                </div>

                <div className="flex items-baseline whitespace-nowrap">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">8</span>
                  <span className="pl-4">&#125;</span>
                </div>
                <div className="flex items-baseline whitespace-nowrap">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">9</span>
                  <span>&#125;</span>
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 2: CONTEXT AWARENESS (Layer 01 Architecture & Signal Pipeline) */}
            {/* =================================================================== */}
            {mode === "context" && (
              <div className="w-full h-full flex flex-col justify-between relative py-0.5">
                {/* CleanCalloutCard - Floating gracefully over bottom-right corner */}
                <CleanCalloutCard
                  category="CONTEXT AWARENESS"
                  title="Instant Project Context"
                  description="Ingests raw filesystem buffers, keystrokes, and AST tokens to index 64,280 workspace symbols in 0.08ms with zero cloud latency."
                  pill="0.08ms"
                  accentColor="#0055FF"
                  className="absolute bottom-2 right-2 sm:-bottom-5 sm:-right-5 z-40 w-[260px] sm:w-[285px] max-w-[calc(100%-16px)] pointer-events-auto"
                />

                {/* Top Architectural Telemetry & Ingestion Pipeline (Full Width) */}
                <div className="space-y-2 w-full">
                  {/* Telemetry pill row */}
                  <div className="flex flex-wrap items-center gap-2 text-[9px] font-mono">
                    <span className="px-2 py-0.5 bg-[#0055FF]/15 border border-[#0055FF]/40 text-[#0055FF] font-bold rounded-[3px] flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse" />
                      SIGNAL INGESTION ACTIVE
                    </span>
                    <span className="px-2 py-0.5 bg-[#111111] border border-[#222222] text-[#888888] rounded-[3px]">
                      kqueue/inotify: 1,420 files
                    </span>
                    <span className="px-2 py-0.5 bg-[#111111] border border-[#222222] text-[#888888] rounded-[3px]">
                      Lookup: 0.08ms (O(1))
                    </span>
                  </div>

                  {/* 3-Stage Signal Ingestion Mesh Pipeline (Spacious 3 columns) */}
                  <div className="grid grid-cols-3 gap-2 text-[10px] font-mono">
                    <div className="p-2 bg-[#0c0d14] border border-[#222222] rounded-[4px]">
                      <div className="text-[8.5px] text-[#71717a] uppercase tracking-wider font-semibold">Tier 1 · POSIX Daemon</div>
                      <div className="mt-0.5 text-white font-medium text-[10.5px]">kqueue / inotify</div>
                      <div className="text-[8.5px] text-[#0055FF]">120Hz Event Bus</div>
                    </div>
                    <div className="p-2 bg-[#0c0d14] border border-[#222222] rounded-[4px]">
                      <div className="text-[8.5px] text-[#71717a] uppercase tracking-wider font-semibold">Tier 2 · Tokenizer</div>
                      <div className="mt-0.5 text-white font-medium text-[10.5px]">TokenStream Lexer</div>
                      <div className="text-[8.5px] text-[#0055FF]">Zero-Copy Parser</div>
                    </div>
                    <div className="p-2 bg-[#0c0d14] border border-[#0055FF]/40 bg-[#0055FF]/5 rounded-[4px]">
                      <div className="text-[8.5px] text-[#0055FF] uppercase tracking-wider font-semibold">Tier 3 · Symbol Graph</div>
                      <div className="mt-0.5 text-white font-medium text-[10.5px]">64,280 Nodes</div>
                      <div className="text-[8.5px] text-[#16a34a]">2.1 MB In-Memory</div>
                    </div>
                  </div>
                </div>

                {/* Center Code Canvas (Full Width) */}
                <div className="my-2 py-2 border-y border-[#1c1c1f] space-y-1 font-mono text-[11px] sm:text-[11.5px] leading-relaxed w-full">
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-2 select-none shrink-0">1</span>
                    <span>
                      <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">TokenStream</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/kernel&quot;</span>;
                    </span>
                  </div>
                  <div className={`flex items-baseline whitespace-nowrap rounded-[3px] ${scanLine === 2 ? "bg-white/10" : ""}`}>
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-2 select-none shrink-0">2</span>
                    <span>
                      <span className="text-[#569cd6]">export function</span> <span className="text-[#dcdcaa]">indexWorkspace</span>(<span className="text-[#9cdcfe]">paths</span>: <span className="text-[#4ec9b0]">string</span>[]) &#123;
                    </span>
                  </div>
                  <div className={`flex items-baseline whitespace-nowrap rounded-[3px] ${scanLine === 3 ? "bg-white/10" : ""}`}>
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-2 select-none shrink-0">3</span>
                    <span className="pl-3">
                      <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">ast</span> = <span className="text-[#569cd6]">new</span> <span className="text-[#4ec9b0]">TokenStream</span>().<span className="text-[#dcdcaa]">parseAll</span>(<span className="text-[#9cdcfe]">paths</span>);
                    </span>
                  </div>
                  <div className="flex items-center justify-between bg-[#0055FF]/15 border border-[#0055FF]/40 px-2 py-0.5 rounded-[4px] whitespace-nowrap">
                    <div className="flex items-baseline whitespace-nowrap">
                      <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-2 select-none shrink-0">4</span>
                      <span className="pl-3">
                        <span className="text-[#569cd6]">return</span> <span className="text-[#9cdcfe]">ast</span>.<span className="text-[#dcdcaa]">buildSymbolIndex</span>();
                      </span>
                    </div>
                    <span className="text-[9px] font-mono text-[#0055FF] font-bold ml-2">
                      RESOLVED 0.08ms
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-2 select-none shrink-0">5</span>
                    <span>&#125;</span>
                  </div>
                </div>

                {/* Bottom Docked Live Symbol Inspector Bar (Full Width) */}
                <div className="p-2 bg-[#090a10] border border-[#222222] rounded-[4px] font-mono text-[9px] w-full">
                  <div className="flex items-center justify-between text-[#888888] pb-1 border-b border-[#1c1c1f]">
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse" />
                      <span className="uppercase tracking-wider font-semibold text-[#a1a1aa]">Symbol Graph Inspector</span>
                    </div>
                    <span className="text-[#0055FF] font-bold">LIVE DOCK · 0.08ms</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-1 text-[#888888]">
                    <div>Target: <span className="text-white font-medium">buildSymbolIndex()</span></div>
                    <div>Def: <span className="text-[#ce9178]">kernel/symbol_index.rs:94</span></div>
                    <div>Refs: <span className="text-white">1,420 files</span></div>
                    <div>Latency: <span className="text-[#16a34a] font-bold">0.08ms O(1)</span></div>
                  </div>
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 3: INTELLIGENT PROCESSING (Layer 02 AST-CRDT Pipeline)         */}
            {/* =================================================================== */}
            {mode === "processing" && (
              <div className="w-full h-full flex flex-col justify-between relative py-0.5">
                {/* CleanCalloutCard - Floating gracefully over bottom-right corner */}
                <CleanCalloutCard
                  category="INTELLIGENT PROCESSING"
                  title="Deterministic AST Synthesis"
                  description="Synthesizes concurrent peer mutations directly at the AST node level, eliminating text merge conflicts and broken syntax."
                  pill="CRDT V4"
                  accentColor="#0055FF"
                  className="absolute bottom-2 right-2 sm:-bottom-5 sm:-right-5 z-40 w-[260px] sm:w-[285px] max-w-[calc(100%-16px)] pointer-events-auto"
                />

                {/* Top Architectural Telemetry & AST Convergence Flow (Full Width) */}
                <div className="space-y-2 w-full">
                  {/* Telemetry pill row */}
                  <div className="flex flex-wrap items-center gap-2 text-[9px] font-mono">
                    <span className="px-2 py-0.5 bg-[#0055FF]/15 border border-[#0055FF]/40 text-[#0055FF] font-bold rounded-[3px] flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse" />
                      AST-CRDT CONVERGENCE
                    </span>
                    <span className="px-2 py-0.5 bg-[#111111] border border-[#222222] text-[#888888] rounded-[3px]">
                      Vector Clock: V[14, 29, 07]
                    </span>
                    <span className="px-2 py-0.5 bg-[#111111] border border-[#222222] text-[#16a34a] rounded-[3px]">
                      Conflicts: 0 (Grammar 100%)
                    </span>
                  </div>

                  {/* Concurrent Mutation Stream Orchestration (3 columns full width) */}
                  <div className="grid grid-cols-3 gap-2 text-[10px] font-mono">
                    <div className="p-2 bg-[#0c0d14] border border-[#222222] rounded-[4px]">
                      <div className="flex items-center justify-between text-[8.5px] text-[#71717a]">
                        <span>PEER A · SF (0x7F2A)</span>
                        <span className="text-[#0055FF]">SEQ #14</span>
                      </div>
                      <div className="mt-0.5 text-white font-mono text-[10px] truncate">
                        + INSERT Statement(LockGuard)
                      </div>
                      <div className="text-[8.5px] text-[#16a34a]">Deterministic Transform</div>
                    </div>
                    <div className="p-2 bg-[#0c0d14] border border-[#222222] rounded-[4px]">
                      <div className="flex items-center justify-between text-[8.5px] text-[#71717a]">
                        <span>PEER B · TOKYO (0x19B4)</span>
                        <span className="text-[#0055FF]">SEQ #29</span>
                      </div>
                      <div className="mt-0.5 text-white font-mono text-[10px] truncate">
                        + REPLACE Ident(ticket)
                      </div>
                      <div className="text-[8.5px] text-[#16a34a]">Sub-10ms Mesh Sync</div>
                    </div>
                    <div className="p-2 bg-[#0c0d14] border border-[#0055FF]/40 bg-[#0055FF]/5 rounded-[4px]">
                      <div className="flex items-center justify-between text-[8.5px] text-[#0055FF]">
                        <span>ENGINE · AST VECTOR</span>
                        <span className="text-[#16a34a]">SYNC</span>
                      </div>
                      <div className="mt-0.5 text-white font-mono text-[10px] truncate">
                        Resolved: 0x9e3f_c12a
                      </div>
                      <div className="text-[8.5px] text-[#0055FF]">Zero Merge Conflicts</div>
                    </div>
                  </div>
                </div>

                {/* Center Code Canvas (Full Width) */}
                <div className="my-2 py-2 border-y border-[#1c1c1f] space-y-1 font-mono text-[11px] sm:text-[11.5px] leading-relaxed w-full">
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-2 select-none shrink-0">1</span>
                    <span>
                      <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">SynthesizedTree</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/crdt&quot;</span>;
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-2 select-none shrink-0">2</span>
                    <span>
                      <span className="text-[#569cd6]">export function</span> <span className="text-[#dcdcaa]">synthesizeASTDelta</span>(<span className="text-[#9cdcfe]">delta</span>: <span className="text-[#4ec9b0]">ASTMutation</span>) &#123;
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-2 select-none shrink-0">3</span>
                    <span className="pl-3">
                      <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">tree</span> = <span className="text-[#4ec9b0]">SynthesizedTree</span>.<span className="text-[#dcdcaa]">resolve</span>(<span className="text-[#9cdcfe]">delta</span>.<span className="text-[#9cdcfe]">targetId</span>);
                    </span>
                  </div>
                  <div className="flex items-center justify-between bg-[#0055FF]/15 border border-[#0055FF]/40 px-2 py-0.5 rounded-[4px] whitespace-nowrap">
                    <div className="flex items-baseline whitespace-nowrap">
                      <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-2 select-none shrink-0">4</span>
                      <span className="pl-3">
                        <span className="text-[#569cd6]">return</span> <span className="text-[#9cdcfe]">tree</span>.<span className="text-[#dcdcaa]">transformDeterministic</span>(<span className="text-[#9cdcfe]">delta</span>.<span className="text-[#9cdcfe]">patch</span>, <span className="text-[#b5cea8]">0x{resolvedToken.toString(16)}</span>);
                      </span>
                    </div>
                    <span className="text-[9px] font-mono text-[#0055FF] font-bold ml-2">
                      AST CONVERGED
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-2 select-none shrink-0">5</span>
                    <span>&#125;</span>
                  </div>
                </div>

                {/* Bottom Docked AST State Inspector Bar (Full Width) */}
                <div className="p-2 bg-[#090a10] border border-[#222222] rounded-[4px] font-mono text-[9px] w-full">
                  <div className="flex items-center justify-between text-[#888888] pb-1 border-b border-[#1c1c1f]">
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#16a34a] animate-pulse" />
                      <span className="uppercase tracking-wider font-semibold text-[#a1a1aa]">AST Vector State</span>
                    </div>
                    <span className="text-[#16a34a] font-bold">CONVERGED · 0 CONFLICTS</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-1 text-[#888888]">
                    <div>Syntax: <span className="text-[#16a34a] font-medium">Valid AST</span></div>
                    <div>Root Hash: <span className="text-white font-mono">0x9e3f_c12a</span></div>
                    <div>Conflict Rate: <span className="text-[#16a34a] font-bold">0.000%</span></div>
                    <div>Sync Latency: <span className="text-white">8.4ms P2P</span></div>
                  </div>
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 4: ACTIONABLE OUTPUT (Layer 03 LLVM Pipeline & POSIX Sandbox) */}
            {/* =================================================================== */}
            {mode === "output" && (
              <div className="w-full h-full flex flex-col justify-between relative py-0.5">
                {/* CleanCalloutCard - Floating gracefully over bottom-right corner */}
                <CleanCalloutCard
                  category="ACTIONABLE OUTPUT"
                  title="Instant Native Binaries"
                  description="Compiles verified ARM64 machine binaries and verifies atomic git diffs locally inside an isolated POSIX namespace in 140ms."
                  pill="140ms"
                  accentColor="#0055FF"
                  className="absolute bottom-2 right-2 sm:-bottom-5 sm:-right-5 z-40 w-[260px] sm:w-[285px] max-w-[calc(100%-16px)] pointer-events-auto"
                />

                {/* Top Architectural 3-Stage LLVM Compilation Pipeline (Full Width) */}
                <div className="space-y-2 w-full">
                  {/* Telemetry pill row */}
                  <div className="flex flex-wrap items-center gap-2 text-[9px] font-mono">
                    <span className="px-2 py-0.5 bg-[#0055FF]/15 border border-[#0055FF]/40 text-[#0055FF] font-bold rounded-[3px] flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse" />
                      LLVM NATIVE BACKEND
                    </span>
                    <span className="px-2 py-0.5 bg-[#111111] border border-[#222222] text-[#888888] rounded-[3px]">
                      Target: aarch64-apple-darwin
                    </span>
                    <span className="px-2 py-0.5 bg-[#111111] border border-[#222222] text-[#16a34a] rounded-[3px]">
                      140ms Native Compile
                    </span>
                  </div>

                  {/* 3-Stage Native Pipeline (Full Width 3 Columns) */}
                  <div className="grid grid-cols-3 gap-2 text-[10px] font-mono">
                    <div className="p-2 bg-[#0c0d14] border border-[#222222] rounded-[4px]">
                      <div className="text-[8.5px] text-[#71717a] uppercase tracking-wider font-semibold">Stage 1 · Semantic Pass</div>
                      <div className="mt-0.5 text-white font-medium text-[10.5px]">AST Validation</div>
                      <div className="text-[8.5px] text-[#16a34a]">PASS · 12ms</div>
                    </div>
                    <div className="p-2 bg-[#0c0d14] border border-[#222222] rounded-[4px]">
                      <div className="text-[8.5px] text-[#71717a] uppercase tracking-wider font-semibold">Stage 2 · Optimizer</div>
                      <div className="mt-0.5 text-white font-medium text-[10.5px]">LLVM IR (O3 SIMD)</div>
                      <div className="text-[8.5px] text-[#16a34a]">PASS · 48ms</div>
                    </div>
                    <div className="p-2 bg-[#0c0d14] border border-[#0055FF]/40 bg-[#0055FF]/5 rounded-[4px]">
                      <div className="text-[8.5px] text-[#0055FF] uppercase tracking-wider font-semibold">Stage 3 · Code Emitter</div>
                      <div className="mt-0.5 text-white font-medium text-[10.5px]">Mach-O ARM64</div>
                      <div className="text-[8.5px] text-[#0055FF]">READY · 80ms</div>
                    </div>
                  </div>
                </div>

                {/* Center / Lower: Isolated POSIX Terminal & Atomic Patch Sandbox (Full Width) */}
                <div className="mt-2 pt-2 border-t border-[#1c1c1f] flex flex-col flex-1 min-h-0 w-full">
                  <div className="bg-[#07080d] border border-[#222222] rounded-[4px] p-2.5 font-mono text-[10px] space-y-1.5 overflow-hidden flex-1 flex flex-col justify-center">
                    <div className="flex items-center justify-between text-[#71717a] pb-1 border-b border-[#1c1c1f] text-[8.5px]">
                      <span className="flex items-center gap-1.5 text-[#a1a1aa]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#16a34a]" />
                        POSIX Sandbox Terminal · /dev/pts/0
                      </span>
                      <span className="text-[#0055FF] font-semibold">ISOLATED OS NAMESPACE</span>
                    </div>
                    <div className="text-[#888888] whitespace-nowrap">
                      <span className="text-[#569cd6]">$</span> crux build --target aarch64-apple-darwin --release
                    </div>
                    <div className="text-[#4ec9b0] pl-2 whitespace-nowrap font-medium">
                      ✓ Emitted native binary <span className="text-white font-semibold">target/release/crux-core</span> (2.4 MB Mach-O) in 140ms
                    </div>
                    <div className="text-[#888888] whitespace-nowrap">
                      <span className="text-[#569cd6]">$</span> crux test --isolated
                    </div>
                    <div className="text-[#16a34a] pl-2 font-medium whitespace-nowrap">
                      ✓ 8/8 unit tests passed (0 failures) · 0 memory leaks · 4.2ms latency
                    </div>
                    <div className="text-[#888888] whitespace-nowrap">
                      <span className="text-[#569cd6]">$</span> git diff --stat
                    </div>
                    <div className="text-white/80 pl-2 whitespace-nowrap">
                      src/stream_syncer.ts | 2 +- (1 file changed) [STAGED & COMPILED]
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 5: DECENTRALIZED AST-CRDT                                      */}
            {/* =================================================================== */}
            {mode === "crdt" && (
              <div className="w-full h-full flex flex-col justify-between relative py-0.5">
                {/* CleanCalloutCard - Floating gracefully over bottom-right corner */}
                <CleanCalloutCard
                  category="DECENTRALIZED CRDT"
                  title="Collision-Free Sync"
                  description="Decentralized CRDT ensures every keystroke lands in deterministic order across all team members."
                  pill="< 1ms"
                  accentColor="#0055FF"
                  className="absolute bottom-2 right-2 sm:-bottom-5 sm:-right-5 z-40 w-[260px] sm:w-[285px] max-w-[calc(100%-16px)] pointer-events-auto"
                />

                <div className="space-y-1 w-full font-mono text-[11px] sm:text-[11.5px] leading-relaxed">
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">1</span>
                    <span>
                      <span className="text-[#569cd6]">use</span> crux_crdt::&#123;<span className="text-[#4ec9b0]">ASTVectorTree</span>, <span className="text-[#4ec9b0]">ASTPatch</span>&#125;;
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">2</span>
                    <span>
                      <span className="text-[#569cd6]">impl</span> <span className="text-[#4ec9b0]">ASTVectorTree</span> &#123;
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">3</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">pub fn</span> <span className="text-[#dcdcaa]">merge_deterministic</span>(&amp;<span className="text-[#569cd6]">mut self</span>, <span className="text-[#9cdcfe]">patch</span>: &amp;<span className="text-[#4ec9b0]">ASTPatch</span>) -&gt; <span className="text-[#4ec9b0]">Result</span>&lt;<span className="text-[#569cd6]">{`u64`}</span>&gt; &#123;
                    </span>
                  </div>

                  {/* Line 4: Active Probe Token with horizontal connector */}
                  <div className="flex items-center justify-between bg-white/5 py-1 rounded-[4px] relative whitespace-nowrap">
                    <div className="flex items-baseline min-w-0">
                      <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none shrink-0">4</span>
                      <span className="pl-8">
                        <span className="text-[#569cd6]">let</span> <span className="text-[#9cdcfe]">epoch</span> = <span className="text-[#569cd6]">self</span>.<span className="text-[#9cdcfe]">vector_clock</span>.<span className="text-[#dcdcaa]">fetch_add</span>(<span className="text-[#b5cea8]">1</span>, <span className="text-[#4ec9b0]">Ordering</span>::<span className="text-[#4ec9b0]">SeqCst</span>);
                      </span>
                      <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] rounded-[4px] px-2 py-0.5 text-white font-mono text-[9px]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                        <span>EPOCH: #{crdtEpoch}</span>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">5</span>
                    <span className="pl-8">
                      <span className="text-[#569cd6]">self</span>.<span className="text-[#dcdcaa]">apply_atomic_token</span>(<span className="text-[#9cdcfe]">patch</span>.<span className="text-[#dcdcaa]">token</span>(), <span className="text-[#9cdcfe]">epoch</span>);
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">6</span>
                    <span className="pl-4">&#125;</span>
                  </div>
                </div>

                {/* Bottom CRDT Vector Inspector */}
                <div className="p-2 bg-[#090a10] border border-[#222222] rounded-[4px] font-mono text-[9px] w-full">
                  <div className="flex items-center justify-between text-[#888888]">
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse" />
                      <span className="text-white font-medium">Vector Tree Clock: V[{crdtEpoch}, 14, 02]</span>
                    </div>
                    <span className="text-[#16a34a] font-bold">STATE CONVERGED</span>
                  </div>
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 6: NATIVE SILICON RUNTIME                                      */}
            {/* =================================================================== */}
            {mode === "silicon" && (
              <div className="w-full h-full flex flex-col justify-between relative py-0.5">
                {/* CleanCalloutCard - Floating gracefully over bottom-right corner */}
                <CleanCalloutCard
                  category="NATIVE SILICON RUNTIME"
                  title="Native GPU Rasterization"
                  description="Renders text directly via Metal & WebGPU compute shaders for butter-smooth 120 FPS input-to-photon latency."
                  pill="120 FPS"
                  accentColor="#0055FF"
                  className="absolute bottom-2 right-2 sm:-bottom-5 sm:-right-5 z-40 w-[260px] sm:w-[285px] max-w-[calc(100%-16px)] pointer-events-auto"
                />

                <div className="space-y-1 w-full font-mono text-[11px] sm:text-[11.5px] leading-relaxed">
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">1</span>
                    <span>
                      <span className="text-[#569cd6]">#include</span> <span className="text-[#ce9178]">&lt;metal_stdlib&gt;</span>
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">2</span>
                    <span>
                      <span className="text-[#569cd6]">kernel void</span> <span className="text-[#dcdcaa]">rasterize_glyph_quads</span>(
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">3</span>
                    <span className="pl-4">
                      device <span className="text-[#569cd6]">const</span> <span className="text-[#4ec9b0]">GlyphVertex</span>* <span className="text-[#9cdcfe]">vertices</span> [[buffer(0)]],
                    </span>
                  </div>

                  {/* Line 4: Active Probe Token with horizontal connector */}
                  <div className="flex items-center justify-between bg-white/5 py-1 rounded-[4px] relative whitespace-nowrap">
                    <div className="flex items-baseline min-w-0">
                      <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none shrink-0">4</span>
                      <span className="pl-4">
                        <span className="text-[#4ec9b0]">texture2d</span>&lt;<span className="text-[#569cd6]">float</span>&gt; <span className="text-[#9cdcfe]">atlas</span> [[texture(0)]]
                      </span>
                      <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] rounded-[4px] px-2 py-0.5 text-white font-mono text-[9px]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                        <span>120 FPS // METAL 3</span>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">5</span>
                    <span className="pl-4">
                      <span className="text-[#9cdcfe]">surface</span>.<span className="text-[#dcdcaa]">write</span>(<span className="text-[#dcdcaa]">sample_glyph</span>(<span className="text-[#9cdcfe]">atlas</span>), <span className="text-[#9cdcfe]">gid</span>);
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">6</span>
                    <span>&#125;</span>
                  </div>
                </div>

                {/* Bottom GPU Telemetry Inspector */}
                <div className="p-2 bg-[#090a10] border border-[#222222] rounded-[4px] font-mono text-[9px] w-full">
                  <div className="flex items-center justify-between text-[#888888]">
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse" />
                      <span className="text-white font-medium">Apple Silicon GPU · Metal Compute Pipeline</span>
                    </div>
                    <span className="text-[#16a34a] font-bold">120 FPS · 0.4ms FRAME TIME</span>
                  </div>
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 7: AUTONOMOUS @CRUXAI AGENTS                                   */}
            {/* =================================================================== */}
            {mode === "agents" && (
              <div className="w-full h-full flex flex-col justify-between relative py-0.5">
                {/* CleanCalloutCard - Floating gracefully over bottom-right corner */}
                <CleanCalloutCard
                  category="AUTONOMOUS @CRUXAI"
                  title="Context-Aware AI Assistant"
                  description="Proposes verified multi-file refactors and atomic git diffs that compile locally before you accept them."
                  pill="POSIX"
                  accentColor="#16a34a"
                  className="absolute bottom-2 right-2 sm:-bottom-5 sm:-right-5 z-40 w-[260px] sm:w-[285px] max-w-[calc(100%-16px)] pointer-events-auto"
                />

                {/* Top Code lines (Full Width) */}
                <div className="space-y-1 w-full font-mono text-[11px] sm:text-[11.5px] leading-relaxed">
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">1</span>
                    <span>
                      <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">LocalDaemonClient</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/daemon&quot;</span>;
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">2</span>
                    <span>
                      <span className="text-[#569cd6]">export class</span> <span className="text-[#4ec9b0]">StreamSyncer</span> &#123;
                    </span>
                  </div>

                  {/* Full-width Inline Diff Box */}
                  <div className="my-2 border border-[#222222] bg-[#0a0a0a] rounded-[6px] overflow-hidden w-full">
                    <div className="flex justify-between items-center px-3 py-1.5 border-b border-[#222222] bg-[#111111]">
                      <span className="text-[10px] font-mono text-white flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 bg-[#16a34a] rounded-full animate-pulse" />
                        <span className="font-semibold">@CruxAI proposes atomic bitset</span>
                        {diffState === "accepted" && (
                          <span className="ml-2 px-1.5 py-0.2 text-[9px] bg-black border border-[#222222] text-[#16a34a] font-mono rounded-[3px]">
                            [APPLIED ✓]
                          </span>
                        )}
                      </span>
                      <div className="flex items-center gap-1.5">
                        {diffState === "pending" ? (
                          <>
                            <button
                              type="button"
                              onClick={() => setDiffState("accepted")}
                              className="px-2.5 py-0.5 bg-white text-black font-mono text-[9px] uppercase font-bold hover:bg-[#CCCCCC] transition-none cursor-pointer rounded-[3px]"
                            >
                              Accept
                            </button>
                            <button
                              type="button"
                              onClick={() => setDiffState("rejected")}
                              className="px-2.5 py-0.5 border border-[#222222] bg-[#000000] text-[#888888] font-mono text-[9px] uppercase hover:text-white transition-none cursor-pointer rounded-[3px]"
                            >
                              Reject
                            </button>
                          </>
                        ) : (
                          <span className="text-[9px] font-mono text-[#16a34a] font-bold">
                            APPLIED
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="p-2.5 text-[10.5px] sm:text-[11px] leading-relaxed font-mono space-y-1">
                      <div className="bg-[#FF453A]/10 text-[#FF453A] px-2 py-1 border-l-2 border-[#FF453A] line-through rounded-r-[2px] whitespace-nowrap">
                        - const lock = await this.daemon.acquireLock(channel);
                      </div>
                      <div className="bg-[#16a34a]/10 text-[#16a34a] px-2 py-1 border-l-2 border-[#16a34a] font-semibold rounded-r-[2px] whitespace-nowrap">
                        + const ticket = await atomicBitset.claimTicket();
                      </div>
                    </div>
                  </div>

                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">3</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">return</span> ticket;
                    </span>
                  </div>
                  <div className="flex items-baseline whitespace-nowrap">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none shrink-0">4</span>
                    <span>&#125;</span>
                  </div>
                </div>

                {/* Bottom Agent Telemetry Bar */}
                <div className="p-2 bg-[#090a10] border border-[#222222] rounded-[4px] font-mono text-[9px] w-full">
                  <div className="flex items-center justify-between text-[#888888]">
                    <div className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#16a34a] animate-pulse" />
                      <span className="text-white font-medium">AST Verified &amp; Compiled Locally</span>
                    </div>
                    <span className="text-[#16a34a] font-bold">0 SYNTAX ERRORS · 118ms PASS</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
