"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Search,
  Plus,
  Download,
  Play,
  Share2,
  Check,
} from "lucide-react";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";
import CruxPointerCursor from "@/components/crux/CruxPointerCursor";
import BranchedMenu, { BranchedMenuItem } from "@/components/crux/zenith/BranchedMenu";
import {
  Folder01Icon,
  JavaScriptIcon,
  CodeIcon,
  File01Icon,
} from "@hugeicons/core-free-icons";

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

interface TelemetryMetric {
  label: string;
  value: string;
  sub: string;
}

interface BareMetalTelemetryHUDProps {
  channel: string;
  badge: string;
  title: string;
  desc: string;
  metrics: TelemetryMetric[];
  hexDump: string[];
  accentColor?: string;
  activeHexIndex?: number;
  className?: string;
}

/**
 * 10,000-Hour Bare-Metal Telemetry HUD Module
 * - Engineered hardware brutalist chassis with CAD registration marks
 * - Real-time animated oscilloscope signal waveform
 * - 4-Cell hardware performance matrix
 * - Dynamic live-cycling 8-byte DMA hex memory bus
 * - Precision input terminal socket where circuit leader line plugs in
 */
function BareMetalTelemetryHUD({
  channel,
  badge,
  title,
  desc,
  metrics,
  hexDump,
  accentColor = "#0055FF",
  activeHexIndex = 0,
  className = "",
}: BareMetalTelemetryHUDProps) {
  return (
    <div
      className={`relative border border-dashed bg-[#060812]/98 text-left p-3 sm:p-3.5 transition-all select-none shadow-[0_0_35px_rgba(0,85,255,0.14)] ${className}`}
      style={{
        borderColor: accentColor,
        borderRadius: "6px",
      }}
    >
      {/* Precision CAD Corner Registration Marks */}
      <span
        className="absolute -top-1.5 -left-1.5 font-mono text-[9px] leading-none select-none font-bold"
        style={{ color: accentColor }}
      >
        ┌
      </span>
      <span
        className="absolute -top-1.5 -right-1.5 font-mono text-[9px] leading-none select-none font-bold"
        style={{ color: accentColor }}
      >
        ┐
      </span>
      <span
        className="absolute -bottom-1.5 -left-1.5 font-mono text-[9px] leading-none select-none font-bold"
        style={{ color: accentColor }}
      >
        └
      </span>
      <span
        className="absolute -bottom-1.5 -right-1.5 font-mono text-[9px] leading-none select-none font-bold"
        style={{ color: accentColor }}
      >
        ┘
      </span>

      {/* Input Terminal Socket Header (Arrow plugs in directly above this socket) */}
      <div
        className="absolute -top-2.5 left-1/2 -translate-x-1/2 px-2 py-0.5 border font-mono text-[8px] uppercase tracking-wider font-bold flex items-center gap-1.5 z-20 shadow-md"
        style={{
          backgroundColor: "#060812",
          borderColor: accentColor,
          color: accentColor,
        }}
      >
        <span
          className="w-1.5 h-1.5 rounded-full animate-ping"
          style={{ backgroundColor: accentColor }}
        />
        <span>▲ PROBE INPUT: {channel}</span>
      </div>

      {/* Top Header Row with Live Oscilloscope Waveform */}
      <div className="flex items-center justify-between gap-2 pt-1 pb-2 border-b border-[#182033]">
        <div
          className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-wider font-bold"
          style={{ color: accentColor }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full animate-pulse"
            style={{ backgroundColor: accentColor }}
          />
          <span>{badge}</span>
        </div>

        {/* Live SVG Signal Waveform */}
        <div className="flex items-center gap-2">
          <svg className="w-16 h-4" viewBox="0 0 70 16" fill="none">
            <path
              d="M 0 8 Q 8 8, 12 3 T 20 13 T 28 8 T 38 8 Q 44 8, 48 2 T 54 14 T 62 8 H 70"
              stroke={accentColor}
              strokeWidth="1.2"
              strokeLinecap="round"
              className="opacity-80"
            />
          </svg>
          <span className="text-[8px] font-mono text-[#00FF66] font-bold">
            ● 120Hz
          </span>
        </div>
      </div>

      {/* 4-Cell Telemetry Metrics Matrix */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 my-2">
        {metrics.map((m, idx) => (
          <div
            key={idx}
            className="p-1.5 bg-[#0a0d18] border border-[#161f36] flex flex-col justify-between"
          >
            <span className="text-[7.5px] font-mono text-[#64748b] uppercase tracking-wider">
              {m.label}
            </span>
            <span className="text-[11px] font-mono font-bold text-white tracking-tight mt-0.5">
              {m.value}
            </span>
            <span className="text-[7px] font-mono text-[#00FF66] mt-0.5">
              {m.sub}
            </span>
          </div>
        ))}
      </div>

      {/* Architectural Explanation */}
      <div className="mt-1.5">
        <h4 className="text-[11.5px] font-medium text-white font-sans tracking-tight">
          {title}
        </h4>
        <p className="mt-0.5 text-[10px] font-sans text-[#94a3b8] leading-relaxed">
          {desc}
        </p>
      </div>

      {/* Live DMA Hex Register Dump */}
      <div className="mt-2 pt-1.5 border-t border-[#161f36] flex items-center justify-between font-mono text-[8px] text-[#64748b]">
        <div className="flex items-center gap-1">
          <span className="text-[#888888] hidden sm:inline">DMA_BUS:</span>
          <div className="flex items-center gap-0.5">
            {hexDump.map((byte, i) => (
              <span
                key={i}
                className={`px-1 py-0.2 rounded-none transition-colors ${
                  i === activeHexIndex
                    ? "bg-white text-black font-bold shadow-sm"
                    : "bg-[#101424] text-[#888888]"
                }`}
              >
                {byte}
              </span>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-1 text-[#00FF66] font-bold">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00FF66] animate-pulse" />
          <span>0-COPY MMAP</span>
        </div>
      </div>
    </div>
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
  // MULTIPLAYER TYPING SIMULATION: 3 Cursors Advance in 100% Lockstep
  // Hrushkesh Gangala (#0055FF), Rishi Eric (#ff70a6), Muhaiman (#00FF66)
  // Identical 23-char strings -> exact same velocity and forward direction
  // =========================================================================
  const hrushkeshTarget = 'channel = "stream-mesh";'; // 23 chars
  const rishiTarget = "timeout = 2500; // fast";     // 23 chars
  const muhaimanTarget = 'ticket.id + ":OK"; // 0ms'; // 23 chars

  const [typingStep, setTypingStep] = useState(0);

  useEffect(() => {
    if (mode !== "multiplayer") return;

    const targetLen = 23;
    let step = 0;
    let dir = 1; // 1: typing, 0: pause at end, -1: deleting, 2: pause at start
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

  const hrushkeshText = useMemo(
    () => hrushkeshTarget.slice(0, typingStep),
    [hrushkeshTarget, typingStep]
  );
  const rishiText = useMemo(
    () => rishiTarget.slice(0, typingStep),
    [rishiTarget, typingStep]
  );
  const muhaimanText = useMemo(
    () => muhaimanTarget.slice(0, typingStep),
    [muhaimanTarget, typingStep]
  );

  // Dynamic Cycling Byte for Hardware Telemetry Hex Dump
  const [activeHexIndex, setActiveHexIndex] = useState(0);
  useEffect(() => {
    const interval = setInterval(() => {
      setActiveHexIndex((prev) => (prev + 1) % 8);
    }, 450);
    return () => clearInterval(interval);
  }, []);

  // Context scanning animation (for mode="context")
  const [scanLine, setScanLine] = useState(2);
  useEffect(() => {
    if (mode !== "context") return;
    const interval = setInterval(() => {
      setScanLine((prev) => (prev >= 9 ? 2 : prev + 1));
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

  // BranchedMenu Tree Data with exact branches for all modes
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
      className={`relative w-full h-full bg-[#000000] text-white flex flex-col select-none overflow-hidden ${className}`}
      style={{
        fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
      }}
    >
      {/* ========================================================================= */}
      {/* 1. TOP WINDOW BAR (Matches CruxEditorView.tsx)                             */}
      {/* ========================================================================= */}
      <header className="h-9 px-3 border-b border-[#222222] bg-[#0c0c0c] flex items-center justify-between shrink-0 select-none z-20">
        {/* Left: Brand + Quick Search */}
        <div className="flex items-center gap-3">
          <CruxBrandLogo size={16} withText={true} />
          <div className="hidden sm:flex items-center gap-2 px-2 py-0.5 bg-[#000000] border border-[#222222] text-[#888888] text-[10px]">
            <Search className="w-3 h-3 text-[#71717a]" />
            <span className="font-mono text-[#888888]">{activeFile}</span>
            <kbd className="text-[9px] bg-[#111111] text-[#71717a] px-1 border border-[#222222] font-mono">⌘P</kbd>
          </div>
        </div>

        {/* Center: Editor / Canvas Toggle */}
        <div className="flex items-center bg-[#000000] border border-[#222222] p-0.5">
          <span className="px-2.5 py-0.5 text-[10px] font-mono uppercase bg-[#222222] text-white font-bold">
            Editor
          </span>
          <span className="px-2.5 py-0.5 text-[10px] font-mono uppercase text-[#71717a] hidden sm:inline">
            Canvas
          </span>
        </div>

        {/* Right: Collaborators & Action Buttons */}
        <div className="flex items-center gap-2">
          {mode === "multiplayer" ? (
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#111111] border border-[#222222] text-[10px] font-mono text-white">
              <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse" />
              <span>3 Peers (Hrushkesh, Rishi, Muhaiman)</span>
            </div>
          ) : mode === "agents" ? (
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#111111] border border-[#222222] text-[10px] font-mono text-white">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00FF66]" />
              <span>@CruxAI Active</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#111111] border border-[#222222] text-[10px] font-mono text-white">
              <span className="w-1.5 h-1.5 rounded-full bg-white" />
              <span>Host</span>
            </div>
          )}

          <button
            type="button"
            className="px-2 py-0.5 border border-[#222222] hover:border-white bg-[#000000] hover:bg-white hover:text-black text-white font-mono text-[10px] uppercase transition-none cursor-pointer flex items-center gap-1"
          >
            <Play className="w-2.5 h-2.5 fill-current text-white" />
            <span>Run ↵</span>
          </button>

          <button
            type="button"
            onClick={handleCopy}
            className="px-2 py-0.5 border border-[#222222] hover:border-white bg-[#000000] hover:bg-white hover:text-black text-white font-mono text-[10px] uppercase transition-none cursor-pointer hidden sm:flex items-center gap-1"
          >
            {copiedLink ? <Check className="w-2.5 h-2.5" /> : <Share2 className="w-2.5 h-2.5" />}
            <span>{copiedLink ? "Copied" : "Share"}</span>
          </button>
        </div>
      </header>

      {/* ========================================================================= */}
      {/* 2. MAIN LAYOUT: FILE TREE (BranchedMenu) + CODE EDITOR                      */}
      {/* ========================================================================= */}
      <div className="flex-1 flex min-h-0 bg-[#000000] overflow-hidden">
        {/* Left Sidebar: Exact BranchedMenu Tree Branch with White Reach Line */}
        <aside className="w-40 sm:w-48 border-r border-[#222222] bg-[#000000] flex flex-col shrink-0 select-none">
          <div className="px-3 py-1.5 border-b border-[#222222] text-[10px] font-bold tracking-widest text-[#888888] uppercase flex items-center justify-between font-mono">
            <span>Explorer</span>
            <div className="flex items-center gap-1.5 text-[#666666]">
              <Plus className="w-3 h-3 hover:text-white cursor-pointer" />
              <Download className="w-3 h-3 hover:text-white cursor-pointer" />
            </div>
          </div>

          {/* Real BranchedMenu with SVG Curved Branches & White Active Trace */}
          <div className="flex-1 py-1 font-mono text-xs overflow-y-auto">
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
              rowHeight={28}
              indent={28}
              trunk={12}
              radius={6}
              lineWidth={1.5}
              fontSize={11}
              color="#888888"
              accentColor="#ffffff"
              lineColor="#222222"
            />
          </div>
        </aside>

        {/* Right Main Editor Pane */}
        <main className="flex-1 bg-[#000000] flex flex-col min-w-0 overflow-hidden relative">
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

          {/* Code Canvas Area */}
          <div className="flex-1 p-3 sm:p-4 overflow-auto font-mono text-[12px] sm:text-[12.5px] leading-[1.7] bg-[#000000] relative">
            {/* =================================================================== */}
            {/* DEMO 1: REAL-TIME COLLABORATIVE MESH                                */}
            {/* 3 Cursors: Hrushkesh Gangala, Rishi Eric, Muhaiman                  */}
            {/* Synchronized typing at identical velocity; Cursors on right side    */}
            {/* UNDER the change boxes (top-full mt-1.5 right-0)                    */}
            {/* =================================================================== */}
            {mode === "multiplayer" && (
              <div className="space-y-0.5 relative">
                {/* Code Buffer */}
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                  <span>
                    <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">LocalDaemonClient</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/daemon&quot;</span>;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                  <span>
                    <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">SyncVector</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;./types&quot;</span>;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                  <span className="text-[#6a9955] italic">// Peer stream syncer</span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">4</span>
                  <span>
                    <span className="text-[#569cd6]">export class</span> <span className="text-[#4ec9b0]">StreamSyncer</span> &#123;
                  </span>
                </div>

                {/* Line 5: Rishi Eric typing (Pink box with cursor UNDER on right side) */}
                <div className="flex items-baseline bg-[#ffffff]/5 py-1">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">5</span>
                  <span className="pl-4">
                    <span className="text-[#9cdcfe]">timeout</span> ={" "}
                    <span className="relative inline-flex items-center bg-[#ff70a6]/15 border border-[#ff70a6] px-2 py-0.5 text-[#b5cea8] mx-1">
                      <span>{rishiText || "timeout = 2500; // fast"}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#ff70a6] ml-1 align-middle animate-pulse" />
                      {/* Cursor placed on right side UNDER the actual changes */}
                      <span className="absolute top-full right-0 mt-1.5 pointer-events-none z-30 select-none">
                        <CruxPointerCursor
                          name="Rishi Eric"
                          uid="RISHI-E"
                          color="#ff70a6"
                          status="editing"
                        />
                      </span>
                    </span>
                  </span>
                </div>

                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                  <span className="pl-4">
                    <span className="text-[#9cdcfe]">daemon</span> = <span className="text-[#569cd6]">new</span> <span className="text-[#4ec9b0]">LocalDaemonClient</span>(&#123; <span className="text-[#9cdcfe]">port</span>: <span className="text-[#b5cea8]">7447</span> &#125;);
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                  <span></span>
                </div>

                {/* Line 8: Hrushkesh Gangala typing (Blue box with cursor UNDER on right side) */}
                <div className="flex items-baseline bg-[#ffffff]/5 py-1">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">8</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">async</span> <span className="text-[#dcdcaa]">acquireLock</span>(
                    <span className="relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] px-2 py-0.5 text-[#ce9178] mx-1">
                      <span>{hrushkeshText || '"stream-mesh";'}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#0055FF] ml-1 align-middle animate-pulse" />
                      {/* Cursor placed on right side UNDER the actual changes */}
                      <span className="absolute top-full right-0 mt-1.5 pointer-events-none z-30 select-none">
                        <CruxPointerCursor
                          name="Hrushkesh Gangala"
                          uid="HRUSHKESH"
                          color="#0055FF"
                          status="typing"
                        />
                      </span>
                    </span>
                    ) &#123;
                  </span>
                </div>

                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">9</span>
                  <span className="pl-8">
                    <span className="text-[#9cdcfe]">console</span>.<span className="text-[#dcdcaa]">log</span>(<span className="text-[#ce9178]">&quot;[StreamSyncer] Lock acquired&quot;</span>);
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">10</span>
                  <span className="pl-8">
                    <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">ticket</span> = <span className="text-[#569cd6]">await</span> <span className="text-[#569cd6]">this</span>.<span className="text-[#9cdcfe]">daemon</span>.<span className="text-[#dcdcaa]">acquireLock</span>(channel);
                  </span>
                </div>

                {/* Line 11: Muhaiman typing (Green box with cursor UNDER on right side) */}
                <div className="flex items-baseline bg-[#ffffff]/5 py-1">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">11</span>
                  <span className="pl-8">
                    <span className="text-[#569cd6]">return</span>{" "}
                    <span className="relative inline-flex items-center bg-[#00FF66]/15 border border-[#00FF66] px-2 py-0.5 text-[#9cdcfe] mx-1">
                      <span>{muhaimanText || 'ticket.id + ":OK"; // 0ms'}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#00FF66] ml-1 align-middle animate-pulse" />
                      {/* Cursor placed on right side UNDER the actual changes */}
                      <span className="absolute top-full right-0 mt-1.5 pointer-events-none z-30 select-none">
                        <CruxPointerCursor
                          name="Muhaiman"
                          uid="MUHAIMAN"
                          color="#00FF66"
                          status="sync"
                        />
                      </span>
                    </span>
                  </span>
                </div>

                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">12</span>
                  <span className="pl-4">&#125;</span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">13</span>
                  <span>&#125;</span>
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 2: CONTEXT AWARENESS (AST Ingestion & Symbol Indexing Scanning) */}
            {/* Exact circuit bridge from Line 5 token directly into Telemetry HUD  */}
            {/* =================================================================== */}
            {mode === "context" && (
              <div className="space-y-0.5 relative">
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                  <span>
                    <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">TokenStream</span>, <span className="text-[#4ec9b0]">ASTBuffer</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/kernel&quot;</span>;
                  </span>
                </div>
                <div className={`flex items-baseline ${scanLine === 2 ? "bg-white/10" : ""}`}>
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                  <span>
                    <span className="text-[#569cd6]">export function</span> <span className="text-[#dcdcaa]">indexWorkspace</span>(<span className="text-[#9cdcfe]">paths</span>: <span className="text-[#4ec9b0]">string</span>[]) &#123;
                  </span>
                </div>
                <div className={`flex items-baseline ${scanLine === 3 ? "bg-white/10" : ""}`}>
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">stream</span> = <span className="text-[#569cd6]">new</span> <span className="text-[#4ec9b0]">TokenStream</span>(&#123; <span className="text-[#9cdcfe]">bufferDirect</span>: <span className="text-[#569cd6]">true</span> &#125;);
                  </span>
                </div>
                <div className={`flex items-baseline ${scanLine === 4 ? "bg-white/10" : ""}`}>
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">4</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">ast</span> = <span className="text-[#9cdcfe]">stream</span>.<span className="text-[#dcdcaa]">parseAll</span>(<span className="text-[#9cdcfe]">paths</span>);
                  </span>
                </div>

                {/* Line 5: Active Probe Token with Circuit Trace extending to Right Margin */}
                <div className="flex items-center justify-between bg-[#ffffff]/5 py-0.5 relative">
                  <div className="flex items-baseline min-w-0">
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">5</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">return</span> <span className="text-[#9cdcfe]">ast</span>.<span className="text-[#dcdcaa]">buildSymbolIndex</span>();
                    </span>
                    <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                      <span>64,280 NODES</span>
                    </span>
                  </div>

                  {/* Horizontal Circuit Trace heading out into free space */}
                  <div className="flex-1 flex items-center min-w-[20px] ml-2 mr-3 sm:mr-6">
                    <div className="w-full h-0 border-b border-dashed border-[#0055FF]/80" />
                    <div className="w-2.5 h-2.5 border-r border-t border-dashed border-[#0055FF] -ml-2.5 shrink-0" />
                  </div>
                </div>

                {/* Lines 6-9 with vertical circuit trace in right margin */}
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                    <span>&#125;</span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                    <span></span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                    <span className="text-[#6a9955] italic">// 0.08ms memory-mapped AST kernel buffer</span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">9</span>
                    <span>
                      <span className="text-[#569cd6]">export const</span> <span className="text-[#9cdcfe]">workspaceIndex</span> = <span className="text-[#dcdcaa]">indexWorkspace</span>([<span className="text-[#ce9178]">&quot;src/**/*.rs&quot;</span>]);
                    </span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>

                {/* Precision Circuit Bridge: Plunges directly into HUD's top socket */}
                <div className="flex flex-col items-center pt-2 pb-1 relative">
                  <div className="h-5 w-0 border-r border-dashed border-[#0055FF]" />
                  <div className="w-0 h-0 border-x-[5px] border-x-transparent border-t-[7px] border-t-[#0055FF] -mt-0.5" />
                </div>

                {/* 10,000-Hour Bare-Metal Telemetry HUD in Free Space */}
                <div className="w-full mt-1">
                  <BareMetalTelemetryHUD
                    channel="CH-01 // AST_INDEXER"
                    badge="CONTEXT AWARENESS"
                    title="Kernel Symbol Indexing & Topology"
                    desc="Memory-mapped AST topology parses workspace buffers in 0.08ms. Zero-latency context retrieval for agents."
                    metrics={[
                      { label: "Parse Latency", value: "0.08ms", sub: "SUB-FRAME JIT" },
                      { label: "AST Topology", value: "64,280", sub: "NODES INDEXED" },
                      { label: "Memory Bus", value: "0-Copy", sub: "MMAP RESIDENT" },
                      { label: "Throughput", value: "1.4 GB/s", sub: "HOST DARWIN" },
                    ]}
                    hexDump={["0x7F", "0xA2", "0x3C", "0x08", "0x91", "0xF0", "0x4B", "0x12"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 3: INTELLIGENT PROCESSING (AST Synthesis & Delta Merge)        */}
            {/* =================================================================== */}
            {mode === "processing" && (
              <div className="space-y-0.5 relative">
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                  <span>
                    <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">ASTMutation</span>, <span className="text-[#4ec9b0]">SynthesizedTree</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/crdt&quot;</span>;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                  <span>
                    <span className="text-[#569cd6]">export function</span> <span className="text-[#dcdcaa]">synthesizeASTDelta</span>(<span className="text-[#9cdcfe]">delta</span>: <span className="text-[#4ec9b0]">ASTMutation</span>) &#123;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">tree</span> = <span className="text-[#4ec9b0]">SynthesizedTree</span>.<span className="text-[#dcdcaa]">resolve</span>(<span className="text-[#9cdcfe]">delta</span>.<span className="text-[#9cdcfe]">targetId</span>);
                  </span>
                </div>

                {/* Line 4: Active Probe Token with Circuit Trace */}
                <div className="flex items-center justify-between bg-[#ffffff]/5 py-0.5 relative">
                  <div className="flex items-baseline min-w-0">
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">4</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">return</span> <span className="text-[#9cdcfe]">tree</span>.<span className="text-[#dcdcaa]">transformDeterministic</span>(<span className="text-[#9cdcfe]">delta</span>.<span className="text-[#9cdcfe]">patch</span>, <span className="text-[#b5cea8]">0x{resolvedToken.toString(16)}</span>);
                    </span>
                    <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                      <span>TOKEN CONVERGED</span>
                    </span>
                  </div>

                  {/* Horizontal Circuit Trace heading out into free space */}
                  <div className="flex-1 flex items-center min-w-[20px] ml-2 mr-3 sm:mr-6">
                    <div className="w-full h-0 border-b border-dashed border-[#0055FF]/80" />
                    <div className="w-2.5 h-2.5 border-r border-t border-dashed border-[#0055FF] -ml-2.5 shrink-0" />
                  </div>
                </div>

                {/* Lines 5-8 with vertical circuit trace in right margin */}
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                    <span>&#125;</span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                    <span></span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                    <span className="text-[#6a9955] italic">// Structural AST convergence without text collision storms</span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                    <span>
                      <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">convergedNode</span> = <span className="text-[#dcdcaa]">synthesizeASTDelta</span>(&#123; <span className="text-[#9cdcfe]">targetId</span>: <span className="text-[#b5cea8]">{resolvedToken}</span> &#125;);
                    </span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>

                {/* Precision Circuit Bridge: Plunges directly into HUD's top socket */}
                <div className="flex flex-col items-center pt-2 pb-1 relative">
                  <div className="h-5 w-0 border-r border-dashed border-[#0055FF]" />
                  <div className="w-0 h-0 border-x-[5px] border-x-transparent border-t-[7px] border-t-[#0055FF] -mt-0.5" />
                </div>

                {/* 10,000-Hour Bare-Metal Telemetry HUD in Free Space */}
                <div className="w-full mt-1">
                  <BareMetalTelemetryHUD
                    channel="CH-02 // AST_SYNTHESIS"
                    badge="INTELLIGENT PROCESSING"
                    title="Deterministic AST Synthesis & Token Merge"
                    desc="Structural token reconciliation maintains syntax tree validity through multi-pass JIT compiler verification."
                    metrics={[
                      { label: "Reconciliation", value: "0.14ms", sub: "ATOMIC JIT" },
                      { label: "Token Target", value: `0x${resolvedToken.toString(16)}`, sub: "RECONCILED" },
                      { label: "Syntax Validity", value: "100%", sub: "PARSER VALID" },
                      { label: "Collision Rate", value: "0.00%", sub: "DETERMINISTIC" },
                    ]}
                    hexDump={["0x0E", "0x77", "0xAA", "0x51", "0x04", "0x8C", "0x2D", "0x99"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 4: DECENTRALIZED AST-CRDT (Rust Structural Vector Merge)       */}
            {/* =================================================================== */}
            {mode === "crdt" && (
              <div className="space-y-0.5 relative">
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                  <span className="text-[#6a9955] italic">// Decentralized AST-CRDT Vector Synchronization</span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                  <span>
                    <span className="text-[#569cd6]">use</span> crux_crdt::&#123;<span className="text-[#4ec9b0]">ASTVectorTree</span>, <span className="text-[#4ec9b0]">NodeId</span>, <span className="text-[#4ec9b0]">ASTPatch</span>&#125;;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                  <span></span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">4</span>
                  <span>
                    <span className="text-[#569cd6]">impl</span> <span className="text-[#4ec9b0]">ASTVectorTree</span> &#123;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">pub fn</span> <span className="text-[#dcdcaa]">merge_deterministic</span>(&amp;<span className="text-[#569cd6]">mut self</span>, <span className="text-[#9cdcfe]">patch</span>: &amp;<span className="text-[#4ec9b0]">ASTPatch</span>) -&gt; <span className="text-[#4ec9b0]">Result</span>&lt;<span className="text-[#569cd6]">u64</span>&gt; &#123;
                  </span>
                </div>

                {/* Line 6: Active Probe Token with Circuit Trace */}
                <div className="flex items-center justify-between bg-[#ffffff]/5 py-0.5 relative">
                  <div className="flex items-baseline min-w-0">
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">6</span>
                    <span className="pl-8">
                      <span className="text-[#569cd6]">let</span> <span className="text-[#9cdcfe]">epoch</span> = <span className="text-[#569cd6]">self</span>.<span className="text-[#9cdcfe]">vector_clock</span>.<span className="text-[#dcdcaa]">fetch_add</span>(<span className="text-[#b5cea8]">1</span>, <span className="text-[#4ec9b0]">Ordering</span>::<span className="text-[#4ec9b0]">SeqCst</span>);
                    </span>
                    <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                      <span>EPOCH: #{crdtEpoch}</span>
                    </span>
                  </div>

                  {/* Horizontal Circuit Trace heading out into free space */}
                  <div className="flex-1 flex items-center min-w-[20px] ml-2 mr-3 sm:mr-6">
                    <div className="w-full h-0 border-b border-dashed border-[#0055FF]/80" />
                    <div className="w-2.5 h-2.5 border-r border-t border-dashed border-[#0055FF] -ml-2.5 shrink-0" />
                  </div>
                </div>

                {/* Lines 7-10 with vertical circuit trace in right margin */}
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                    <span className="pl-8">
                      <span className="text-[#569cd6]">self</span>.<span className="text-[#dcdcaa]">apply_atomic_token</span>(<span className="text-[#9cdcfe]">patch</span>.<span className="text-[#dcdcaa]">token</span>(), <span className="text-[#9cdcfe]">epoch</span>);
                    </span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                    <span className="pl-8">
                      <span className="text-[#4ec9b0]">Ok</span>(<span className="text-[#9cdcfe]">epoch</span>)
                    </span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">9</span>
                    <span className="pl-4">&#125;</span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">10</span>
                    <span>&#125;</span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>

                {/* Precision Circuit Bridge: Plunges directly into HUD's top socket */}
                <div className="flex flex-col items-center pt-2 pb-1 relative">
                  <div className="h-5 w-0 border-r border-dashed border-[#0055FF]" />
                  <div className="w-0 h-0 border-x-[5px] border-x-transparent border-t-[7px] border-t-[#0055FF] -mt-0.5" />
                </div>

                {/* 10,000-Hour Bare-Metal Telemetry HUD in Free Space */}
                <div className="w-full mt-1">
                  <BareMetalTelemetryHUD
                    channel="CH-03 // VECTOR_CLOCK"
                    badge="DECENTRALIZED CRDT"
                    title="Atomic Vector Clock Convergence"
                    desc="Lamport vector clocks resolve structural AST patches deterministically. Zero collision storms across concurrent edits."
                    metrics={[
                      { label: "Lamport Epoch", value: `#${crdtEpoch}`, sub: "FETCH_ADD" },
                      { label: "Vector Clocks", value: "SeqCst", sub: "ATOMIC ORDERING" },
                      { label: "Collision Storms", value: "0.00%", sub: "DETERMINISTIC" },
                      { label: "Sync Overhead", value: "<0.01ms", sub: "LOCK-FREE RING" },
                    ]}
                    hexDump={["0x2A", "0x4F", "0xC1", "0x90", "0x00", "0x1B", "0x7E", "0x88"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 5: NATIVE SILICON RUNTIME (Metal WebGPU Direct Phosphor 120 FPS)*/}
            {/* =================================================================== */}
            {mode === "silicon" && (
              <div className="space-y-0.5 relative">
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                  <span className="text-[#6a9955] italic">// Direct Metal &amp; WebGPU Compute Shader · 4.2ms Input Latency</span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                  <span>
                    <span className="text-[#569cd6]">#include</span> <span className="text-[#ce9178]">&lt;metal_stdlib&gt;</span>
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                  <span>
                    <span className="text-[#569cd6]">using namespace</span> metal;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">4</span>
                  <span></span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                  <span>
                    <span className="text-[#569cd6]">kernel void</span> <span className="text-[#dcdcaa]">rasterize_glyph_quads</span>(
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                  <span className="pl-4">
                    device <span className="text-[#569cd6]">const</span> <span className="text-[#4ec9b0]">GlyphVertex</span>* <span className="text-[#9cdcfe]">vertices</span> [[buffer(0)]],
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                  <span className="pl-4">
                    <span className="text-[#4ec9b0]">texture2d</span>&lt;<span className="text-[#569cd6]">float</span>, access::sample&gt; <span className="text-[#9cdcfe]">atlas</span> [[texture(0)]],
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">uint2</span> <span className="text-[#9cdcfe]">gid</span> [[thread_position_in_grid]]
                  </span>
                </div>

                {/* Line 9: Active Probe Token with Circuit Trace */}
                <div className="flex items-center justify-between bg-[#ffffff]/5 py-0.5 relative">
                  <div className="flex items-baseline min-w-0">
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">9</span>
                    <span>) &#123;</span>
                    <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                      <span>120 FPS // METAL 3</span>
                    </span>
                  </div>

                  {/* Horizontal Circuit Trace heading out into free space */}
                  <div className="flex-1 flex items-center min-w-[20px] ml-2 mr-3 sm:mr-6">
                    <div className="w-full h-0 border-b border-dashed border-[#0055FF]/80" />
                    <div className="w-2.5 h-2.5 border-r border-t border-dashed border-[#0055FF] -ml-2.5 shrink-0" />
                  </div>
                </div>

                {/* Lines 10-11 with vertical circuit trace in right margin */}
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">10</span>
                    <span className="pl-4">
                      <span className="text-[#9cdcfe]">surface</span>.<span className="text-[#dcdcaa]">write</span>(<span className="text-[#dcdcaa]">sample_glyph</span>(<span className="text-[#9cdcfe]">atlas</span>, <span className="text-[#9cdcfe]">vertices</span>[<span className="text-[#9cdcfe]">gid</span>.<span className="text-[#9cdcfe]">x</span>]), <span className="text-[#9cdcfe]">gid</span>);
                    </span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">11</span>
                    <span>&#125;</span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>

                {/* Precision Circuit Bridge: Plunges directly into HUD's top socket */}
                <div className="flex flex-col items-center pt-2 pb-1 relative">
                  <div className="h-5 w-0 border-r border-dashed border-[#0055FF]" />
                  <div className="w-0 h-0 border-x-[5px] border-x-transparent border-t-[7px] border-t-[#0055FF] -mt-0.5" />
                </div>

                {/* 10,000-Hour Bare-Metal Telemetry HUD in Free Space */}
                <div className="w-full mt-1">
                  <BareMetalTelemetryHUD
                    channel="CH-04 // METAL3_GPU"
                    badge="NATIVE SILICON RUNTIME"
                    title="Direct Metal 3 & WebGPU Compute Pipeline"
                    desc="Bypasses DOM layout reflows and V8 GC pauses. Rasterizes glyph quads directly via GPU compute at locked 120 FPS."
                    metrics={[
                      { label: "Input Latency", value: "4.2ms", sub: "DIRECT HW" },
                      { label: "Framerate", value: "120 FPS", sub: "LOCKED V-SYNC" },
                      { label: "GPU Pipeline", value: "Metal 3", sub: "COMPUTE SHADER" },
                      { label: "DOM Reflows", value: "0 ms", sub: "ZERO BROWSER GC" },
                    ]}
                    hexDump={["0x99", "0x3D", "0x14", "0xEF", "0x7A", "0x55", "0x82", "0x01"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 6: ACTIONABLE OUTPUT (Mach-O ARM64 Compiler Output Artifact)   */}
            {/* =================================================================== */}
            {mode === "output" && (
              <div className="space-y-0.5 relative">
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                  <span className="text-[#6a9955] italic">// Native LLVM Mach-O Binary Compilation Pipeline</span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                  <span>
                    <span className="text-[#569cd6]">use</span> crux_build::&#123;<span className="text-[#4ec9b0]">LLVMBackend</span>, <span className="text-[#4ec9b0]">TargetTriple</span>, <span className="text-[#4ec9b0]">MachOBinary</span>&#125;;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                  <span></span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">4</span>
                  <span>
                    <span className="text-[#569cd6]">pub fn</span> <span className="text-[#dcdcaa]">emit_native_binary</span>(<span className="text-[#9cdcfe]">target</span>: <span className="text-[#4ec9b0]">TargetTriple</span>) -&gt; <span className="text-[#4ec9b0]">Result</span>&lt;<span className="text-[#4ec9b0]">MachOBinary</span>&gt; &#123;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">let</span> <span className="text-[#9cdcfe]">codegen</span> = <span className="text-[#4ec9b0]">LLVMBackend</span>::<span className="text-[#dcdcaa]">new</span>(<span className="text-[#9cdcfe]">target</span>)?;
                  </span>
                </div>

                {/* Line 6: Active Probe Token with Circuit Trace */}
                <div className="flex items-center justify-between bg-[#ffffff]/5 py-0.5 relative">
                  <div className="flex items-baseline min-w-0">
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">6</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">let</span> <span className="text-[#9cdcfe]">artifact</span> = <span className="text-[#9cdcfe]">codegen</span>.<span className="text-[#dcdcaa]">emit_arm64_slice</span>(<span className="text-[#ce9178]">&quot;aarch64-apple-darwin&quot;</span>)?;
                    </span>
                    <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                      <span>ARM64 READY // 140ms</span>
                    </span>
                  </div>

                  {/* Horizontal Circuit Trace heading out into free space */}
                  <div className="flex-1 flex items-center min-w-[20px] ml-2 mr-3 sm:mr-6">
                    <div className="w-full h-0 border-b border-dashed border-[#0055FF]/80" />
                    <div className="w-2.5 h-2.5 border-r border-t border-dashed border-[#0055FF] -ml-2.5 shrink-0" />
                  </div>
                </div>

                {/* Lines 7-8 with vertical circuit trace in right margin */}
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                    <span className="pl-4">
                      <span className="text-[#4ec9b0]">Ok</span>(<span className="text-[#9cdcfe]">artifact</span>)
                    </span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                    <span>&#125;</span>
                  </div>
                  <div className="mr-3 sm:mr-6 h-5 border-r border-dashed border-[#0055FF]/80" />
                </div>

                {/* Precision Circuit Bridge: Plunges directly into HUD's top socket */}
                <div className="flex flex-col items-center pt-2 pb-1 relative">
                  <div className="h-5 w-0 border-r border-dashed border-[#0055FF]" />
                  <div className="w-0 h-0 border-x-[5px] border-x-transparent border-t-[7px] border-t-[#0055FF] -mt-0.5" />
                </div>

                {/* 10,000-Hour Bare-Metal Telemetry HUD in Free Space */}
                <div className="w-full mt-1">
                  <BareMetalTelemetryHUD
                    channel="CH-05 // LLVM_CODEGEN"
                    badge="ACTIONABLE OUTPUT"
                    title="Native LLVM Mach-O ARM64 Binary Emitter"
                    desc="Emits direct ARM64 host binaries in 140ms. Instant execution artifacts with zero cloud build overhead."
                    metrics={[
                      { label: "Build Latency", value: "140ms", sub: "LLVM 18 DIRECT" },
                      { label: "Target Architecture", value: "ARM64", sub: "APPLE SILICON" },
                      { label: "Format Slice", value: "Mach-O", sub: "0xFEEDFACF" },
                      { label: "Cloud Overhead", value: "0 ms", sub: "LOCAL EXCLUSIVE" },
                    ]}
                    hexDump={["0xCF", "0xFA", "0xED", "0xFE", "0x0C", "0x00", "0x00", "0x01"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 7: AUTONOMOUS @CRUXAI AGENTS (Suggestion Review Diff)          */}
            {/* =================================================================== */}
            {mode === "agents" && (
              <div className="space-y-1 relative">
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                  <span>
                    <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">LocalDaemonClient</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/daemon&quot;</span>;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                  <span>
                    <span className="text-[#569cd6]">export class</span> <span className="text-[#4ec9b0]">StreamSyncer</span> &#123;
                  </span>
                </div>

                {/* Inline Diff Box */}
                <div className="my-2 border border-[#222222] bg-[#0a0a0a]">
                  <div className="flex justify-between items-center px-3 py-1 border-b border-[#222222] bg-[#111111]">
                    <span className="text-[10px] font-mono text-white flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 bg-[#00FF66]" />
                      <span>@CruxAI suggests an atomic refactor</span>
                      {diffState === "accepted" && (
                        <span className="ml-2 px-1.5 py-0.2 text-[9px] bg-black border border-[#222222] text-[#00FF66] font-mono">
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
                        <span className="text-[9px] font-mono text-[#00FF66] font-bold">
                          APPLIED
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="p-2 text-[11px] leading-relaxed font-mono">
                    <div className="bg-[#FF453A]/10 text-[#FF453A] px-2 py-0.5 border-l-2 border-[#FF453A] line-through">
                      - const lock = await this.daemon.acquireLock(channel);
                    </div>
                    <div className="bg-[#00FF66]/10 text-[#00FF66] px-2 py-0.5 border-l-2 border-[#00FF66] font-semibold">
                      + const ticket = await atomicBitset.claimTicket();
                    </div>
                    <div className="bg-[#00FF66]/10 text-[#00FF66] px-2 py-0.5 border-l-2 border-[#00FF66] font-semibold">
                      + await wal.commitLockFree(ticket);
                    </div>
                  </div>
                </div>

                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">return</span> ticket;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">4</span>
                  <span>&#125;</span>
                </div>

                {/* Precision Circuit Bridge: Plunges directly into HUD's top socket */}
                <div className="flex flex-col items-center pt-2 pb-1 relative">
                  <div className="h-5 w-0 border-r border-dashed border-[#00FF66]" />
                  <div className="w-0 h-0 border-x-[5px] border-x-transparent border-t-[7px] border-t-[#00FF66] -mt-0.5" />
                </div>

                {/* 10,000-Hour Bare-Metal Telemetry HUD in Free Space */}
                <div className="w-full mt-1">
                  <BareMetalTelemetryHUD
                    channel="CH-06 // AGENT_DIFF"
                    badge="AUTONOMOUS AI ENGINE"
                    title="@CruxAI Embedded Local Refactor Engine"
                    desc="Embedded agent proposes lock-free atomic bitset patch. Deterministically evaluated via local PTY bridge."
                    metrics={[
                      { label: "Agent Evaluation", value: "12ms", sub: "LOCAL PTY" },
                      { label: "Verification", value: "100%", sub: "PASSED TESTS" },
                      { label: "Architecture", value: "Atomic", sub: "BITSET RING" },
                      { label: "Deadlock Risk", value: "0.00%", sub: "LOCK-FREE WAL" },
                    ]}
                    hexDump={["0x00", "0xFF", "0x66", "0x2A", "0x51", "0x90", "0x1E", "0x44"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#00FF66"
                  />
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
