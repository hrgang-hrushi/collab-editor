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
import { BotAvatar } from "bot-avatars";
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

interface AppleTelemetryHUDProps {
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
 * Senior UI/UX Apple-Grade Telemetry Inspector HUD
 * - Xcode / Instruments inspired side-docked inspector
 * - Zero vertical scrolling: fits precisely in view side-by-side with code
 * - Refined Apple radii (8px outer container, 4px inner cells)
 * - Real-time signal oscilloscope and live DMA hex memory stream
 * - Direct horizontal circuit bus receptor notch aligned with active code token
 */
function AppleTelemetryHUD({
  channel,
  badge,
  title,
  desc,
  metrics,
  hexDump,
  accentColor = "#0055FF",
  activeHexIndex = 0,
  className = "",
}: AppleTelemetryHUDProps) {
  return (
    <div
      className={`relative bg-[#070913]/95 backdrop-blur-md border text-left p-3 select-none shadow-[0_8px_32px_rgba(0,0,0,0.65)] ${className}`}
      style={{
        borderColor: `${accentColor}50`,
        borderRadius: "8px",
      }}
    >
      {/* Physical Left Socket Notch: Aligned directly with horizontal circuit trace */}
      <div
        className="absolute -left-[6px] top-6 w-3 h-3 flex items-center justify-center rounded-[2px] shadow-sm z-10"
        style={{
          backgroundColor: accentColor,
        }}
      >
        <span className="w-1.5 h-1.5 bg-black rounded-[1px]" />
      </div>

      {/* Top Header Row: Badge + Live Waveform */}
      <div className="flex items-center justify-between pb-1.5 border-b border-white/10">
        <div
          className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-wider font-bold"
          style={{ color: accentColor }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full animate-ping"
            style={{ backgroundColor: accentColor }}
          />
          <span>{badge}</span>
        </div>

        {/* Live SVG Signal Waveform */}
        <div className="flex items-center gap-1.5">
          <svg className="w-12 h-3" viewBox="0 0 50 12" fill="none">
            <path
              d="M 0 6 Q 6 6, 9 2 T 15 10 T 21 6 T 29 6 Q 34 6, 37 1 T 42 11 T 47 6 H 50"
              stroke={accentColor}
              strokeWidth="1.2"
              strokeLinecap="round"
              className="opacity-80"
            />
          </svg>
          <span className="text-[7.5px] font-mono text-[#16a34a] font-bold">
            ● 120Hz
          </span>
        </div>
      </div>

      {/* 4-Cell Telemetry Metrics Matrix */}
      <div className="grid grid-cols-2 gap-1.5 my-2">
        {metrics.map((m, idx) => (
          <div
            key={idx}
            className="p-1.5 bg-[#0f1322]/85 border border-white/5 flex flex-col justify-between"
            style={{ borderRadius: "4px" }}
          >
            <span className="text-[7px] font-mono text-[#86868b] uppercase tracking-wider">
              {m.label}
            </span>
            <span className="text-[10.5px] font-mono font-bold text-white tracking-tight mt-0.5 tabular-nums">
              {m.value}
            </span>
            <span className="text-[6.5px] font-mono text-[#16a34a] mt-0.5">
              {m.sub}
            </span>
          </div>
        ))}
      </div>

      {/* Architectural Description */}
      <div className="mt-1">
        <h4 className="text-[11px] font-medium text-white font-sans tracking-tight">
          {title}
        </h4>
        <p className="mt-0.5 text-[9.5px] font-sans text-[#86868b] leading-relaxed">
          {desc}
        </p>
      </div>

      {/* Live Hex Stream */}
      <div className="mt-2 pt-1.5 border-t border-white/10 flex items-center justify-between font-mono text-[7.5px] text-[#86868b]">
        <div className="flex items-center gap-1">
          <span className="text-[#666666] hidden sm:inline">DMA:</span>
          <div className="flex items-center gap-0.5">
            {hexDump.slice(0, 6).map((byte, i) => (
              <span
                key={i}
                className={`px-1 py-0.2 transition-colors ${
                  i === activeHexIndex
                    ? "bg-white text-black font-bold shadow-sm"
                    : "bg-[#141828] text-[#86868b]"
                }`}
                style={{ borderRadius: "2px" }}
              >
                {byte}
              </span>
            ))}
          </div>
        </div>
        <span className="text-[#16a34a] font-bold">0-COPY</span>
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

  // Cycling active byte for live telemetry
  const [activeHexIndex, setActiveHexIndex] = useState(0);
  useEffect(() => {
    const interval = setInterval(() => {
      setActiveHexIndex((prev) => (prev + 1) % 6);
    }, 450);
    return () => clearInterval(interval);
  }, []);

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
      className={`relative w-full h-full bg-[#000000] text-white flex flex-col select-none overflow-hidden ${className}`}
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
      <div className="flex-1 flex min-h-0 bg-[#000000] overflow-hidden">
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

          {/* Code Canvas Area: overflow-hidden ensures ZERO vertical scrolling */}
          <div className="flex-1 p-3 sm:p-4 overflow-hidden font-mono text-[11.5px] sm:text-[12px] leading-[1.65] bg-[#000000] relative flex flex-col justify-center">
            {/* =================================================================== */}
            {/* DEMO 1: REAL-TIME COLLABORATIVE MESH                                */}
            {/* 3 Peers typing with their names: Erik, Hrushi, Muhaymin             */}
            {/* No avatars while typing, just names; Rounded edges (4px)            */}
            {/* =================================================================== */}
            {mode === "multiplayer" && (
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

                {/* Line 3: Erik (Pink - no avatar while typing, just name) */}
                <div className="flex items-baseline bg-white/5 py-1 rounded-[4px]">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">3</span>
                  <span className="pl-4">
                    <span className="text-[#9cdcfe]">timeout</span> ={" "}
                    <span className="relative inline-flex items-center bg-[#ff70a6]/15 border border-[#ff70a6] rounded-[4px] px-2 py-0.5 text-white mx-1">
                      <span>{pinkText || "timeout = 2500; // fast"}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#ff70a6] ml-1 rounded-[1px] align-middle animate-pulse" />
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

                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">4</span>
                  <span className="pl-4">
                    <span className="text-[#9cdcfe]">daemon</span> = <span className="text-[#569cd6]">new</span> <span className="text-[#4ec9b0]">LocalDaemonClient</span>(&#123; <span className="text-[#9cdcfe]">port</span>: <span className="text-[#b5cea8]">7447</span> &#125;);
                  </span>
                </div>

                {/* Line 5: Hrushi (Blue - no avatar while typing, just name) */}
                <div className="flex items-baseline bg-white/5 py-1 rounded-[4px]">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">5</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">async</span> <span className="text-[#dcdcaa]">acquireLock</span>(
                    <span className="relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] rounded-[4px] px-2 py-0.5 text-white mx-1">
                      <span>{blueText || '"stream-mesh";'}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#0055FF] ml-1 rounded-[1px] align-middle animate-pulse" />
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
                    ) &#123;
                  </span>
                </div>

                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                  <span className="pl-8">
                    <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">ticket</span> = <span className="text-[#569cd6]">await</span> <span className="text-[#569cd6]">this</span>.<span className="text-[#9cdcfe]">daemon</span>.<span className="text-[#dcdcaa]">acquireLock</span>(channel);
                  </span>
                </div>

                {/* Line 7: Muhaymin (Green - no avatar while typing, just name) */}
                <div className="flex items-baseline bg-white/5 py-1 rounded-[4px]">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">7</span>
                  <span className="pl-8">
                    <span className="text-[#569cd6]">return</span>{" "}
                    <span className="relative inline-flex items-center bg-[#16a34a]/15 border border-[#16a34a] rounded-[4px] px-2 py-0.5 text-white mx-1">
                      <span>{greenText || 'ticket.id + ":OK"; // 0ms'}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#16a34a] ml-1 rounded-[1px] align-middle animate-pulse" />
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

                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                  <span className="pl-4">&#125;</span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">9</span>
                  <span>&#125;</span>
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 2: CONTEXT AWARENESS (Side-by-Side Zero-Scroll Xcode Dock)     */}
            {/* =================================================================== */}
            {mode === "context" && (
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 relative">
                {/* Left: Code Lines (5 clean lines) */}
                <div className="space-y-1 flex-1 min-w-0">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                    <span>
                      <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">TokenStream</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/kernel&quot;</span>;
                    </span>
                  </div>
                  <div className={`flex items-baseline rounded-[4px] ${scanLine === 2 ? "bg-white/10" : ""}`}>
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                    <span>
                      <span className="text-[#569cd6]">export function</span> <span className="text-[#dcdcaa]">indexWorkspace</span>(<span className="text-[#9cdcfe]">paths</span>: <span className="text-[#4ec9b0]">string</span>[]) &#123;
                    </span>
                  </div>
                  <div className={`flex items-baseline rounded-[4px] ${scanLine === 3 ? "bg-white/10" : ""}`}>
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">ast</span> = <span className="text-[#569cd6]">new</span> <span className="text-[#4ec9b0]">TokenStream</span>().<span className="text-[#dcdcaa]">parseAll</span>(<span className="text-[#9cdcfe]">paths</span>);
                    </span>
                  </div>

                  {/* Line 4: Active Probe Token with horizontal connector */}
                  <div className="flex items-center justify-between bg-white/5 py-1 rounded-[4px] relative">
                    <div className="flex items-baseline min-w-0">
                      <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">4</span>
                      <span className="pl-4">
                        <span className="text-[#569cd6]">return</span> <span className="text-[#9cdcfe]">ast</span>.<span className="text-[#dcdcaa]">buildSymbolIndex</span>();
                      </span>
                      <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] rounded-[4px] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                        <span>64,280 NODES</span>
                      </span>
                    </div>

                    {/* Direct Horizontal Circuit Bridge into Inspector HUD */}
                    <div className="hidden lg:flex flex-1 items-center min-w-[16px] max-w-[48px] mx-2">
                      <div className="w-full h-0 border-b border-dashed border-[#0055FF]" />
                      <div className="w-0 h-0 border-y-[4px] border-y-transparent border-l-[6px] border-l-[#0055FF] -ml-0.5" />
                    </div>
                  </div>

                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                    <span>&#125;</span>
                  </div>
                </div>

                {/* Right: Apple Telemetry Inspector HUD (Zero-Scroll Side Dock) */}
                <div className="w-full lg:w-[240px] shrink-0">
                  <AppleTelemetryHUD
                    channel="CH-01 // AST_INDEX"
                    badge="CONTEXT AWARENESS"
                    title="Kernel Symbol Indexing"
                    desc="Memory-mapped AST topology parses buffers in 0.08ms with zero GC."
                    metrics={[
                      { label: "Parse Latency", value: "0.08ms", sub: "SUB-FRAME JIT" },
                      { label: "AST Topology", value: "64,280", sub: "NODES INDEXED" },
                      { label: "Memory Bus", value: "0-Copy", sub: "MMAP RESIDENT" },
                      { label: "Throughput", value: "1.4 GB/s", sub: "HOST DARWIN" },
                    ]}
                    hexDump={["0x7F", "0xA2", "0x3C", "0x08", "0x91", "0xF0"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 3: INTELLIGENT PROCESSING (Side-by-Side Zero-Scroll Xcode Dock)*/}
            {/* =================================================================== */}
            {mode === "processing" && (
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 relative">
                <div className="space-y-1 flex-1 min-w-0">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                    <span>
                      <span className="text-[#569cd6]">import</span> &#123; <span className="text-[#4ec9b0]">SynthesizedTree</span> &#125; <span className="text-[#569cd6]">from</span> <span className="text-[#ce9178]">&quot;@crux/crdt&quot;</span>;
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

                  {/* Line 4: Active Probe Token with horizontal connector */}
                  <div className="flex items-center justify-between bg-white/5 py-1 rounded-[4px] relative">
                    <div className="flex items-baseline min-w-0">
                      <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">4</span>
                      <span className="pl-4">
                        <span className="text-[#569cd6]">return</span> <span className="text-[#9cdcfe]">tree</span>.<span className="text-[#dcdcaa]">transformDeterministic</span>(<span className="text-[#9cdcfe]">delta</span>.<span className="text-[#9cdcfe]">patch</span>, <span className="text-[#b5cea8]">0x{resolvedToken.toString(16)}</span>);
                      </span>
                      <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] rounded-[4px] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                        <span>TOKEN CONVERGED</span>
                      </span>
                    </div>

                    <div className="hidden lg:flex flex-1 items-center min-w-[16px] max-w-[48px] mx-2">
                      <div className="w-full h-0 border-b border-dashed border-[#0055FF]" />
                      <div className="w-0 h-0 border-y-[4px] border-y-transparent border-l-[6px] border-l-[#0055FF] -ml-0.5" />
                    </div>
                  </div>

                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                    <span>&#125;</span>
                  </div>
                </div>

                <div className="w-full lg:w-[240px] shrink-0">
                  <AppleTelemetryHUD
                    channel="CH-02 // SYNTHESIS"
                    badge="INTELLIGENT PROCESSING"
                    title="Deterministic AST Synthesis"
                    desc="Structural token reconciliation guarantees tree validity across all concurrent diffs."
                    metrics={[
                      { label: "Reconciliation", value: "0.14ms", sub: "ATOMIC JIT" },
                      { label: "Token Target", value: `0x${resolvedToken.toString(16)}`, sub: "RECONCILED" },
                      { label: "Syntax Validity", value: "100%", sub: "PARSER VALID" },
                      { label: "Collision Rate", value: "0.00%", sub: "DETERMINISTIC" },
                    ]}
                    hexDump={["0x0E", "0x77", "0xAA", "0x51", "0x04", "0x8C"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 4: DECENTRALIZED AST-CRDT (Side-by-Side Zero-Scroll Xcode Dock)*/}
            {/* =================================================================== */}
            {mode === "crdt" && (
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 relative">
                <div className="space-y-1 flex-1 min-w-0">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                    <span>
                      <span className="text-[#569cd6]">use</span> crux_crdt::&#123;<span className="text-[#4ec9b0]">ASTVectorTree</span>, <span className="text-[#4ec9b0]">ASTPatch</span>&#125;;
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                    <span>
                      <span className="text-[#569cd6]">impl</span> <span className="text-[#4ec9b0]">ASTVectorTree</span> &#123;
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">pub fn</span> <span className="text-[#dcdcaa]">merge_deterministic</span>(&amp;<span className="text-[#569cd6]">mut self</span>, <span className="text-[#9cdcfe]">patch</span>: &amp;<span className="text-[#4ec9b0]">ASTPatch</span>) -&gt; <span className="text-[#4ec9b0]">Result</span>&lt;<span className="text-[#569cd6]">{`u64`}</span>&gt; &#123;
                    </span>
                  </div>

                  {/* Line 4: Active Probe Token with horizontal connector */}
                  <div className="flex items-center justify-between bg-white/5 py-1 rounded-[4px] relative">
                    <div className="flex items-baseline min-w-0">
                      <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">4</span>
                      <span className="pl-8">
                        <span className="text-[#569cd6]">let</span> <span className="text-[#9cdcfe]">epoch</span> = <span className="text-[#569cd6]">self</span>.<span className="text-[#9cdcfe]">vector_clock</span>.<span className="text-[#dcdcaa]">fetch_add</span>(<span className="text-[#b5cea8]">1</span>, <span className="text-[#4ec9b0]">Ordering</span>::<span className="text-[#4ec9b0]">SeqCst</span>);
                      </span>
                      <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] rounded-[4px] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                        <span>EPOCH: #{crdtEpoch}</span>
                      </span>
                    </div>

                    <div className="hidden lg:flex flex-1 items-center min-w-[16px] max-w-[48px] mx-2">
                      <div className="w-full h-0 border-b border-dashed border-[#0055FF]" />
                      <div className="w-0 h-0 border-y-[4px] border-y-transparent border-l-[6px] border-l-[#0055FF] -ml-0.5" />
                    </div>
                  </div>

                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                    <span className="pl-8">
                      <span className="text-[#569cd6]">self</span>.<span className="text-[#dcdcaa]">apply_atomic_token</span>(<span className="text-[#9cdcfe]">patch</span>.<span className="text-[#dcdcaa]">token</span>(), <span className="text-[#9cdcfe]">epoch</span>);
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                    <span className="pl-4">&#125;</span>
                  </div>
                </div>

                <div className="w-full lg:w-[240px] shrink-0">
                  <AppleTelemetryHUD
                    channel="CH-03 // VECTOR"
                    badge="DECENTRALIZED CRDT"
                    title="Atomic Vector Clocks"
                    desc="Lamport vector clocks resolve structural AST patches deterministically with zero collisions."
                    metrics={[
                      { label: "Lamport Epoch", value: `#${crdtEpoch}`, sub: "FETCH_ADD" },
                      { label: "Vector Clocks", value: "SeqCst", sub: "ATOMIC ORDER" },
                      { label: "Collision Rate", value: "0.00%", sub: "DETERMINISTIC" },
                      { label: "Sync Overhead", value: "<0.01ms", sub: "LOCK-FREE RING" },
                    ]}
                    hexDump={["0x2A", "0x4F", "0xC1", "0x90", "0x00", "0x1B"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 5: NATIVE SILICON RUNTIME (Side-by-Side Zero-Scroll Xcode Dock)*/}
            {/* =================================================================== */}
            {mode === "silicon" && (
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 relative">
                <div className="space-y-1 flex-1 min-w-0">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                    <span>
                      <span className="text-[#569cd6]">#include</span> <span className="text-[#ce9178]">&lt;metal_stdlib&gt;</span>
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                    <span>
                      <span className="text-[#569cd6]">kernel void</span> <span className="text-[#dcdcaa]">rasterize_glyph_quads</span>(
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                    <span className="pl-4">
                      device <span className="text-[#569cd6]">const</span> <span className="text-[#4ec9b0]">GlyphVertex</span>* <span className="text-[#9cdcfe]">vertices</span> [[buffer(0)]],
                    </span>
                  </div>

                  {/* Line 4: Active Probe Token with horizontal connector */}
                  <div className="flex items-center justify-between bg-white/5 py-1 rounded-[4px] relative">
                    <div className="flex items-baseline min-w-0">
                      <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">4</span>
                      <span className="pl-4">
                        <span className="text-[#4ec9b0]">texture2d</span>&lt;<span className="text-[#569cd6]">float</span>&gt; <span className="text-[#9cdcfe]">atlas</span> [[texture(0)]]
                      </span>
                      <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] rounded-[4px] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                        <span>120 FPS // METAL 3</span>
                      </span>
                    </div>

                    <div className="hidden lg:flex flex-1 items-center min-w-[16px] max-w-[48px] mx-2">
                      <div className="w-full h-0 border-b border-dashed border-[#0055FF]" />
                      <div className="w-0 h-0 border-y-[4px] border-y-transparent border-l-[6px] border-l-[#0055FF] -ml-0.5" />
                    </div>
                  </div>

                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                    <span className="pl-4">
                      <span className="text-[#9cdcfe]">surface</span>.<span className="text-[#dcdcaa]">write</span>(<span className="text-[#dcdcaa]">sample_glyph</span>(<span className="text-[#9cdcfe]">atlas</span>), <span className="text-[#9cdcfe]">gid</span>);
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                    <span>&#125;</span>
                  </div>
                </div>

                <div className="w-full lg:w-[240px] shrink-0">
                  <AppleTelemetryHUD
                    channel="CH-04 // METAL3"
                    badge="NATIVE SILICON RUNTIME"
                    title="Direct Metal 3 & WebGPU Compute"
                    desc="Bypasses DOM layout reflows and V8 pauses. Directly rasterizes glyph quads at 120 FPS."
                    metrics={[
                      { label: "Input Latency", value: "4.2ms", sub: "DIRECT HW" },
                      { label: "Framerate", value: "120 FPS", sub: "LOCKED V-SYNC" },
                      { label: "GPU Pipeline", value: "Metal 3", sub: "COMPUTE SHADER" },
                      { label: "DOM Reflows", value: "0 ms", sub: "ZERO BROWSER GC" },
                    ]}
                    hexDump={["0x99", "0x3D", "0x14", "0xEF", "0x7A", "0x55"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 6: ACTIONABLE OUTPUT (Side-by-Side Zero-Scroll Xcode Dock)     */}
            {/* =================================================================== */}
            {mode === "output" && (
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 relative">
                <div className="space-y-1 flex-1 min-w-0">
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                    <span>
                      <span className="text-[#569cd6]">use</span> crux_build::&#123;<span className="text-[#4ec9b0]">LLVMBackend</span>, <span className="text-[#4ec9b0]">MachOBinary</span>&#125;;
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">2</span>
                    <span>
                      <span className="text-[#569cd6]">pub fn</span> <span className="text-[#dcdcaa]">emit_native_binary</span>(<span className="text-[#9cdcfe]">target</span>: <span className="text-[#4ec9b0]">TargetTriple</span>) -&gt; <span className="text-[#4ec9b0]">Result</span>&lt;<span className="text-[#4ec9b0]">MachOBinary</span>&gt; &#123;
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">3</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">let</span> <span className="text-[#9cdcfe]">codegen</span> = <span className="text-[#4ec9b0]">LLVMBackend</span>::<span className="text-[#dcdcaa]">new</span>(<span className="text-[#9cdcfe]">target</span>)?;
                    </span>
                  </div>

                  {/* Line 4: Active Probe Token with horizontal connector */}
                  <div className="flex items-center justify-between bg-white/5 py-1 rounded-[4px] relative">
                    <div className="flex items-baseline min-w-0">
                      <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">4</span>
                      <span className="pl-4">
                        <span className="text-[#569cd6]">let</span> <span className="text-[#9cdcfe]">bin</span> = <span className="text-[#9cdcfe]">codegen</span>.<span className="text-[#dcdcaa]">emit_arm64_slice</span>(<span className="text-[#ce9178]">&quot;aarch64-apple-darwin&quot;</span>)?;
                      </span>
                      <span className="ml-2 relative inline-flex items-center bg-[#0055FF]/15 border border-[#0055FF] rounded-[4px] px-2 py-0.5 text-white font-mono text-[9px] shadow-[0_0_12px_rgba(0,85,255,0.4)]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#0055FF] animate-pulse mr-1" />
                        <span>ARM64 READY // 140ms</span>
                      </span>
                    </div>

                    <div className="hidden lg:flex flex-1 items-center min-w-[16px] max-w-[48px] mx-2">
                      <div className="w-full h-0 border-b border-dashed border-[#0055FF]" />
                      <div className="w-0 h-0 border-y-[4px] border-y-transparent border-l-[6px] border-l-[#0055FF] -ml-0.5" />
                    </div>
                  </div>

                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                    <span className="pl-4">
                      <span className="text-[#4ec9b0]">Ok</span>(<span className="text-[#9cdcfe]">bin</span>)
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                    <span>&#125;</span>
                  </div>
                </div>

                <div className="w-full lg:w-[240px] shrink-0">
                  <AppleTelemetryHUD
                    channel="CH-05 // LLVM"
                    badge="ACTIONABLE OUTPUT"
                    title="Native Mach-O ARM64 Emitter"
                    desc="Emits direct ARM64 host binaries in 140ms with zero cloud build dependencies."
                    metrics={[
                      { label: "Build Latency", value: "140ms", sub: "LLVM 18 DIRECT" },
                      { label: "Target Architecture", value: "ARM64", sub: "APPLE SILICON" },
                      { label: "Format Slice", value: "Mach-O", sub: "0xFEEDFACF" },
                      { label: "Cloud Overhead", value: "0 ms", sub: "LOCAL EXCLUSIVE" },
                    ]}
                    hexDump={["0xCF", "0xFA", "0xED", "0xFE", "0x0C", "0x00"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 7: AUTONOMOUS @CRUXAI AGENTS (Side-by-Side Zero-Scroll Dock)   */}
            {/* =================================================================== */}
            {mode === "agents" && (
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 relative">
                <div className="space-y-1 flex-1 min-w-0">
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

                  {/* Inline Diff Box with rounded corners and high contrast green */}
                  <div className="my-1 border border-[#222222] bg-[#0a0a0a] rounded-[6px] overflow-hidden">
                    <div className="flex justify-between items-center px-3 py-1 border-b border-[#222222] bg-[#111111]">
                      <span className="text-[10px] font-mono text-white flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 bg-[#16a34a] rounded-full" />
                        <span>@CruxAI proposes atomic bitset</span>
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
                              className="px-2 py-0.5 bg-white text-black font-mono text-[9px] uppercase font-bold hover:bg-[#CCCCCC] transition-none cursor-pointer rounded-[3px]"
                            >
                              Accept
                            </button>
                            <button
                              type="button"
                              onClick={() => setDiffState("rejected")}
                              className="px-2 py-0.5 border border-[#222222] bg-[#000000] text-[#888888] font-mono text-[9px] uppercase hover:text-white transition-none cursor-pointer rounded-[3px]"
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

                    <div className="p-2 text-[10.5px] leading-relaxed font-mono">
                      <div className="bg-[#FF453A]/10 text-[#FF453A] px-2 py-0.5 border-l-2 border-[#FF453A] line-through rounded-r-[2px]">
                        - const lock = await this.daemon.acquireLock(channel);
                      </div>
                      <div className="bg-[#16a34a]/10 text-[#16a34a] px-2 py-0.5 border-l-2 border-[#16a34a] font-semibold rounded-r-[2px]">
                        + const ticket = await atomicBitset.claimTicket();
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
                </div>

                <div className="w-full lg:w-[240px] shrink-0">
                  <AppleTelemetryHUD
                    channel="CH-06 // AGENT"
                    badge="AUTONOMOUS AI ENGINE"
                    title="@CruxAI Local Refactor"
                    desc="Embedded agent proposes lock-free atomic bitset patch evaluated via local PTY bridge."
                    metrics={[
                      { label: "Evaluation", value: "12ms", sub: "LOCAL PTY" },
                      { label: "Verification", value: "100%", sub: "PASSED TESTS" },
                      { label: "Architecture", value: "Atomic", sub: "BITSET RING" },
                      { label: "Deadlock Risk", value: "0.00%", sub: "LOCK-FREE WAL" },
                    ]}
                    hexDump={["0x00", "0xFF", "0x66", "0x2A", "0x51", "0x90"]}
                    activeHexIndex={activeHexIndex}
                    accentColor="#16a34a"
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
