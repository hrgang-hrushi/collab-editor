"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Search,
  Plus,
  Download,
  Play,
  Share2,
  Check,
  CheckCircle2,
  FileCode2,
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

interface TechnicalCalloutProps {
  badge: string;
  title: string;
  desc: string;
  telemetry: string;
  accentColor?: string;
  className?: string;
}

function TechnicalCalloutBubble({
  badge,
  title,
  desc,
  telemetry,
  accentColor = "#0055FF",
  className = "",
}: TechnicalCalloutProps) {
  return (
    <div
      className={`relative border border-dashed bg-[#060914]/95 text-left p-3 sm:p-3.5 transition-all select-none shadow-[0_0_25px_rgba(0,85,255,0.12)] ${className}`}
      style={{
        borderColor: accentColor,
        borderRadius: "8px", // Subtle cloud/capsule soft contour with dashed border
      }}
    >
      {/* Corner Blueprint Plus Markers */}
      <span className="absolute -top-1.5 -left-1.5 font-mono text-[9px] leading-none select-none font-bold" style={{ color: accentColor }}>
        +
      </span>
      <span className="absolute -top-1.5 -right-1.5 font-mono text-[9px] leading-none select-none font-bold" style={{ color: accentColor }}>
        +
      </span>
      <span className="absolute -bottom-1.5 -left-1.5 font-mono text-[9px] leading-none select-none font-bold" style={{ color: accentColor }}>
        +
      </span>
      <span className="absolute -bottom-1.5 -right-1.5 font-mono text-[9px] leading-none select-none font-bold" style={{ color: accentColor }}>
        +
      </span>

      {/* Top Header Row with Pulsing LED */}
      <div className="flex items-center justify-between gap-2 pb-1.5 border-b border-[#222222]/80">
        <div className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-wider font-bold" style={{ color: accentColor }}>
          <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: accentColor }} />
          <span>{badge}</span>
        </div>
        <span className="text-[8px] font-mono text-[#555555]">CRUX KERNEL</span>
      </div>

      {/* Title */}
      <h4 className="mt-2 text-[12px] font-medium text-white font-sans tracking-tight">
        {title}
      </h4>

      {/* Description */}
      <p className="mt-1 text-[10.5px] font-sans text-[#888888] leading-relaxed">
        {desc}
      </p>

      {/* Telemetry Footer */}
      <div className="mt-2.5 pt-2 border-t border-[#1a1a24] flex items-center justify-between font-mono text-[8.5px] text-[#666666]">
        <span className="text-[#888888]">{telemetry}</span>
        <span className="text-[#00FF66] font-bold">LIVE ●</span>
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

  // Collaborative live typing strings for multiplayer
  const [sarahText, setSarahText] = useState("");
  const [marcusText, setMarcusText] = useState("");
  const [alexText, setAlexText] = useState("");

  // Phased natural typing simulation for multiplayer cursors
  useEffect(() => {
    if (mode !== "multiplayer") return;

    const sTarget = 'channel = "stream-mesh"';
    const mTarget = "timeout = 2500;";
    const aTarget = 'ticket.id + ":OK"';

    let sIdx = 0;
    let mIdx = 0;
    let aIdx = 0;
    let phase = 0; // 0: typing, 1: pause, 2: deleting, 3: restart pause
    let pauseCounter = 0;

    const timer = setInterval(() => {
      if (phase === 0) {
        if (sIdx < sTarget.length) sIdx++;
        if (mIdx < mTarget.length) mIdx++;
        if (aIdx < aTarget.length) aIdx++;
        if (sIdx >= sTarget.length && mIdx >= mTarget.length && aIdx >= aTarget.length) {
          phase = 1;
          pauseCounter = 0;
        }
      } else if (phase === 1) {
        pauseCounter++;
        if (pauseCounter > 16) {
          phase = 2;
        }
      } else if (phase === 2) {
        if (sIdx > 0) sIdx--;
        if (mIdx > 0) mIdx--;
        if (aIdx > 0) aIdx--;
        if (sIdx === 0 && mIdx === 0 && aIdx === 0) {
          phase = 3;
          pauseCounter = 0;
        }
      } else if (phase === 3) {
        pauseCounter++;
        if (pauseCounter > 4) {
          phase = 0;
        }
      }

      setSarahText(sTarget.slice(0, sIdx));
      setMarcusText(mTarget.slice(0, mIdx));
      setAlexText(aTarget.slice(0, aIdx));
    }, 85);

    return () => clearInterval(timer);
  }, [mode]);

  // Context scanning animation (for mode="context")
  const [scanLine, setScanLine] = useState(2);
  useEffect(() => {
    if (mode !== "context") return;
    const interval = setInterval(() => {
      setScanLine((prev) => (prev >= 11 ? 2 : prev + 1));
    }, 550);
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
              <span className="w-1.5 h-1.5 rounded-full bg-[#38b6ff] animate-pulse" />
              <span>3 Active Peers</span>
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
        <aside className="w-44 sm:w-50 border-r border-[#222222] bg-[#000000] flex flex-col shrink-0 select-none">
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
            {/* DEMO 1: REAL-TIME COLLABORATIVE MESH (3 Cursors Exact Typing Motion)*/}
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
                {/* Marcus Vance typing on Line 5 */}
                <div className="flex items-baseline bg-[#ffffff]/5 py-0.5">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">5</span>
                  <span className="pl-4">
                    <span className="text-[#9cdcfe]">timeout</span> ={" "}
                    <span className="relative inline-flex items-center text-[#b5cea8]">
                      <span>{marcusText || "2500;"}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#ff70a6] ml-0.5 align-middle animate-pulse" />
                      <span className="absolute -top-7 left-full -ml-1 pointer-events-none z-30 select-none">
                        <CruxPointerCursor
                          name="Marcus Vance"
                          uid="MARCUS-V"
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
                {/* Sarah Lin typing on Line 8 */}
                <div className="flex items-baseline bg-[#ffffff]/5 py-0.5">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">8</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">async</span> <span className="text-[#dcdcaa]">acquireLock</span>(
                    <span className="relative inline-flex items-center text-[#ce9178]">
                      <span>{sarahText || '"stream-mesh"'}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#38b6ff] ml-0.5 align-middle animate-pulse" />
                      <span className="absolute -top-7 left-full -ml-1 pointer-events-none z-30 select-none">
                        <CruxPointerCursor
                          name="Sarah Lin"
                          uid="SARAH-L"
                          color="#38b6ff"
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
                    <span className="text-[#9cdcfe]">console</span>.<span className="text-[#dcdcaa]">log</span>(<span className="text-[#ce9178]">&quot;[StreamSyncer] Mutual exclusion lock acquired&quot;</span>);
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">10</span>
                  <span className="pl-8">
                    <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">ticket</span> = <span className="text-[#569cd6]">await</span> <span className="text-[#569cd6]">this</span>.<span className="text-[#9cdcfe]">daemon</span>.<span className="text-[#dcdcaa]">acquireLock</span>(channel);
                  </span>
                </div>
                {/* Alex Chen typing on Line 11 */}
                <div className="flex items-baseline bg-[#ffffff]/5 py-0.5">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">11</span>
                  <span className="pl-8">
                    <span className="text-[#569cd6]">return</span>{" "}
                    <span className="relative inline-flex items-center text-[#9cdcfe]">
                      <span>{alexText || 'ticket.id + ":OK";'}</span>
                      <span className="inline-block w-1.5 h-3.5 bg-[#22c55e] ml-0.5 align-middle animate-pulse" />
                      <span className="absolute -top-7 left-full -ml-1 pointer-events-none z-30 select-none hidden sm:block">
                        <CruxPointerCursor
                          name="Alex Chen"
                          uid="ALEX-C"
                          color="#22c55e"
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
            {/* =================================================================== */}
            {/* =================================================================== */}
            {/* DEMO 2: CONTEXT AWARENESS (AST Ingestion & Symbol Indexing Scanning) */}
            {/* =================================================================== */}
            {mode === "context" && (
              <div className="flex flex-col xl:flex-row xl:items-start justify-between gap-3 relative">
                <div className="space-y-0.5 flex-1 min-w-0">
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
                    {scanLine === 2 && (
                      <span className="ml-2 text-[9px] bg-white text-black px-1.5 font-bold">[PARSING]</span>
                    )}
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
                  <div className={`flex items-baseline bg-[#ffffff]/5 ${scanLine === 5 ? "bg-white/15" : ""}`}>
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">5</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">return</span> <span className="text-[#9cdcfe]">ast</span>.<span className="text-[#dcdcaa]">buildSymbolIndex</span>();
                    </span>
                    <span className="ml-2 text-[9px] bg-white text-black px-1.5 font-bold">[64,280 NODES]</span>
                    {/* Dotted leader line extending into free space */}
                    <span className="hidden xl:inline-flex items-center ml-2">
                      <span className="border-b border-dashed border-[#0055FF] w-6" />
                      <span className="text-[#0055FF] text-[8px] -ml-0.5">▶</span>
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                    <span>&#125;</span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                    <span></span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                    <span className="text-[#6a9955] italic">// 0.08ms memory-mapped AST kernel buffer</span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">9</span>
                    <span>
                      <span className="text-[#569cd6]">export const</span> <span className="text-[#9cdcfe]">workspaceIndex</span> = <span className="text-[#dcdcaa]">indexWorkspace</span>([<span className="text-[#ce9178]">&quot;src/**/*.rs&quot;</span>, <span className="text-[#ce9178]">&quot;src/**/*.ts&quot;</span>]);
                    </span>
                  </div>
                </div>

                {/* Technical Callout Bubble */}
                <div className="xl:w-[210px] 2xl:w-[230px] shrink-0 mt-3 xl:mt-1">
                  <TechnicalCalloutBubble
                    badge="CONTEXT AWARENESS"
                    title="Kernel Symbol Indexing"
                    desc="Memory-mapped AST topology parses workspace buffers in 0.08ms. Zero-latency context retrieval for agents."
                    telemetry="64,280 NODES · 0.08ms"
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 3: INTELLIGENT PROCESSING (Active AST Synthesis & Delta Merge) */}
            {/* =================================================================== */}
            {mode === "processing" && (
              <div className="flex flex-col xl:flex-row xl:items-start justify-between gap-3 relative">
                <div className="space-y-0.5 flex-1 min-w-0">
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
                  <div className="flex items-baseline bg-[#ffffff]/5">
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">4</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">return</span> <span className="text-[#9cdcfe]">tree</span>.<span className="text-[#dcdcaa]">transformDeterministic</span>(<span className="text-[#9cdcfe]">delta</span>.<span className="text-[#9cdcfe]">patch</span>, <span className="text-[#b5cea8]">0x{resolvedToken.toString(16)}</span>);
                      <span className="ml-2 text-[9px] bg-white text-black font-bold px-1.5 py-0.2">
                        [TOKEN CONVERGED]
                      </span>
                    </span>
                    {/* Dotted leader line */}
                    <span className="hidden xl:inline-flex items-center ml-2">
                      <span className="border-b border-dashed border-[#0055FF] w-6" />
                      <span className="text-[#0055FF] text-[8px] -ml-0.5">▶</span>
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                    <span>&#125;</span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">6</span>
                    <span></span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                    <span className="text-[#6a9955] italic">// Structural AST convergence without text collision storms</span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                    <span>
                      <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">convergedNode</span> = <span className="text-[#dcdcaa]">synthesizeASTDelta</span>(&#123; <span className="text-[#9cdcfe]">targetId</span>: <span className="text-[#b5cea8]">{resolvedToken}</span> &#125;);
                    </span>
                  </div>
                </div>

                {/* Technical Callout Bubble */}
                <div className="xl:w-[210px] 2xl:w-[230px] shrink-0 mt-3 xl:mt-1">
                  <TechnicalCalloutBubble
                    badge="INTELLIGENT PROCESSING"
                    title="Deterministic AST Synthesis"
                    desc="Structural token reconciliation maintains syntax tree validity through multi-pass JIT compiler verification."
                    telemetry={`TOKEN: 0x${resolvedToken.toString(16)} · JIT: VALID`}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 4: DECENTRALIZED AST-CRDT (Rust Structural Vector Merge)       */}
            {/* =================================================================== */}
            {mode === "crdt" && (
              <div className="flex flex-col xl:flex-row xl:items-start justify-between gap-3 relative">
                <div className="space-y-0.5 flex-1 min-w-0">
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
                      <span className="text-[#569cd6]">pub fn</span> <span className="text-[#dcdcaa]">merge_deterministic</span>(&amp;<span className="text-[#569cd6]">mut self</span>, <span className="text-[#9cdcfe]">patch</span>: &amp;<span className="text-[#4ec9b0]">ASTPatch</span>, <span className="text-[#9cdcfe]">node</span>: <span className="text-[#4ec9b0]">NodeId</span>) -&gt; <span className="text-[#4ec9b0]">Result</span>&lt;<span className="text-[#569cd6]">u64</span>&gt; &#123;
                    </span>
                  </div>
                  <div className="flex items-baseline bg-[#ffffff]/5">
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">6</span>
                    <span className="pl-8">
                      <span className="text-[#569cd6]">let</span> <span className="text-[#9cdcfe]">epoch</span> = <span className="text-[#569cd6]">self</span>.<span className="text-[#9cdcfe]">vector_clock</span>.<span className="text-[#dcdcaa]">fetch_add</span>(<span className="text-[#b5cea8]">1</span>, <span className="text-[#4ec9b0]">Ordering</span>::<span className="text-[#4ec9b0]">SeqCst</span>);
                      <span className="ml-2 text-[9px] bg-white text-black font-bold px-1.5 py-0.2">
                        [EPOCH: #{crdtEpoch}]
                      </span>
                    </span>
                    {/* Dotted leader line */}
                    <span className="hidden xl:inline-flex items-center ml-2">
                      <span className="border-b border-dashed border-[#0055FF] w-6" />
                      <span className="text-[#0055FF] text-[8px] -ml-0.5">▶</span>
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                    <span className="pl-8">
                      <span className="text-[#569cd6]">self</span>.<span className="text-[#dcdcaa]">apply_atomic_token</span>(<span className="text-[#9cdcfe]">patch</span>.<span className="text-[#dcdcaa]">token</span>(), <span className="text-[#9cdcfe]">epoch</span>);
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                    <span className="pl-8">
                      <span className="text-[#4ec9b0]">Ok</span>(<span className="text-[#9cdcfe]">epoch</span>)
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">9</span>
                    <span className="pl-4">&#125;</span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">10</span>
                    <span>&#125;</span>
                  </div>
                </div>

                {/* Technical Callout Bubble */}
                <div className="xl:w-[210px] 2xl:w-[230px] shrink-0 mt-3 xl:mt-1">
                  <TechnicalCalloutBubble
                    badge="DECENTRALIZED CRDT"
                    title="Atomic Vector Convergence"
                    desc="Lamport vector clocks resolve structural AST patches deterministically. Zero collision storms across concurrent edits."
                    telemetry={`EPOCH: #${crdtEpoch} · COLLISION: 0.00%`}
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 5: NATIVE SILICON RUNTIME (Metal WebGPU Direct Phosphor 120 FPS)*/}
            {/* =================================================================== */}
            {mode === "silicon" && (
              <div className="flex flex-col xl:flex-row xl:items-start justify-between gap-3 relative">
                <div className="space-y-0.5 flex-1 min-w-0">
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
                  <div className="flex items-baseline bg-[#ffffff]/5">
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">9</span>
                    <span>) &#123;</span>
                    <span className="ml-2 text-[9px] bg-white text-black font-bold px-1.5 py-0.2">
                      [120 FPS // METAL 3]
                    </span>
                    {/* Dotted leader line */}
                    <span className="hidden xl:inline-flex items-center ml-2">
                      <span className="border-b border-dashed border-[#0055FF] w-6" />
                      <span className="text-[#0055FF] text-[8px] -ml-0.5">▶</span>
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">10</span>
                    <span className="pl-4">
                      <span className="text-[#9cdcfe]">surface</span>.<span className="text-[#dcdcaa]">write</span>(<span className="text-[#dcdcaa]">sample_glyph</span>(<span className="text-[#9cdcfe]">atlas</span>, <span className="text-[#9cdcfe]">vertices</span>[<span className="text-[#9cdcfe]">gid</span>.<span className="text-[#9cdcfe]">x</span>]), <span className="text-[#9cdcfe]">gid</span>);
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">11</span>
                    <span>&#125;</span>
                  </div>
                </div>

                {/* Technical Callout Bubble */}
                <div className="xl:w-[210px] 2xl:w-[230px] shrink-0 mt-3 xl:mt-1">
                  <TechnicalCalloutBubble
                    badge="NATIVE SILICON PIPELINE"
                    title="Direct Metal 3 & WebGPU"
                    desc="Bypasses DOM layout reflows and V8 GC pauses. Rasterizes glyph quads directly via GPU compute at locked 120 FPS."
                    telemetry="LATENCY: 4.2ms · 120 FPS"
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 6: ACTIONABLE OUTPUT (Mach-O ARM64 Compiler Output Artifact)   */}
            {/* =================================================================== */}
            {mode === "output" && (
              <div className="flex flex-col xl:flex-row xl:items-start justify-between gap-3 relative">
                <div className="space-y-0.5 flex-1 min-w-0">
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
                  <div className="flex items-baseline bg-[#ffffff]/5">
                    <span className="w-6 text-right text-[10px] text-[#0055FF] font-bold pr-3 select-none">6</span>
                    <span className="pl-4">
                      <span className="text-[#569cd6]">let</span> <span className="text-[#9cdcfe]">artifact</span> = <span className="text-[#9cdcfe]">codegen</span>.<span className="text-[#dcdcaa]">emit_arm64_slice</span>(<span className="text-[#ce9178]">&quot;aarch64-apple-darwin&quot;</span>)?;
                      <span className="ml-2 text-[9px] bg-white text-black font-bold px-1.5 py-0.2">
                        [ARM64 READY // 140ms]
                      </span>
                    </span>
                    {/* Dotted leader line */}
                    <span className="hidden xl:inline-flex items-center ml-2">
                      <span className="border-b border-dashed border-[#0055FF] w-6" />
                      <span className="text-[#0055FF] text-[8px] -ml-0.5">▶</span>
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">7</span>
                    <span className="pl-4">
                      <span className="text-[#4ec9b0]">Ok</span>(<span className="text-[#9cdcfe]">artifact</span>)
                    </span>
                  </div>
                  <div className="flex items-baseline">
                    <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                    <span>&#125;</span>
                  </div>
                </div>

                {/* Technical Callout Bubble */}
                <div className="xl:w-[210px] 2xl:w-[230px] shrink-0 mt-3 xl:mt-1">
                  <TechnicalCalloutBubble
                    badge="ACTIONABLE OUTPUT"
                    title="Native Mach-O Binary Emitter"
                    desc="Emits direct ARM64 host binaries in 140ms. Instant execution artifacts with zero cloud build overhead."
                    telemetry="TARGET: ARM64-DARWIN · 140ms"
                    accentColor="#0055FF"
                  />
                </div>
              </div>
            )}

            {/* =================================================================== */}
            {/* DEMO 7: AUTONOMOUS @CRUXAI AGENTS (Suggestion Review Diff)          */}
            {/* =================================================================== */}
            {mode === "agents" && (
              <div className="flex flex-col xl:flex-row xl:items-start justify-between gap-3 relative">
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
                        {/* Dotted leader line from suggestion badge */}
                        <span className="hidden xl:inline-flex items-center ml-2">
                          <span className="border-b border-dashed border-[#00FF66] w-6" />
                          <span className="text-[#00FF66] text-[8px] -ml-0.5">▶</span>
                        </span>
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
                </div>

                {/* Technical Callout Bubble */}
                <div className="xl:w-[210px] 2xl:w-[230px] shrink-0 mt-3 xl:mt-1">
                  <TechnicalCalloutBubble
                    badge="AUTONOMOUS AI ENGINE"
                    title="@CruxAI Local Refactor"
                    desc="Embedded agent proposes lock-free atomic bitset patch. Deterministically evaluated via local PTY bridge."
                    telemetry="STATUS: VERIFIED · 100% PASS"
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
