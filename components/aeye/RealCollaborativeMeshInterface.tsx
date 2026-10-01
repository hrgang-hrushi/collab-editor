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

export default function RealCollaborativeMeshInterface({
  mode = "multiplayer",
  className = "",
}: RealCollaborativeMeshInterfaceProps) {
  // Determine active file based on mode
  const initialFile = useMemo(() => {
    if (mode === "silicon" || mode === "output") return "spatial_engine.metal";
    if (mode === "crdt" || mode === "context") return "ast_crdt_sync.ts";
    return "stream_syncer.ts";
  }, [mode]);

  const [activeFile, setActiveFile] = useState(initialFile);
  const [diffState, setDiffState] = useState<"pending" | "accepted" | "rejected">("pending");
  const [copiedLink, setCopiedLink] = useState(false);
  const [typedSuffix, setTypedSuffix] = useState("");

  useEffect(() => {
    setActiveFile(initialFile);
  }, [initialFile]);

  // Collaborative live typing animation by peer Sarah Lin
  useEffect(() => {
    let timeout: NodeJS.Timeout;
    const targetText = 'channel = "stream-primary"';
    let index = 0;
    let isTyping = true;

    const runLoop = () => {
      if (isTyping) {
        if (index < targetText.length) {
          index += 1;
          setTypedSuffix(targetText.slice(0, index));
          timeout = setTimeout(runLoop, 150);
        } else {
          isTyping = false;
          timeout = setTimeout(runLoop, 2500);
        }
      } else {
        if (index > 0) {
          index -= 1;
          setTypedSuffix(targetText.slice(0, index));
          timeout = setTimeout(runLoop, 80);
        } else {
          isTyping = true;
          timeout = setTimeout(runLoop, 1200);
        }
      }
    };

    timeout = setTimeout(runLoop, 600);
    return () => clearTimeout(timeout);
  }, [activeFile]);

  const handleCopy = () => {
    if (typeof window !== "undefined") {
      navigator.clipboard?.writeText(window.location.href);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    }
  };

  // BranchedMenu Tree Data matching ZenithFileTree.tsx exactly
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
            value: "ast_crdt_sync.ts",
            label: "ast_crdt_sync.ts",
            icon: JavaScriptIcon,
          },
        ],
      },
      {
        value: "Cargo.toml",
        label: "Cargo.toml",
        icon: File01Icon,
      },
    ];
  }, []);

  const isMetal = activeFile.endsWith(".metal");
  const isAgentDiff = mode === "agents";

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
        {/* Left: Brand + Search */}
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

        {/* Right: Collaborators & Actions */}
        <div className="flex items-center gap-2">
          {/* Collaborator Badge */}
          <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#111111] border border-[#222222] text-[10px] font-mono text-white">
            <span className="w-1.5 h-1.5 rounded-full bg-[#38b6ff] animate-pulse" />
            <span>Sarah Lin</span>
          </div>

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
        {/* Left Sidebar: Exact BranchedMenu Tree Branch */}
        <aside className="w-44 sm:w-48 border-r border-[#222222] bg-[#000000] flex flex-col shrink-0 select-none">
          <div className="px-3 py-1.5 border-b border-[#222222] text-[10px] font-bold tracking-widest text-[#888888] uppercase flex items-center justify-between font-mono">
            <span>Explorer</span>
            <div className="flex items-center gap-1.5 text-[#666666]">
              <Plus className="w-3 h-3 hover:text-white cursor-pointer" />
              <Download className="w-3 h-3 hover:text-white cursor-pointer" />
            </div>
          </div>

          {/* Real BranchedMenu with SVG Curved Branches */}
          <div className="flex-1 py-1 font-mono text-xs overflow-y-auto">
            <BranchedMenu
              items={branchedMenuItems}
              defaultOpen={[0, 1]}
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
              lineWidth={1.2}
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
            {/* Live Multiplayer Cursor */}
            {!isAgentDiff && (
              <div className="absolute top-[148px] sm:top-[156px] left-[175px] sm:left-[215px] pointer-events-none z-30">
                <CruxPointerCursor
                  name="Sarah Lin"
                  uid="SARAH-L"
                  color="#38b6ff"
                  status="typing"
                />
              </div>
            )}

            {/* Mode: Agent Inline Suggestion Diff */}
            {isAgentDiff ? (
              <div className="space-y-1">
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
                      <span className="w-1.5 h-1.5 bg-[#38b6ff]" />
                      <span>Sarah Lin suggests an update</span>
                      {diffState === "accepted" && (
                        <span className="ml-2 px-1.5 py-0.2 text-[9px] bg-black border border-[#222222] text-[#00FF66] font-mono">
                          [ACCEPTED ✓]
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
              </div>
            ) : isMetal ? (
              /* Mode: Metal Shader */
              <div className="space-y-0.5">
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">1</span>
                  <span className="text-[#6a9955] italic">// WebGPU & Metal Compute Shader Pipeline</span>
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
                    <span className="text-[#4ec9b0]">texture2d</span>&lt;<span className="text-[#569cd6]">float</span>, access::sample&gt; <span className="text-[#9cdcfe]">atlas</span> [[texture(0)]]
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">8</span>
                  <span>) &#123;</span>
                </div>
                <div className="flex items-baseline bg-[#ffffff]/5">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">9</span>
                  <span className="pl-4">
                    <span className="text-[#6a9955] italic">// Phosphor rasterization in 4.2ms</span>
                    <span className="inline-block w-1.5 h-3.5 bg-white ml-1 align-middle animate-pulse" />
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">10</span>
                  <span>&#125;</span>
                </div>
              </div>
            ) : (
              /* Mode: TypeScript Standard (stream_syncer.ts / ast_crdt_sync.ts) */
              <div className="space-y-0.5">
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
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">5</span>
                  <span className="pl-4">
                    <span className="text-[#9cdcfe]">timeout</span> = <span className="text-[#b5cea8]">5000</span>;
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
                <div className="flex items-baseline bg-[#ffffff]/5">
                  <span className="w-6 text-right text-[10px] text-white font-bold pr-3 select-none">8</span>
                  <span className="pl-4">
                    <span className="text-[#569cd6]">async</span> <span className="text-[#dcdcaa]">acquireLock</span>({typedSuffix}
                    <span className="inline-block w-1.5 h-3.5 bg-white ml-0.5 align-middle animate-pulse" />
                    ) &#123;
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">9</span>
                  <span className="pl-8">
                    <span className="text-[#9cdcfe]">console</span>.<span className="text-[#dcdcaa]">log</span>(<span className="text-[#ce9178]">&quot;[StreamSyncer] Requesting mutual exclusion lock...&quot;</span>);
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">10</span>
                  <span className="pl-8">
                    <span className="text-[#569cd6]">const</span> <span className="text-[#9cdcfe]">ticket</span> = <span className="text-[#569cd6]">await</span> <span className="text-[#569cd6]">this</span>.<span className="text-[#9cdcfe]">daemon</span>.<span className="text-[#dcdcaa]">acquireLock</span>(channel);
                  </span>
                </div>
                <div className="flex items-baseline">
                  <span className="w-6 text-right text-[10px] text-[#444444] pr-3 select-none">11</span>
                  <span className="pl-8">
                    <span className="text-[#569cd6]">return</span> <span className="text-[#9cdcfe]">ticket</span>;
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
          </div>
        </main>
      </div>
    </div>
  );
}
