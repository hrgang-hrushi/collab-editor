"use client";

import React, { useState, useEffect } from "react";
import {
  Zap,
  Terminal,
  Cpu,
  Layers,
  Check,
  Play,
  RotateCcw,
  Sparkles,
  ExternalLink,
  Code2,
  FileCode2,
  Share2,
} from "lucide-react";
import CruxBrandLogo from "../CruxBrandLogo";

interface CruxCollaborativeDemoProps {
  onLaunchWebEditor?: () => void;
  onOpenWaitlist?: () => void;
}

const INITIAL_CODE_LINES = [
  { num: "01", text: "// Crux AST-CRDT Lock-Free Vector Mesh · Native Mach-O Kernel", indent: 0, tag: "comment" },
  { num: "02", text: "use crux_core::crdt::{ASTVectorTree, ConflictFreeResolver, NodeId};", indent: 0, tag: "import" },
  { num: "03", text: "use crux_gpu::metal::{CAMetalDrawable, QuadShaderPipeline};", indent: 0, tag: "import" },
  { num: "04", text: "", indent: 0, tag: "empty" },
  { num: "05", text: "#[inline(always)]", indent: 0, tag: "attr" },
  { num: "06", text: "pub async fn synchronize_collaborative_ring(", indent: 0, tag: "fn" },
  { num: "07", text: "    local_tree: &mut ASTVectorTree,", indent: 4, tag: "arg" },
  { num: "08", text: "    remote_delta: &[u8],", indent: 4, tag: "arg" },
  { num: "09", text: "    peer_token: NodeId,", indent: 4, tag: "arg" },
  { num: "10", text: ") -> Result<CRDTSyncMetrics, KernelPanic> {", indent: 0, tag: "fn_ret" },
  { num: "11", text: "    // Zero-copy deserialization directly from POSIX shm ring", indent: 4, tag: "comment" },
  { num: "12", text: "    let mutation = ConflictFreeResolver::parse_ast_patch(remote_delta)?;", indent: 4, tag: "code" },
  { num: "13", text: "    let convergence_instant = std::time::Instant::now();", indent: 4, tag: "code" },
  { num: "14", text: "", indent: 4, tag: "empty" },
  { num: "15", text: "    // AST-CRDT structural merge: resolves without text collision storms", indent: 4, tag: "comment" },
  { num: "16", text: "    let commit_hash = local_tree.merge_deterministic(&mutation, peer_token)?;", indent: 4, tag: "code" },
  { num: "17", text: "    crux_gpu::invalidate_dirty_quads(local_tree.dirty_range());", indent: 4, tag: "code" },
  { num: "18", text: "", indent: 4, tag: "empty" },
  { num: "19", text: "    Ok(CRDTSyncMetrics {", indent: 4, tag: "ret" },
  { num: "20", text: "        latency_us: convergence_instant.elapsed().as_micros() as u32,", indent: 8, tag: "field" },
  { num: "21", text: "        conflicts: 0,", indent: 8, tag: "field" },
  { num: "22", text: "        sync_state: SyncTopology::MeshConverged,", indent: 8, tag: "field" },
  { num: "23", text: "    })", indent: 4, tag: "ret" },
  { num: "24", text: "}", indent: 0, tag: "close" },
];

export default function CruxCollaborativeDemo({
  onLaunchWebEditor,
  onOpenWaitlist,
}: CruxCollaborativeDemoProps) {
  const [activeTab, setActiveTab] = useState<"editor" | "terminal" | "telemetry">("editor");
  const [isSimulating, setIsSimulating] = useState(true);
  const [activeFile, setActiveFile] = useState("ring_buffer.rs");
  const [typingIndex, setTypingIndex] = useState(0);
  const [simulatedConflictResolved, setSimulatedConflictResolved] = useState(false);
  const [agentPassCount, setAgentPassCount] = useState(1);
  const [activeTerminalTab, setActiveTerminalTab] = useState<"stdout" | "agent" | "ipc">("stdout");

  // Tarika cursor coordinate state
  const [tarikaPos, setTarikaPos] = useState({ x: 190, y: 140, line: 12 });
  // Pavan cursor coordinate state
  const [pavanPos, setPavanPos] = useState({ x: 310, y: 220, line: 16 });

  // Terminal stdout logs
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    "crux-sh:~/crux-core$ bun run stream_syncer.ts",
    "[StreamSyncer] Requesting mutual exclusion lock for: stream-mesh-primary...",
    "[StreamSyncer] Lock acquired successfully! Ticket: tkt-ddkdluc",
    "[StreamSyncer] Mesh channel ready on origin: unix:///var/run/crux-7447.sock",
    "[@CruxAI] Initialized AST-CRDT ring buffer with 3 active peer channels.",
  ]);

  // Collaborative typing animation
  useEffect(() => {
    if (!isSimulating) return;

    const interval = setInterval(() => {
      // Natural oscillating cursor steps
      setTarikaPos((prev) => {
        const nextX = 140 + Math.sin(Date.now() / 900) * 110;
        const nextY = 120 + Math.cos(Date.now() / 1100) * 40;
        return { x: Math.round(nextX), y: Math.round(nextY), line: 12 };
      });

      setPavanPos((prev) => {
        const nextX = 260 + Math.cos(Date.now() / 850) * 130;
        const nextY = 195 + Math.sin(Date.now() / 1200) * 50;
        return { x: Math.round(nextX), y: Math.round(nextY), line: 16 };
      });

      setTypingIndex((prev) => (prev + 1) % 40);
    }, 450);

    return () => clearInterval(interval);
  }, [isSimulating]);

  const handleTriggerConflictTest = () => {
    setSimulatedConflictResolved(true);
    setTerminalLogs((prev) => [
      ...prev.slice(-7),
      "[CRDT-EVENT] Concurrent AST insertion received from Node [PAVAN R.] (line 16: col 34)",
      "[CRDT-EVENT] Concurrent AST insertion received from Node [TARIKA K.] (line 16: col 34)",
      "[@CruxAI] Resolved structural fork: AST vector priority preserved (0 syntax collisions, 0.04ms).",
      "[StreamSyncer] Broadcasted converged delta packet [42 bytes] to 3 peers.",
    ]);

    setTimeout(() => {
      setSimulatedConflictResolved(false);
    }, 4000);
  };

  const handleRunAgentOptimize = () => {
    setAgentPassCount((prev) => prev + 1);
    setTerminalLogs((prev) => [
      ...prev.slice(-6),
      `[@CruxAI] Initiated AST tree optimization pass #${agentPassCount + 1}...`,
      "[@CruxAI] CAMetalLayer text quad batch coalesced: 12,400 glyphs -> 1 draw call.",
      "[@CruxAI] Verified zero-copy memory safety via rustc --check (0 warnings).",
    ]);
  };

  return (
    <div
      className="relative mx-auto max-w-6xl mt-12 text-left"
      style={{
        fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
      }}
    >
      {/* Brutalist Window Frame */}
      <div className="rounded-none border border-[#222222] bg-[#000000] overflow-hidden">
        {/* ========================================================================= */}
        {/* WINDOW CHROME & TOP APPLICATION HEADER                                   */}
        {/* ========================================================================= */}
        <div className="px-4 py-2 bg-[#111111] border-b border-[#222222] flex flex-wrap items-center justify-between gap-3 select-none">
          {/* Left: Crux Wordmark & Host Architecture Tag */}
          <div className="flex items-center gap-3">
            <CruxBrandLogo size={14} withText={true} />
            <span className="text-[#444444]">|</span>
            <span className="text-[11px] font-mono text-[#888888] flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-white rounded-none" />
              <span>STUDIO v0.1.0-alpha</span>
              <span className="text-[#444444] hidden sm:inline">[MACH-O aarch64 / Metal 3]</span>
            </span>
          </div>

          {/* Center: Live Collaboration Telemetry Badges */}
          <div className="flex items-center gap-2 text-[10px] font-mono">
            <div className="px-2 py-0.5 bg-[#000000] border border-[#222222] text-white flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-white animate-pulse" />
              <span>P2P MESH: 3 PEERS</span>
            </div>
            <div className="px-2 py-0.5 bg-[#000000] border border-[#222222] text-[#888888] hidden md:flex items-center gap-1">
              <span>SYNC:</span>
              <strong className="text-white">0.08ms AST-CRDT</strong>
            </div>
            <div className="px-2 py-0.5 bg-[#000000] border border-[#222222] text-[#888888] hidden sm:flex items-center gap-1">
              <span>LATENCY:</span>
              <strong className="text-white">4.2ms</strong>
            </div>
          </div>

          {/* Right: Quick Action Controls */}
          <div className="flex items-center gap-2">
            {onLaunchWebEditor && (
              <button
                type="button"
                onClick={onLaunchWebEditor}
                className="px-2.5 py-1 bg-white hover:bg-[#CCCCCC] text-black text-[11px] font-mono font-bold uppercase transition-none flex items-center gap-1.5 cursor-pointer rounded-none"
              >
                <span>Try In Browser</span>
                <ExternalLink className="w-3 h-3 text-black" />
              </button>
            )}
            {onOpenWaitlist && (
              <button
                type="button"
                onClick={onOpenWaitlist}
                className="px-2.5 py-1 bg-transparent hover:bg-white hover:text-black text-white border border-[#222222] hover:border-white text-[11px] font-mono uppercase transition-none cursor-pointer rounded-none"
              >
                <span>Request Seat</span>
              </button>
            )}
          </div>
        </div>

        {/* ========================================================================= */}
        {/* INTERACTIVE WORKSPACE TRI-PANE VIEWPORT                                  */}
        {/* ========================================================================= */}
        <div className="grid grid-cols-12 min-h-[460px] text-xs">
          {/* ======================================================================= */}
          {/* LEFT PANE: EXPLORER & ACTIVE COLLABORATORS DRAWER                       */}
          {/* ======================================================================= */}
          <div className="hidden md:block col-span-3 border-r border-[#222222] bg-[#000000] p-3 font-mono text-[#888888] space-y-4">
            {/* Project / Workspace Meta */}
            <div>
              <div className="text-[10px] font-bold uppercase tracking-wider text-[#444444] pb-2 flex items-center justify-between border-b border-[#222222]">
                <span>WORKSPACE</span>
                <span className="text-white">[CRUX-CORE]</span>
              </div>
              <div className="pt-2 space-y-1">
                {[
                  { name: "ring_buffer.rs", active: activeFile === "ring_buffer.rs" },
                  { name: "ast_crdt.rs", active: activeFile === "ast_crdt.rs" },
                  { name: "render_quad.metal", active: activeFile === "render_quad.metal" },
                ].map((f) => (
                  <button
                    key={f.name}
                    type="button"
                    onClick={() => setActiveFile(f.name)}
                    className={`w-full flex items-center gap-2 py-1.5 px-2 text-left transition-none cursor-pointer rounded-none ${
                      f.active
                        ? "bg-[#111111] text-white border border-[#222222] font-semibold"
                        : "text-[#888888] hover:text-white border border-transparent hover:border-[#222222]"
                    }`}
                  >
                    <FileCode2 className={`w-3.5 h-3.5 ${f.active ? "text-white" : "text-[#444444]"}`} />
                    <span className="truncate">{f.name}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Active Collaborative Peers Roster */}
            <div>
              <div className="text-[10px] font-bold uppercase tracking-wider text-[#444444] pb-2 flex items-center justify-between border-b border-[#222222]">
                <span>CONNECTED PEERS</span>
                <span className="text-white">[3 LIVE]</span>
              </div>
              <div className="pt-2 space-y-1.5 text-[11px]">
                {/* Local user */}
                <div className="p-2 bg-[#111111] border border-[#222222] text-white space-y-0.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 bg-white" />
                      <span>[YOU] Local Host</span>
                    </span>
                    <span className="text-[#888888] text-[10px]">0.00ms</span>
                  </div>
                  <div className="text-[10px] text-[#444444]">Active Cursor · Line 10</div>
                </div>

                {/* Tarika K. */}
                <div className="p-2 bg-[#090909] border border-[#222222] text-white space-y-0.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 bg-white animate-pulse" />
                      <span>[TARIKA K.]</span>
                    </span>
                    <span className="text-[#888888] text-[10px]">0.42ms</span>
                  </div>
                  <div className="text-[10px] text-[#888888] flex items-center justify-between">
                    <span>Tokyo Node</span>
                    <span className="text-white font-mono">Line 12</span>
                  </div>
                </div>

                {/* Pavan R. */}
                <div className="p-2 bg-[#090909] border border-[#222222] text-white space-y-0.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 bg-white animate-pulse" />
                      <span>[PAVAN R.]</span>
                    </span>
                    <span className="text-[#888888] text-[10px]">0.61ms</span>
                  </div>
                  <div className="text-[10px] text-[#888888] flex items-center justify-between">
                    <span>SF Edge</span>
                    <span className="text-white font-mono">Line 16</span>
                  </div>
                </div>

                {/* Local @CruxAI Worker */}
                <div className="p-2 bg-[#090909] border border-[#222222] text-white space-y-0.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 bg-white" />
                      <span>[@CruxAI]</span>
                    </span>
                    <span className="text-[#888888] text-[10px]">Host</span>
                  </div>
                  <div className="text-[10px] text-[#444444]">AST Structural Linter</div>
                </div>
              </div>
            </div>

            {/* Live Interactive Action Buttons */}
            <div className="pt-2 border-t border-[#222222] space-y-2">
              <button
                type="button"
                onClick={handleTriggerConflictTest}
                className="w-full py-1.5 px-2 bg-[#111111] hover:bg-white hover:text-black border border-[#222222] hover:border-white text-white text-[11px] font-mono uppercase transition-none cursor-pointer flex items-center justify-center gap-1.5"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Simulate Conflict</span>
              </button>
              <button
                type="button"
                onClick={handleRunAgentOptimize}
                className="w-full py-1.5 px-2 bg-[#111111] hover:bg-white hover:text-black border border-[#222222] hover:border-white text-white text-[11px] font-mono uppercase transition-none cursor-pointer flex items-center justify-center gap-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Run @CruxAI Pass</span>
              </button>
            </div>
          </div>

          {/* ======================================================================= */}
          {/* CENTER & RIGHT PANE: ZENITH CODE EDITOR WITH LIVE PEER CURSORS          */}
          {/* ======================================================================= */}
          <div className="col-span-12 md:col-span-9 bg-[#000000] flex flex-col justify-between">
            {/* Editor Tab Strip */}
            <div className="h-8 bg-[#111111] border-b border-[#222222] flex items-center justify-between px-3 select-none">
              <div className="flex items-center h-full">
                <div className="h-full px-4 border-r border-[#222222] bg-[#000000] border-t-2 border-t-white text-white text-[11px] font-mono uppercase flex items-center gap-2">
                  <span className="w-1.5 h-1.5 bg-white" />
                  <span>{activeFile}</span>
                </div>
                <div className="h-full px-4 border-r border-[#222222] text-[#444444] hover:text-white text-[11px] font-mono uppercase flex items-center gap-2 cursor-pointer transition-none">
                  <span>ast_vector.rs</span>
                </div>
              </div>

              {/* Simulation Status / Conflict Pill */}
              <div className="flex items-center gap-2">
                {simulatedConflictResolved && (
                  <div className="px-2 py-0.5 bg-white text-black text-[10px] font-mono font-bold uppercase animate-pulse flex items-center gap-1">
                    <Check className="w-3 h-3 text-black stroke-[3]" />
                    <span>0 CONFLICTS · AUTO CONVERGED</span>
                  </div>
                )}
                <div className="hidden sm:flex items-center gap-2 text-[10px] font-mono text-[#888888]">
                  <span>AST SYNC:</span>
                  <span className="text-white font-bold">120 FPS STABLE</span>
                </div>
              </div>
            </div>

            {/* Code Canvas & Live Multiplayer Cursors Area */}
            <div className="relative flex-1 p-3 overflow-hidden font-mono text-[12px] leading-relaxed bg-[#000000]">
              {/* Hardware Brutalist Subtle Grid Watermark */}
              <div className="absolute inset-0 opacity-[0.02] bg-[linear-gradient(to_right,#ffffff_1px,transparent_1px),linear-gradient(to_bottom,#ffffff_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />

              {/* =================================================================== */}
              {/* LIVE PEER CURSOR 1: [TARIKA K.] [LIVE]                             */}
              {/* =================================================================== */}
              <div
                className="absolute pointer-events-none z-30 select-none flex items-start"
                style={{
                  transform: `translate3d(${tarikaPos.x}px, ${tarikaPos.y}px, 0)`,
                  transition: "transform 0.4s cubic-bezier(0.16, 1, 0.3, 1)",
                }}
              >
                {/* 1.4px Pure White Outlined Precision Dart */}
                <svg width="18" height="20" viewBox="0 0 16 16" fill="currentColor" className="text-white">
                  <path d="M0 0L6 14L8.5 8.5L14 6L0 0Z" fill="#FFFFFF" stroke="#000000" strokeWidth="1" />
                </svg>
                {/* Hardware Brutalist Peer Name Tag */}
                <div className="ml-1 px-1.5 py-0.5 bg-[#000000] border border-white text-[10px] font-mono font-bold text-white flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 bg-white animate-pulse" />
                  <span>[TARIKA K.]</span>
                  <span className="text-[#888888]">[LIVE]</span>
                </div>
              </div>

              {/* =================================================================== */}
              {/* LIVE PEER CURSOR 2: [PAVAN R.] [LIVE]                              */}
              {/* =================================================================== */}
              <div
                className="absolute pointer-events-none z-30 select-none flex items-start"
                style={{
                  transform: `translate3d(${pavanPos.x}px, ${pavanPos.y}px, 0)`,
                  transition: "transform 0.45s cubic-bezier(0.16, 1, 0.3, 1)",
                }}
              >
                {/* 1.4px Pure White Outlined Precision Dart */}
                <svg width="18" height="20" viewBox="0 0 16 16" fill="currentColor" className="text-white">
                  <path d="M0 0L6 14L8.5 8.5L14 6L0 0Z" fill="#FFFFFF" stroke="#000000" strokeWidth="1" />
                </svg>
                {/* Hardware Brutalist Peer Name Tag */}
                <div className="ml-1 px-1.5 py-0.5 bg-[#000000] border border-white text-[10px] font-mono font-bold text-white flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 bg-white animate-pulse" />
                  <span>[PAVAN R.]</span>
                  <span className="text-[#888888]">[LIVE]</span>
                </div>
              </div>

              {/* Real Code Lines with Line Gutter */}
              <div className="relative z-10 space-y-0.5">
                {INITIAL_CODE_LINES.map((line) => {
                  const isTarikaLine = line.num === "12";
                  const isPavanLine = line.num === "16";

                  return (
                    <div
                      key={line.num}
                      className={`flex items-center text-left ${
                        isTarikaLine
                          ? "bg-[#111111] border-l-2 border-white pl-1"
                          : isPavanLine
                          ? "bg-[#111111] border-l-2 border-white pl-1"
                          : "pl-1.5"
                      }`}
                    >
                      {/* Line Number Gutter (Strictly 1px divider and #444444 font) */}
                      <span className="w-8 shrink-0 text-right pr-3 text-[#444444] select-none text-[11px]">
                        {line.num}
                      </span>

                      {/* Code Content */}
                      <div className="flex-1 overflow-x-auto whitespace-pre font-mono">
                        {line.indent > 0 && <span>{" ".repeat(line.indent)}</span>}
                        {line.tag === "comment" ? (
                          <span className="text-[#555555]">{line.text.trim()}</span>
                        ) : line.tag === "import" ? (
                          <span className="text-[#888888]">{line.text.trim()}</span>
                        ) : isTarikaLine ? (
                          <span className="text-white font-medium">
                            {line.text.trim()}{" "}
                            <span className="text-[10px] text-[#888888] font-normal italic">
                              {"// [TARIKA K. selected AST patch]"}
                            </span>
                          </span>
                        ) : isPavanLine ? (
                          <span className="text-white font-medium">
                            {line.text.trim()}{" "}
                            <span className="text-[10px] text-[#888888] font-normal italic">
                              {"// [PAVAN R. committed AST delta]"}
                            </span>
                          </span>
                        ) : (
                          <span className="text-white">{line.text.trim()}</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* ===================================================================== */}
            {/* HYPERTERMINAL: POSIX PTY STREAM & @CruxAI EXECUTION STREAM             */}
            {/* ===================================================================== */}
            <div className="border-t border-[#222222] bg-[#000000]">
              {/* Terminal Titlebar */}
              <div className="h-7 bg-[#111111] border-b border-[#222222] px-3 flex items-center justify-between text-[11px] font-mono select-none">
                <div className="flex items-center gap-3">
                  <span className="text-white font-bold flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-white" />
                    <span>HYPERTERMINAL</span>
                  </span>
                  <span className="text-[#444444]">|</span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setActiveTerminalTab("stdout")}
                      className={`px-2 py-0.5 text-[10px] transition-none cursor-pointer ${
                        activeTerminalTab === "stdout"
                          ? "bg-white text-black font-bold"
                          : "text-[#888888] hover:text-white"
                      }`}
                    >
                      [STDOUT]
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTerminalTab("agent")}
                      className={`px-2 py-0.5 text-[10px] transition-none cursor-pointer ${
                        activeTerminalTab === "agent"
                          ? "bg-white text-black font-bold"
                          : "text-[#888888] hover:text-white"
                      }`}
                    >
                      [@CruxAI]
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTerminalTab("ipc")}
                      className={`px-2 py-0.5 text-[10px] transition-none cursor-pointer ${
                        activeTerminalTab === "ipc"
                          ? "bg-white text-black font-bold"
                          : "text-[#888888] hover:text-white"
                      }`}
                    >
                      [IPC SOCKET]
                    </button>
                  </div>
                </div>

                <div className="hidden sm:flex items-center gap-2 text-[10px] text-[#888888]">
                  <span>IPC: unix:///var/run/crux-7447.sock</span>
                  <span className="w-1.5 h-1.5 bg-white" />
                </div>
              </div>

              {/* Terminal Output Log Stream */}
              <div className="p-3 font-mono text-[11.5px] leading-relaxed space-y-1 max-h-36 overflow-y-auto bg-[#000000] text-white">
                {terminalLogs.map((log, idx) => (
                  <div key={idx} className="flex items-start gap-2">
                    <span className="text-[#444444] select-none text-[10px]">&gt;</span>
                    {log.startsWith("[@CruxAI]") ? (
                      <span className="text-white font-bold pl-1">{log}</span>
                    ) : log.startsWith("[CRDT-EVENT]") ? (
                      <span className="text-white pl-1">{log}</span>
                    ) : log.startsWith("crux-sh:") ? (
                      <span className="text-[#888888] font-bold">{log}</span>
                    ) : (
                      <span className="text-[#888888]">{log}</span>
                    )}
                  </div>
                ))}
                {/* Mechanical Blinking Cursor */}
                <div className="flex items-center gap-1 text-white pt-1">
                  <span className="text-[#888888]">crux-sh:~/crux-core$</span>
                  <span className="inline-block w-2 h-3.5 bg-white animate-pulse" />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* BOTTOM METRICS STATUS BAR                                                */}
        {/* ========================================================================= */}
        <div className="px-4 py-2 bg-[#111111] border-t border-[#222222] flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono text-[#888888] select-none">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5 text-white">
              <Check className="w-3.5 h-3.5 text-white stroke-[3]" />
              <span>CRDT AST MESH: ZERO LOCKS · CONVERGED</span>
            </span>
            <span className="hidden sm:inline text-[#444444]">|</span>
            <span className="hidden sm:inline">
              ENCRYPTION: <strong className="text-white">ED25519 P2P WEBRTC</strong>
            </span>
          </div>

          <div className="flex items-center gap-3">
            <span>MEM: 38.4 MB</span>
            <span className="text-[#444444]">/</span>
            <span>DOM OVERHEAD: 0.00ms</span>
            <span className="text-[#444444]">/</span>
            <span className="text-white font-bold">120 FPS</span>
          </div>
        </div>
      </div>
    </div>
  );
}
