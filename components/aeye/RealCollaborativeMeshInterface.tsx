"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import {
  Terminal,
  Play,
  Share2,
  FolderPlus,
  FolderDown,
  Search,
  Plus,
  Download,
  FileCode2,
  Check,
  Zap,
  Cpu,
  Layers,
  Sparkles,
  GitBranch,
} from "lucide-react";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

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

interface CodeLine {
  num: number;
  text: string;
  tag?: "comment" | "keyword" | "code" | "active" | "peer";
}

const FILES_DATA: Record<string, { lang: string; lines: CodeLine[] }> = {
  "main.rs": {
    lang: "Rust",
    lines: [
      { num: 1, text: "// Crux Bare-Metal Silicon Engine · Native Mach-O Runtime", tag: "comment" },
      { num: 2, text: "use crux_core::crdt::{ASTVectorTree, ConflictFreeResolver, NodeId};", tag: "code" },
      { num: 3, text: "use crux_gpu::metal::{CAMetalDrawable, QuadShaderPipeline};", tag: "code" },
      { num: 4, text: "", tag: "code" },
      { num: 5, text: "#[inline(always)]", tag: "comment" },
      { num: 6, text: "pub async fn synchronize_collaborative_ring(", tag: "keyword" },
      { num: 7, text: "    local_tree: &mut ASTVectorTree,", tag: "code" },
      { num: 8, text: "    remote_delta: &[u8],", tag: "code" },
      { num: 9, text: "    peer_token: NodeId,", tag: "code" },
      { num: 10, text: ") -> Result<CRDTSyncMetrics, KernelPanic> {", tag: "keyword" },
      { num: 11, text: "    // Zero-copy deserialization directly from POSIX shm ring", tag: "comment" },
      { num: 12, text: "    let mutation = ConflictFreeResolver::parse_ast_patch(remote_delta)?;", tag: "peer" },
      { num: 13, text: "    let convergence_instant = std::time::Instant::now();", tag: "code" },
      { num: 14, text: "    let commit_hash = local_tree.merge_deterministic(&mutation, peer_token)?;", tag: "active" },
      { num: 15, text: "    crux_gpu::invalidate_dirty_quads(local_tree.dirty_range());", tag: "code" },
      { num: 16, text: "    Ok(CRDTSyncMetrics { latency_us: 42, conflicts: 0 })", tag: "code" },
      { num: 17, text: "}", tag: "code" },
    ],
  },
  "crdt.rs": {
    lang: "Rust",
    lines: [
      { num: 1, text: "// AST-CRDT Structural Convergence Engine", tag: "comment" },
      { num: 2, text: "pub struct ASTVectorTree {", tag: "keyword" },
      { num: 3, text: "    nodes: BTreeMap<NodeId, ASTNode>,", tag: "code" },
      { num: 4, text: "    vector_clock: AtomicU64,", tag: "code" },
      { num: 5, text: "}", tag: "code" },
      { num: 6, text: "", tag: "code" },
      { num: 7, text: "impl ASTVectorTree {", tag: "keyword" },
      { num: 8, text: "    pub fn merge_deterministic(&mut self, patch: &ASTPatch, node: NodeId) -> Result<u64> {", tag: "keyword" },
      { num: 9, text: "        let lamport_epoch = self.vector_clock.fetch_add(1, Ordering::SeqCst);", tag: "peer" },
      { num: 10, text: "        self.apply_atomic_token(patch.target_token(), lamport_epoch);", tag: "active" },
      { num: 11, text: "        Ok(lamport_epoch)", tag: "code" },
      { num: 12, text: "    }", tag: "code" },
      { num: 13, text: "}", tag: "code" },
    ],
  },
  "shader.wgsl": {
    lang: "WGSL",
    lines: [
      { num: 1, text: "// WebGPU Direct Phosphor Compute Shader · 120 FPS", tag: "comment" },
      { num: 2, text: "@group(0) @binding(0) var<storage, read> glyph_quads: array<GlyphQuad>;", tag: "code" },
      { num: 3, text: "@group(0) @binding(1) var font_atlas: texture_2d<f32>;", tag: "code" },
      { num: 4, text: "", tag: "code" },
      { num: 5, text: "@compute @workgroup_size(64)", tag: "comment" },
      { num: 6, text: "fn rasterize_text_matrix(@builtin(global_invocation_id) id: vec3<u32>) {", tag: "keyword" },
      { num: 7, text: "    let glyph = glyph_quads[id.x];", tag: "peer" },
      { num: 8, text: "    let uv_coords = glyph.uv_bounds.xy + glyph.texel_step;", tag: "active" },
      { num: 9, text: "    textureStore(target_surface, id.xy, sample_atlas(uv_coords));", tag: "code" },
      { num: 10, text: "}", tag: "code" },
    ],
  },
};

export default function RealCollaborativeMeshInterface({
  mode = "multiplayer",
  className = "",
}: RealCollaborativeMeshInterfaceProps) {
  // Determine active file based on mode
  const initialFile = useMemo(() => {
    if (mode === "silicon" || mode === "output") return "shader.wgsl";
    if (mode === "crdt" || mode === "processing") return "crdt.rs";
    return "main.rs";
  }, [mode]);

  const [activeFile, setActiveFile] = useState(initialFile);
  const [activeTerminalTab, setActiveTerminalTab] = useState<"stdout" | "agent" | "metrics">("stdout");
  const [isRunning, setIsRunning] = useState(false);
  const [isCopied, setIsCopied] = useState(false);

  // Sync activeFile when mode changes externally
  useEffect(() => {
    setActiveFile(initialFile);
  }, [initialFile]);

  // Peer typing cursor state
  const [peerTypingText, setPeerTypingText] = useState("");
  const [cursorBlink, setCursorBlink] = useState(true);

  // Terminal log stream
  const [terminalLogs, setTerminalLogs] = useState<string[]>(() => {
    switch (mode) {
      case "context":
        return [
          "crux-sh:~/crux-core$ crux index --buffer-direct",
          "[@CruxAI] Ingested 64,280 AST tokens across 32 source trees in 0.08ms.",
          "[@CruxAI] Zero-copy memory map mapped to 0x7fff5fbff820 (NVMe direct).",
          "[@CruxAI] Workspace context ready. 0 index errors.",
        ];
      case "processing":
      case "crdt":
        return [
          "crux-sh:~/crux-core$ crux sync --topology=ast-mesh",
          "[@CruxAI] Active peers connected: Tokyo Node [SARAH L.], SF Edge [MARCUS V.].",
          "[@CruxAI] Concurrent AST mutation received: target_token=NodeId(42).",
          "[@CruxAI] Deterministic merge completed in 0.04ms (0 syntax collisions).",
        ];
      case "output":
      case "silicon":
        return [
          "crux-sh:~/crux-core$ cargo build --release --target=aarch64-darwin",
          "[@CruxAI] WebGPU text quad batch coalesced: 12,400 glyphs -> 1 draw call.",
          "[@CruxAI] CAMetalLayer phosphor pipeline locked at 120 FPS (8.33ms vsync).",
          "[@CruxAI] Finished release [optimized] in 140ms. 0 warnings.",
        ];
      case "agents":
        return [
          "crux-sh:~/crux-core$ @CruxAI refactor --optimize-atomic-locks",
          "[@CruxAI] Analyzing mutable references in src/crdt.rs...",
          "[@CruxAI] Suggested atomic bitset lock-free queue replacing mutex lock.",
          "[@CruxAI] Verification check passed: cargo check 0 warnings (110ms).",
        ];
      case "multiplayer":
      default:
        return [
          "crux-sh:~/crux-core$ bun run stream_syncer.ts",
          "[StreamSyncer] Mesh channel ready on origin: unix:///var/run/crux.sock",
          "[@CruxAI] Initialized AST-CRDT lock-free ring buffer (3 peers connected).",
          "[SARAH L.] Joined collaborative session (RTT: 0.28ms).",
        ];
    }
  });

  // Collaborative peer typing loop
  useEffect(() => {
    let timeout: NodeJS.Timeout;
    const targetString = " // [LIVE AST MUTATION VERIFIED]";
    let idx = 0;
    let forward = true;

    const tick = () => {
      if (forward) {
        if (idx < targetString.length) {
          idx += 1;
          setPeerTypingText(targetString.slice(0, idx));
          timeout = setTimeout(tick, 140);
        } else {
          forward = false;
          timeout = setTimeout(tick, 2400);
        }
      } else {
        if (idx > 0) {
          idx -= 1;
          setPeerTypingText(targetString.slice(0, idx));
          timeout = setTimeout(tick, 70);
        } else {
          forward = true;
          timeout = setTimeout(tick, 1200);
        }
      }
    };

    timeout = setTimeout(tick, 600);
    return () => clearTimeout(timeout);
  }, [mode, activeFile]);

  // Blink interval for brutalist solid cursor
  useEffect(() => {
    const interval = setInterval(() => {
      setCursorBlink((v) => !v);
    }, 500);
    return () => clearInterval(interval);
  }, []);

  const handleRunCode = () => {
    setIsRunning(true);
    setTerminalLogs((prev) => [
      ...prev.slice(-6),
      `crux-sh:~/crux-core$ cargo test --release --lib ${activeFile}`,
      "[@CruxAI] Executing AST-CRDT peer verification pass...",
      "[@CruxAI] CAMetalLayer text quad cache: 100% HIT RATE",
      `test ${activeFile.replace('.', '_')}::test_sync ... ok (0.04ms)`,
      "test result: ok. 1 passed; 0 failed; 0 ignored; finished in 0.08s",
    ]);
    setTimeout(() => {
      setIsRunning(false);
    }, 700);
  };

  const handleCopyLink = () => {
    if (typeof window !== "undefined") {
      navigator.clipboard?.writeText("https://codecrux.us/?session=mesh-p2p");
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 1800);
    }
  };

  const currentFile = FILES_DATA[activeFile] || FILES_DATA["main.rs"];

  return (
    <div
      className={`relative w-full h-full bg-[#000000] text-white flex flex-col select-none overflow-hidden border-0 ${className}`}
      style={{
        fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
      }}
    >
      {/* ========================================================================= */}
      {/* 1. TOP WINDOW BAR (Exact Crux Header Blueprint)                            */}
      {/* ========================================================================= */}
      <header className="h-8 px-3 border-b border-[#222222] bg-[#0c0c0c] flex items-center justify-between shrink-0 select-none z-20">
        {/* Left: Brand Wordmark + Live Telemetry Indicator */}
        <div className="flex items-center gap-2.5">
          <CruxBrandLogo size={15} withText={true} />
          <span className="text-[#333333]">|</span>
          <div className="flex items-center gap-1.5 font-mono text-[10px] text-[#888888]">
            <span className="w-1.5 h-1.5 bg-white rounded-none" />
            <span>0.08ms</span>
            <span className="text-[#444444] hidden sm:inline">· 120 FPS</span>
          </div>
        </div>

        {/* Center: Segmented Control: Editor vs Terminal */}
        <div className="flex items-center border border-[#222222] bg-[#000000]">
          <span className="px-2.5 py-0.5 text-[9px] font-mono uppercase tracking-wider bg-white text-black font-bold">
            EDITOR
          </span>
          <span className="px-2.5 py-0.5 text-[9px] font-mono uppercase tracking-wider text-[#71717a] hidden sm:inline">
            CANVAS
          </span>
        </div>

        {/* Right: Multiplayer Live Presence & Tactile Actions */}
        <div className="flex items-center gap-2">
          {/* Peer Tag Roster */}
          <div className="hidden sm:flex items-center gap-1 border border-[#222222] bg-[#000000] px-2 py-0.5 font-mono text-[9px]">
            <span className="text-white font-bold">[YOU]</span>
            <span className="text-[#333333]">/</span>
            <span className="text-white font-bold flex items-center gap-1">
              <span className="w-1 h-1 bg-white animate-pulse" />
              [SARAH L.]
            </span>
            <span className="text-[#333333]">/</span>
            <span className="text-[#888888]">[@CruxAI]</span>
          </div>

          {/* Run Code Action Button */}
          <button
            type="button"
            onClick={handleRunCode}
            disabled={isRunning}
            className="px-2 py-0.5 border border-[#222222] hover:border-white bg-[#000000] hover:bg-white hover:text-black text-white font-mono text-[9px] uppercase tracking-wider transition-none cursor-pointer flex items-center gap-1 font-bold"
          >
            <Play className="w-2.5 h-2.5 fill-current" />
            <span>{isRunning ? "RUNNING..." : "RUN ↵"}</span>
          </button>

          {/* Share Link Action Button */}
          <button
            type="button"
            onClick={handleCopyLink}
            className="px-2 py-0.5 border border-[#222222] hover:border-white bg-[#000000] hover:bg-white hover:text-black text-white font-mono text-[9px] uppercase tracking-wider transition-none cursor-pointer hidden md:flex items-center gap-1"
          >
            {isCopied ? <Check className="w-2.5 h-2.5" /> : <Share2 className="w-2.5 h-2.5" />}
            <span>{isCopied ? "COPIED" : "SHARE"}</span>
          </button>
        </div>
      </header>

      {/* ========================================================================= */}
      {/* 2. BREADCRUMB BAR                                                         */}
      {/* ========================================================================= */}
      <div className="h-6 px-3 border-b border-[#222222] bg-[#050505] flex items-center justify-between text-[10px] font-mono text-[#555555] shrink-0 select-none">
        <div className="flex items-center gap-1">
          <span className="text-[#444444]">WORKSPACE</span>
          <span className="text-[#333333]">/</span>
          <span className="text-[#666666]">crux-core</span>
          <span className="text-[#333333]">/</span>
          <span className="text-[#888888]">src</span>
          <span className="text-[#333333]">/</span>
          <span className="text-white font-semibold">{activeFile}</span>
        </div>
        <div className="hidden sm:flex items-center gap-3 text-[9px] text-[#71717a]">
          <span>LOCK-FREE RING BUFFER</span>
          <span className="text-[#444444]">|</span>
          <span className="text-white">0.00% COLLISION</span>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 3. MAIN WORKBENCH: FILE TREE + REAL EDITOR PANE                            */}
      {/* ========================================================================= */}
      <div className="flex-1 flex min-h-0 bg-[#000000] overflow-hidden">
        {/* Left Sidebar: Minimalist Explorer & Peer Mesh Drawer */}
        <aside className="w-40 sm:w-44 border-r border-[#222222] bg-[#000000] flex flex-col justify-between shrink-0 select-none">
          {/* Top: Explorer Files */}
          <div>
            <div className="px-2.5 py-1.5 border-b border-[#222222] text-[9px] font-mono font-bold tracking-widest text-[#888888] uppercase flex items-center justify-between">
              <span>EXPLORER</span>
              <div className="flex items-center gap-1.5 text-[#555555]">
                <Plus className="w-2.5 h-2.5 hover:text-white cursor-pointer" />
                <Download className="w-2.5 h-2.5 hover:text-white cursor-pointer" />
              </div>
            </div>

            {/* File List */}
            <div className="p-1 space-y-0.5 text-[10px] font-mono">
              <div className="text-[9px] text-[#555555] px-1.5 py-0.5 uppercase tracking-wider">
                ▼ src/
              </div>
              {Object.keys(FILES_DATA).map((fileName) => {
                const isActive = activeFile === fileName;
                return (
                  <div
                    key={fileName}
                    onClick={() => setActiveFile(fileName)}
                    className={`px-2 py-1 flex items-center justify-between transition-none cursor-pointer rounded-none ${
                      isActive
                        ? "bg-[#111111] text-white border border-[#222222] font-semibold"
                        : "text-[#888888] hover:text-white border border-transparent hover:border-[#222222]"
                    }`}
                  >
                    <div className="flex items-center gap-1.5 truncate">
                      <FileCode2 className={`w-3 h-3 ${isActive ? "text-white" : "text-[#444444]"}`} />
                      <span className="truncate">{fileName}</span>
                    </div>
                    {isActive && <span className="w-1 h-1 bg-white" />}
                  </div>
                );
              })}
              <div className="px-2 py-1 text-[#555555] flex items-center gap-1.5">
                <FileCode2 className="w-3 h-3 text-[#333333]" />
                <span>Cargo.toml</span>
              </div>
            </div>
          </div>

          {/* Bottom: Active Mesh Peers Telemetry */}
          <div className="p-2 border-t border-[#222222] bg-[#050505] text-[9px] font-mono space-y-1">
            <div className="text-[#555555] font-bold uppercase tracking-wider flex items-center justify-between pb-1 border-b border-[#1a1a1a]">
              <span>PEER MESH</span>
              <span className="text-white">[3 LIVE]</span>
            </div>
            <div className="flex items-center justify-between text-[#888888]">
              <span className="text-white">[YOU] Host</span>
              <span>0.00ms</span>
            </div>
            <div className="flex items-center justify-between text-[#888888]">
              <span className="text-white">[SARAH L.]</span>
              <span>0.28ms</span>
            </div>
            <div className="flex items-center justify-between text-[#888888]">
              <span className="text-[#666666]">[@CruxAI]</span>
              <span>POSIX</span>
            </div>
          </div>
        </aside>

        {/* Right: Code Editor Canvas with Line Numbers & Real Code */}
        <main className="flex-1 bg-[#000000] flex flex-col min-w-0 overflow-hidden relative">
          {/* Tab Strip */}
          <div className="h-7 border-b border-[#222222] bg-[#0a0a0a] flex items-center justify-between px-2 shrink-0 select-none">
            <div className="flex items-center h-full">
              {Object.keys(FILES_DATA).map((fileName) => {
                const isActive = activeFile === fileName;
                return (
                  <button
                    key={fileName}
                    type="button"
                    onClick={() => setActiveFile(fileName)}
                    className={`h-full px-3 text-[10px] font-mono uppercase tracking-wider flex items-center gap-1.5 transition-none cursor-pointer border-r border-[#222222] rounded-none ${
                      isActive
                        ? "bg-[#000000] text-white font-bold border-b border-b-white"
                        : "bg-[#0a0a0a] text-[#666666] hover:text-white"
                    }`}
                  >
                    <span>{fileName}</span>
                    {isActive && <span className="w-1 h-1 bg-white inline-block" />}
                  </button>
                );
              })}
            </div>
            <div className="text-[9px] font-mono text-[#555555] hidden sm:block">
              {currentFile.lang.toUpperCase()} // WEBGPU DIRECT
            </div>
          </div>

          {/* Editor Lines Buffer */}
          <div className="flex-1 p-2 sm:p-3 overflow-y-auto font-mono text-[11px] leading-[1.65] bg-[#000000] text-white select-text">
            {currentFile.lines.map((line) => {
              const isPeerLine = line.tag === "peer";
              const isActiveLine = line.tag === "active";

              return (
                <div
                  key={line.num}
                  className={`flex items-baseline group hover:bg-[#111111] transition-none px-1 relative ${
                    isPeerLine ? "bg-[#111111]" : ""
                  }`}
                >
                  {/* Line Number Gutter */}
                  <span className="w-7 text-right text-[10px] text-[#444444] select-none pr-3 shrink-0 font-mono">
                    {line.num}
                  </span>

                  {/* Code Line Content */}
                  <span className="flex-1 whitespace-pre font-mono">
                    {line.tag === "comment" ? (
                      <span className="text-[#555555] italic">{line.text}</span>
                    ) : line.tag === "keyword" ? (
                      <span className="text-white font-bold">{line.text}</span>
                    ) : (
                      <span className="text-[#E0E0E0]">{line.text}</span>
                    )}

                    {/* Active User Cursor */}
                    {isActiveLine && (
                      <span
                        className={`inline-block w-1.5 h-3.5 bg-white ml-0.5 align-middle ${
                          cursorBlink ? "opacity-100" : "opacity-0"
                        }`}
                      />
                    )}

                    {/* Remote Peer Typing Cursor on Sarah's Line */}
                    {isPeerLine && (
                      <span className="relative inline-block ml-1">
                        <span className="text-white font-mono">{peerTypingText}</span>
                        <span className="inline-block px-1 py-0 bg-white text-black text-[8px] font-mono uppercase font-bold ml-1 align-middle select-none">
                          [SARAH L.]
                        </span>
                        <span className="inline-block w-1 h-3 bg-white ml-0.5 align-middle animate-pulse" />
                      </span>
                    )}
                  </span>
                </div>
              );
            })}
          </div>

          {/* ===================================================================== */}
          {/* 4. HYPERTERMINAL BOTTOM PANE (Pure POSIX Terminal Blueprint)           */}
          {/* ===================================================================== */}
          <div className="h-28 border-t border-[#222222] bg-[#050505] flex flex-col shrink-0">
            {/* Terminal Header */}
            <div className="h-6 px-3 bg-[#0c0c0c] border-b border-[#222222] flex items-center justify-between text-[9px] font-mono text-[#71717a] select-none">
              <div className="flex items-center gap-3">
                <span className="text-white font-bold flex items-center gap-1.5">
                  <Terminal className="w-2.5 h-2.5" />
                  <span>TERMINAL // POSIX PTY HOST</span>
                </span>
                <span className="text-[#333333]">|</span>
                <button
                  type="button"
                  onClick={() => setActiveTerminalTab("stdout")}
                  className={`uppercase transition-none cursor-pointer ${
                    activeTerminalTab === "stdout" ? "text-white font-bold" : "hover:text-white"
                  }`}
                >
                  STDOUT
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTerminalTab("agent")}
                  className={`uppercase transition-none cursor-pointer ${
                    activeTerminalTab === "agent" ? "text-white font-bold" : "hover:text-white"
                  }`}
                >
                  @CRUXAI
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTerminalTab("metrics")}
                  className={`uppercase transition-none cursor-pointer ${
                    activeTerminalTab === "metrics" ? "text-white font-bold" : "hover:text-white"
                  }`}
                >
                  TELEMETRY
                </button>
              </div>

              <div className="flex items-center gap-2">
                <span>IPC: 0.08ms</span>
                <span className="w-1.5 h-1.5 bg-white" />
              </div>
            </div>

            {/* Terminal Content Buffer */}
            <div className="flex-1 p-2 overflow-y-auto font-mono text-[10px] leading-relaxed text-[#888888] space-y-0.5 select-text bg-[#000000]">
              {terminalLogs.map((log, idx) => {
                const isCommand = log.startsWith("crux-sh:");
                const isAgent = log.includes("[@CruxAI]");
                return (
                  <div key={idx} className="flex items-baseline gap-1.5">
                    {isCommand ? (
                      <span className="text-white font-bold">{log}</span>
                    ) : isAgent ? (
                      <span>
                        <span className="text-white font-bold">[@CruxAI]</span>
                        <span className="text-[#CCCCCC]">{log.replace("[@CruxAI]", "")}</span>
                      </span>
                    ) : (
                      <span className="text-[#888888]">{log}</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </main>
      </div>

      {/* ========================================================================= */}
      {/* 5. FOOTER STATUS BAR (Exact Crux Status Bar Blueprint)                     */}
      {/* ========================================================================= */}
      <footer className="h-5 px-3 bg-[#000000] border-t border-[#222222] text-[#666666] flex items-center justify-between text-[9px] font-mono select-none shrink-0 z-20">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 text-white">
            <GitBranch className="w-2.5 h-2.5" />
            <span>main*</span>
          </div>
          <span className="text-[#333333]">|</span>
          <span className="text-white uppercase font-bold">DISK IN-SYNC</span>
          <span className="text-[#444444] hidden sm:inline">0.08ms SHM</span>
        </div>

        <div className="flex items-center gap-3 text-[#666666]">
          <span>Ln 14, Col 28</span>
          <span className="hidden sm:inline">UTF-8</span>
          <span className="uppercase text-white font-bold">{currentFile.lang}</span>
          <span className="text-white font-bold">120 FPS</span>
        </div>
      </footer>
    </div>
  );
}
