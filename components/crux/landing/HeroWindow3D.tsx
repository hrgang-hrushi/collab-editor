"use client";

import React, { useState, useEffect } from "react";
import {
  Zap,
  Sliders,
  Terminal,
  Cpu,
  Copy,
  Check,
  FileCode2,
  FolderOpen,
  ArrowRight,
  Bot,
  Activity,
  Layers,
  ChevronRight,
} from "lucide-react";
import CruxBrandLogo from "../CruxBrandLogo";

export default function HeroWindow3D() {
  const [activeTab, setActiveTab] = useState<"webgpu" | "migration" | "agent">("webgpu");
  const [frameTime, setFrameTime] = useState(8.4);
  const [fps, setFps] = useState(120);
  const [migrationStep, setMigrationStep] = useState<"ready" | "scanning" | "imported">("ready");

  // Dynamic live GPU frame time simulator
  useEffect(() => {
    const interval = setInterval(() => {
      // Oscillate naturally between 7.8ms and 9.2ms
      setFrameTime(+(8.1 + Math.sin(Date.now() / 800) * 0.7).toFixed(1));
      setFps(Math.round(119 + Math.random() * 2));
    }, 1200);
    return () => clearInterval(interval);
  }, []);

  const handleSimulateMigration = () => {
    setMigrationStep("scanning");
    setTimeout(() => {
      setMigrationStep("imported");
    }, 1400);
  };

  return (
    <div className="relative mx-auto max-w-5xl mt-12 text-left">
      {/* 3D Hardware Window Shell */}
      <div
        className="rounded-none border border-[#222222] bg-[#000000] overflow-hidden transition-none"
        style={{
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
        }}
      >
        {/* Titlebar with Crux Logo & Tab Switcher */}
        <div className="px-4 py-2.5 bg-[#111111] border-b border-[#222222] flex flex-wrap items-center justify-between gap-3 select-none">
          {/* Crux Official Logo & Studio Version */}
          <div className="flex items-center gap-3">
            <CruxBrandLogo size={14} />
            <span className="text-xs font-mono font-bold text-white tracking-tight flex items-center gap-2">
              <span>Crux Studio</span>
              <span className="text-[#444444]">/</span>
              <span className="text-[#888888] font-normal">native-metal-v3</span>
            </span>
          </div>

          {/* Center: Live-Updating Interactive View Switcher */}
          <div className="flex items-center bg-[#000000] border border-[#222222] text-xs font-mono">
            <button
              onClick={() => setActiveTab("webgpu")}
              className={`flex items-center gap-1.5 px-3 py-1 font-mono transition-none cursor-pointer rounded-none ${
                activeTab === "webgpu"
                  ? "bg-white text-black font-bold border-r border-[#222222]"
                  : "text-[#888888] hover:text-white border-r border-[#222222]"
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              <span>WebGPU Viewport</span>
            </button>
            <button
              onClick={() => setActiveTab("migration")}
              className={`flex items-center gap-1.5 px-3 py-1 font-mono transition-none cursor-pointer rounded-none ${
                activeTab === "migration"
                  ? "bg-white text-black font-bold border-r border-[#222222]"
                  : "text-[#888888] hover:text-white border-r border-[#222222]"
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>1-Click Migration</span>
            </button>
            <button
              onClick={() => setActiveTab("agent")}
              className={`flex items-center gap-1.5 px-3 py-1 font-mono transition-none cursor-pointer rounded-none ${
                activeTab === "agent"
                  ? "bg-white text-black font-bold"
                  : "text-[#888888] hover:text-white"
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Agentic Terminal</span>
            </button>
          </div>

          {/* Right Status Badge */}
          <div className="hidden sm:flex items-center gap-2 text-[11px] font-mono">
            <span className="px-2 py-0.5 rounded-none bg-[#000000] border border-[#222222] text-white">
              {frameTime} ms / {fps} FPS
            </span>
            <span className="px-2 py-0.5 rounded-none bg-[#000000] border border-[#222222] text-[#888888]">
              Rust AST-CRDT
            </span>
          </div>
        </div>

        {/* Tab 1: WebGPU Viewport */}
        {activeTab === "webgpu" && (
          <div className="grid grid-cols-12 min-h-[440px] text-xs">
            {/* Sidebar / AST Node Inspector */}
            <div className="hidden md:block col-span-3 border-r border-[#222222] bg-[#000000] p-4 font-mono text-[#888888] space-y-3">
              <div className="text-[10px] font-bold uppercase tracking-wider text-[#444444] flex items-center justify-between">
                <span>GPU RENDER TREE</span>
                <span className="text-white">HARDWARE V3</span>
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2 py-1 px-2 rounded-none bg-[#111111] text-white font-medium border border-[#222222]">
                  <FileCode2 className="w-3.5 h-3.5 text-white" />
                  <span>render_quad.metal</span>
                </div>
                <div className="flex items-center gap-2 py-1 px-2 hover:text-white cursor-pointer transition-none">
                  <FileCode2 className="w-3.5 h-3.5 text-[#444444]" />
                  <span>glyph_cache.rs</span>
                </div>
                <div className="flex items-center gap-2 py-1 px-2 hover:text-white cursor-pointer transition-none">
                  <FileCode2 className="w-3.5 h-3.5 text-[#444444]" />
                  <span>ast_crdt_delta.rs</span>
                </div>
              </div>

              {/* Hardware Telemetry Card */}
              <div className="pt-4 border-t border-[#222222] space-y-2 text-[11px]">
                <div className="text-[10px] uppercase font-bold text-[#444444]">
                  Active Surface Metrics
                </div>
                <div className="flex justify-between py-1 border-b border-[#222222]">
                  <span className="text-[#888888]">Render Pipeline</span>
                  <span className="text-white font-bold">Metal 3 Direct</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#222222]">
                  <span className="text-[#888888]">DOM Overhead</span>
                  <span className="text-white font-bold">0.00 ms (Bypassed)</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-[#888888]">Buffer VRAM</span>
                  <span className="text-white font-mono">38.4 MB</span>
                </div>
              </div>
            </div>

            {/* Code & Shader Canvas Pane */}
            <div className="col-span-12 md:col-span-9 bg-[#000000] p-6 font-mono flex flex-col justify-between">
              <div className="space-y-1.5 leading-relaxed text-white">
                <div className="text-[#444444] flex items-center justify-between pb-2 border-b border-[#222222]">
                  <span>{"// Direct GPU-accelerated text & spatial rasterization pipeline"}</span>
                  <span className="text-white text-[10px]">[SUB-15MS LATENCY ACTIVE]</span>
                </div>
                <div className="pt-2 text-[#888888]">
                  <span>#[inline(always)]</span>
                </div>
                <div>
                  <span className="text-[#888888]">pub fn</span>{" "}
                  <span className="text-white font-bold">render_metal_frame_sub15ms</span>
                  (viewport: &amp;
                  <span className="text-white">WebGpuViewport</span>, encoder: &amp;mut{" "}
                  <span className="text-white">RenderPassEncoder</span>) -&gt;{" "}
                  <span className="text-white">Result</span>&lt;FrameMetrics, RenderError&gt; &#123;
                </div>
                <div className="pl-4 text-[#888888]">
                  <span>let</span> ast_tokens = viewport.
                  <span className="text-white">fetch_crdt_dirty_glyphs</span>()?;
                </div>
                <div className="pl-4 text-[#888888]">
                  <span>let</span> texture_drawable = viewport.
                  <span className="text-white">next_cametal_drawable</span>().
                  <span>expect</span>(
                  <span className="text-[#888888]">"Zero-copy frame surface"</span>);
                </div>
                <div className="pl-4 text-[#444444]">
                  {"// Instanced vertex rasterization renders 250,000 glyphs at 120 FPS"}
                </div>
                <div className="pl-4 text-white">
                  encoder.draw_instanced_primitives(
                  <span className="text-[#888888]">PrimitiveType::TriangleStrip</span>,
                  ast_tokens.len(),
                  texture_drawable
                  );
                </div>
                <div className="pl-4 text-[#888888]">
                  <span className="text-white">Ok</span>(FrameMetrics &#123; latency_ms:{" "}
                  <span className="text-white font-bold">{frameTime}</span>, target_fps:{" "}
                  <span className="text-white font-bold">120</span> &#125;)
                </div>
                <div>&#125;</div>
              </div>

              {/* Bottom HUD Bar */}
              <div className="mt-8 pt-4 border-t border-[#222222] flex flex-wrap items-center justify-between gap-4 text-[11px] text-[#888888]">
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1.5 text-white font-medium">
                    <Check className="w-3.5 h-3.5 text-white" />
                    <span>GPU Text Cache Warm</span>
                  </span>
                  <div className="w-[1px] h-3 bg-[#222222]" />
                  <span>Input-to-Photon: 4.2ms</span>
                </div>
                <div className="flex items-center gap-2 text-[#888888] font-mono">
                  <span>CRDT Peers: 4 Live</span>
                  <div className="w-[1px] h-3 bg-[#222222]" />
                  <span>Sync Delta: &lt;1ms</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Universal Migration Engine */}
        {activeTab === "migration" && (
          <div className="p-6 sm:p-8 bg-[#000000] min-h-[440px] flex flex-col justify-between font-mono">
            <div className="space-y-6">
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="text-base font-bold text-white flex items-center gap-2">
                    <Sliders className="w-4 h-4 text-white" />
                    <span>Universal Configuration &amp; Extension Importer</span>
                  </h4>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Auto-detects host machine configurations for VS Code, Cursor, and Windsurf in a single scan.
                  </p>
                </div>
                <span className="px-2.5 py-1 rounded-none bg-[#111111] border border-[#222222] text-white text-xs font-mono">
                  scan_existing_ides()
                </span>
              </div>

              {/* Detected IDE Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 rounded-none bg-[#111111] border border-[#222222] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-xs">Cursor IDE</span>
                    <span className="text-[10px] font-mono text-black bg-white px-2 py-0.5 rounded-none font-bold">
                      DETECTED
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-[#888888] truncate">
                    ~/Library/Application Support/Cursor/User
                  </div>
                  <div className="flex flex-wrap gap-1.5 pt-2">
                    <span className="text-[10px] px-2 py-0.5 rounded-none bg-[#000000] border border-[#222222] text-[#888888]">
                      keybindings.json (48 keys)
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-none bg-[#000000] border border-[#222222] text-white">
                      .cursorrules (Active)
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-none bg-[#111111] border border-[#222222] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-xs">Visual Studio Code</span>
                    <span className="text-[10px] font-mono text-black bg-white px-2 py-0.5 rounded-none font-bold">
                      DETECTED
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-[#888888] truncate">
                    ~/Library/Application Support/Code/User
                  </div>
                  <div className="flex flex-wrap gap-1.5 pt-2">
                    <span className="text-[10px] px-2 py-0.5 rounded-none bg-[#000000] border border-[#222222] text-[#888888]">
                      settings.json
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-none bg-[#000000] border border-[#222222] text-[#888888]">
                      12 Extensions
                    </span>
                  </div>
                </div>
              </div>

              {/* Progress Feedback Display */}
              {migrationStep === "scanning" && (
                <div className="p-4 rounded-none bg-[#111111] border border-[#222222] flex items-center gap-3 text-xs text-white font-mono animate-pulse">
                  <span className="w-2 h-2 bg-white" />
                  <span>Parsing AST grammars, re-mapping keybindings, and importing agent prompts...</span>
                </div>
              )}

              {migrationStep === "imported" && (
                <div className="p-4 rounded-none bg-[#111111] border border-white flex items-center justify-between text-xs text-white font-mono">
                  <span className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-white" />
                    <span>Workspace profile imported successfully! Zero shortcut muscle-memory lost.</span>
                  </span>
                  <span className="text-[#888888]">Duration: 142ms</span>
                </div>
              )}
            </div>

            <div className="pt-6 border-t border-[#222222] flex items-center justify-between">
              <span className="text-xs text-[#888888] font-mono">
                Preserves Vim, VS Code, and Emacs keymaps instantly
              </span>
              <button
                onClick={handleSimulateMigration}
                disabled={migrationStep === "scanning"}
                className="px-4 py-2 rounded-none bg-white hover:bg-[#111111] hover:text-white border border-white text-black font-bold text-xs uppercase tracking-wider transition-none flex items-center gap-2 cursor-pointer disabled:opacity-50"
              >
                <span>{migrationStep === "imported" ? "Re-Run Migration Scan" : "Simulate 1-Click Import"}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Tab 3: Agentic Terminal Sandbox */}
        {activeTab === "agent" && (
          <div className="p-6 bg-[#000000] min-h-[440px] font-mono text-xs flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-[#222222]">
                <div className="flex items-center gap-2 text-white">
                  <Bot className="w-4 h-4 text-white" />
                  <span className="font-bold text-white">Crux Autonomous Agent Daemon</span>
                  <span className="text-[10px] text-[#888888]">(Local Subprocess #4812)</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-white" />
                  <span className="text-[11px] text-white">[ONLINE &amp; LISTENING]</span>
                </div>
              </div>

              {/* Simulated Terminal Shell Session */}
              <div className="space-y-2.5 leading-relaxed text-white">
                <div className="text-[#888888]">
                  $ crux agent --mode=autonomous --target=src/compiler/crdt.rs
                </div>
                <div className="text-white font-semibold">
                  [@CruxAI] Local engine initialized via Metal unified memory (M3 Max).
                </div>
                <div className="text-[#888888] pl-3 border-l border-[#222222] space-y-1">
                  <div className="flex items-center gap-1.5">
                    <ChevronRight className="w-3 h-3 text-white" />
                    <span>Analyzing 1,420 AST lines for concurrent CRDT buffer conflicts...</span>
                  </div>
                  <div className="text-white flex items-center gap-1.5">
                    <Check className="w-3 h-3 stroke-[3]" />
                    <span>Detected 0 race hazards in decentralized vector clock</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <ChevronRight className="w-3 h-3 text-white" />
                    <span>Optimizing instanced GPU text quads: 120 FPS continuous pipeline verified</span>
                  </div>
                  <div className="text-white font-bold flex items-center gap-1.5">
                    <ChevronRight className="w-3 h-3 text-white" />
                    <span>Executing shell test suite: `cargo test --release --lib`</span>
                  </div>
                </div>
                <div className="text-white bg-[#111111] p-2.5 rounded-none border border-[#222222] flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <Check className="w-3.5 h-3.5 text-white" />
                    <span>test result: ok. 48 passed; 0 failed; 0 ignored; finished in 0.08s</span>
                  </span>
                  <span className="text-[10px] text-white font-mono font-bold bg-[#000000] border border-[#222222] px-2 py-0.5">
                    100% PASS
                  </span>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-[#222222] flex items-center justify-between text-[#888888] text-[11px]">
              <span className="flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-white" />
                <span>Zero-latency native shell execution without Electron sandboxing</span>
              </span>
              <span className="text-white">Token Speed: 148 tok/s (Local)</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
