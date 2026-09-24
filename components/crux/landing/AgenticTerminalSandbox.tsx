"use client";

import React, { useState } from "react";
import { Terminal, Bot, Play, RefreshCw, Cpu, Copy, Check, Zap } from "lucide-react";
import CruxBrandLogo from "../CruxBrandLogo";

interface TerminalCommandPreset {
  id: string;
  command: string;
  title: string;
  model: string;
  logs: { text: string; type: "cmd" | "info" | "success" | "warning" | "agent"; icon?: "check" | "zap" }[];
}

const PRESETS: TerminalCommandPreset[] = [
  {
    id: "crdt-refactor",
    title: "Autonomous CRDT Vector Refactor",
    command: "crux agent --task='optimize ast vector clocks' --target=src/crdt.rs",
    model: "DeepSeek-Coder-V2 (Local GGUF)",
    logs: [
      { text: "$ crux agent --task='optimize ast vector clocks' --target=src/crdt.rs", type: "cmd" },
      { text: "[orchestrator] Attached to native Rust daemon PID #9124 via IPC socket", type: "info" },
      { text: "[@CruxAI:local] Loaded DeepSeek-Coder-V2 into Apple Silicon unified memory (142 tok/s)", type: "agent" },
      { text: "Reading 32 source nodes in src/crdt/engine.rs...", type: "info" },
      { text: "Found concurrent race risk in decentralized Lamport timestamp ordering", type: "warning" },
      { text: "Generated AST patch: Replaced Mutex with LockFreeAtomicBitset", type: "info" },
      { text: "Running verification: `cargo check --target=aarch64-apple-darwin`", type: "cmd" },
      { text: "Verification clean. 0 compile errors, 0 runtime allocations.", type: "success", icon: "check" },
      { text: "CRDT merge throughput improved by +340% (sub-1ms delta synchronization)", type: "success", icon: "zap" },
    ],
  },
  {
    id: "metal-benchmark",
    title: "WebGPU Metal Pipeline Profiling",
    command: "crux metal --profile-drawcalls --inspect-vram",
    model: "Crux Native Profiler",
    logs: [
      { text: "$ crux metal --profile-drawcalls --inspect-vram", type: "cmd" },
      { text: "[metal-v3] Initializing CAMetalLayer surface at 3456x2234 native Retina resolution", type: "info" },
      { text: "Frame render cadence: 120 FPS locked (8.1ms per frame)", type: "info" },
      { text: "Instanced quad draw calls: 1 call per 50,000 text glyphs", type: "agent" },
      { text: "GPU texture allocation: 38.2 MB / 32,768 MB Unified VRAM", type: "info" },
      { text: "Bypasses HTML DOM tree traversal: 0 layout recalculations triggered", type: "success", icon: "check" },
    ],
  },
  {
    id: "auto-migration",
    title: "Workspace Config Ingest",
    command: "crux migrate --source=cursor --preserve-rules",
    model: "Universal Migration Engine",
    logs: [
      { text: "$ crux migrate --source=cursor --preserve-rules", type: "cmd" },
      { text: "[scanner] Discovered Cursor installation at ~/Library/Application Support/Cursor", type: "info" },
      { text: "Ingesting keybindings.json (64 customized hotkeys parsed)", type: "info" },
      { text: "Extracting .cursorrules & system agent guidelines into Crux Context Hub", type: "agent" },
      { text: "Translating Dark Midnight workbench palette to Metal shader tokens", type: "info" },
      { text: "Complete in 142ms. Zero keystroke muscle memory lost.", type: "success", icon: "check" },
    ],
  },
];

export default function AgenticTerminalSandbox() {
  const [activePreset, setActivePreset] = useState<string>("crdt-refactor");
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);

  const selected = PRESETS.find((p) => p.id === activePreset) || PRESETS[0];

  const handleRunCommand = () => {
    setIsExecuting(true);
    setTimeout(() => {
      setIsExecuting(false);
    }, 800);
  };

  const copyCommand = () => {
    navigator.clipboard.writeText(selected.command);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <section id="terminal" className="py-24 px-6 max-w-6xl mx-auto border-t border-[#222222]">
      {/* Header */}
      <div className="text-center max-w-2xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-none bg-[#111111] border border-[#222222] text-white text-xs font-mono mb-4">
          <Terminal className="w-3.5 h-3.5" />
          <span>[NATIVE SUBPROCESS EXECUTION]</span>
        </div>
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-white mb-4 font-sans">
          The Agentic Terminal Sandbox.
        </h2>
        <p className="text-sm sm:text-base text-[#888888] leading-relaxed font-sans">
          Crux embeds direct OS process spawning and local AI model inference right inside the IDE runtime.
          No bloated WebViews, no sandboxed delay—pure asynchronous terminal throughput.
        </p>
      </div>

      {/* Terminal Sandbox Shell */}
      <div
        className="rounded-none border border-[#222222] bg-[#000000] overflow-hidden relative"
        style={{
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
        }}
      >
        {/* Terminal Header & Preset Buttons */}
        <div className="px-5 py-3 bg-[#111111] border-b border-[#222222] flex flex-wrap items-center justify-between gap-3 select-none">
          <div className="flex items-center gap-3">
            <CruxBrandLogo size={14} />
            <span className="text-xs font-mono text-white font-medium">
              crux-pty-session · zsh (pid #4108)
            </span>
          </div>

          {/* Preset Buttons */}
          <div className="flex items-center bg-[#000000] border border-[#222222] text-xs font-mono">
            {PRESETS.map((p, idx) => (
              <button
                key={p.id}
                onClick={() => setActivePreset(p.id)}
                className={`px-3 py-1 transition-none cursor-pointer rounded-none ${
                  idx < PRESETS.length - 1 ? "border-r border-[#222222]" : ""
                } ${
                  activePreset === p.id
                    ? "bg-white text-black font-bold"
                    : "text-[#888888] hover:text-white"
                }`}
              >
                {p.title}
              </button>
            ))}
          </div>

          {/* Model Status Tag */}
          <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-white">
            <Bot className="w-3.5 h-3.5 text-white" />
            <span>{selected.model}</span>
          </div>
        </div>

        {/* Command Bar Trigger */}
        <div className="px-6 py-3 bg-[#000000] border-b border-[#222222] flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2 text-white truncate mr-4">
            <span className="text-[#888888] font-bold">$</span>
            <span className="text-white truncate">{selected.command}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={copyCommand}
              className="p-1.5 rounded-none bg-[#111111] hover:bg-white hover:text-black border border-[#222222] text-[#888888] transition-none cursor-pointer"
              title="Copy Command"
            >
              {copiedCmd ? <Check className="w-3.5 h-3.5 text-white" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
            <button
              onClick={handleRunCommand}
              disabled={isExecuting}
              className="px-3 py-1 rounded-none bg-white hover:bg-[#111111] hover:text-white border border-white text-black font-bold text-xs uppercase tracking-wider transition-none flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              {isExecuting ? (
                <>
                  <RefreshCw className="w-3 h-3 animate-spin" />
                  <span>Streaming...</span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3 fill-current" />
                  <span>Execute</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Terminal Body Logs */}
        <div className="p-6 font-mono text-xs space-y-2 bg-[#000000] min-h-[300px]">
          {selected.logs.map((log, index) => (
            <div
              key={index}
              className={`leading-relaxed ${
                log.type === "cmd"
                  ? "text-[#888888] font-bold"
                  : log.type === "agent"
                  ? "text-white pl-3 border-l border-[#222222] font-semibold"
                  : log.type === "success"
                  ? "text-white pl-3 border-l border-[#222222] flex items-center gap-1.5"
                  : log.type === "warning"
                  ? "text-[#888888] pl-3 border-l border-[#222222]"
                  : "text-[#888888] pl-3 border-l border-[#222222]"
              }`}
            >
              {log.icon === "check" && <Check className="w-3.5 h-3.5 text-white shrink-0" />}
              {log.icon === "zap" && <Zap className="w-3.5 h-3.5 text-white fill-current shrink-0" />}
              <span>{log.text}</span>
            </div>
          ))}

          {/* Active Blinking Terminal Cursor */}
          <div className="pt-2 flex items-center gap-2 text-[#888888]">
            <span>crux@host ~ %</span>
            <span className="w-2 h-4 bg-white inline-block animate-pulse" />
          </div>
        </div>

        {/* Telemetry Status Bar */}
        <div className="px-6 py-3 bg-[#111111] border-t border-[#222222] flex flex-wrap items-center justify-between gap-4 text-[11px] font-mono text-[#888888]">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-white">
              <Cpu className="w-3.5 h-3.5 text-white" />
              <span>Rust Core: 0.4% CPU</span>
            </span>
            <div className="w-[1px] h-3 bg-[#222222]" />
            <span>RAM: 42 MB</span>
            <div className="w-[1px] h-3 bg-[#222222]" />
            <span>Subprocess Latency: 0.14ms</span>
          </div>

          <span className="text-white font-bold">
            Zero Telemetry Cloud Leaks // 100% Local Execution
          </span>
        </div>
      </div>
    </section>
  );
}
