"use client";

import React, { useState } from "react";
import {
  Download,
  Terminal,
  Zap,
  Cpu,
  Layers,
  Sparkles,
  ArrowRight,
  Sliders,
  CheckCircle2,
  Copy,
  Check,
  ShieldCheck,
  ChevronRight,
  ExternalLink,
  Code2,
  GitBranch,
  Laptop,
  Flame,
  FileCode2,
  RotateCcw,
} from "lucide-react";

interface CruxLandingPageProps {
  onLaunchWebEditor?: () => void;
}

export default function CruxLandingPage({ onLaunchWebEditor }: CruxLandingPageProps) {
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [activeTab, setActiveTab] = useState<"code" | "crdt" | "migration">("code");
  const [downloadProgress, setDownloadProgress] = useState<"idle" | "downloading">("idle");

  const downloadUrl = "/api/download";

  const handleDownload = () => {
    setDownloadProgress("downloading");
    const link = document.createElement("a");
    link.href = downloadUrl;
    link.setAttribute("download", "crux_0.1.0_universal.dmg");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => setDownloadProgress("idle"), 3500);
  };

  const copyBrewCommand = () => {
    navigator.clipboard.writeText("curl -fsSL https://codecrux.us/install.sh | bash");
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  return (
    <div
      className="min-h-screen w-full bg-[#09090b] text-neutral-100 font-sans antialiased selection:bg-neutral-700 selection:text-white overflow-x-hidden"
      style={{
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Inter", "Segoe UI", Roboto, sans-serif',
      }}
    >
      {/* Subtle Background Glows */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute top-[-10%] left-1/2 -translate-x-1/2 w-[1000px] h-[550px] bg-gradient-to-b from-neutral-800/25 via-neutral-900/10 to-transparent blur-3xl opacity-70" />
        <div className="absolute top-[40%] right-[-10%] w-[500px] h-[500px] bg-neutral-800/15 rounded-full blur-3xl" />
        <div className="absolute top-[60%] left-[-10%] w-[500px] h-[500px] bg-neutral-800/15 rounded-full blur-3xl" />
      </div>

      {/* Top Header */}
      <header className="sticky top-0 z-50 backdrop-blur-xl bg-[#09090b]/80 border-b border-neutral-800/60 transition-colors">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          {/* Logo & Platform Tag */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-neutral-100 text-neutral-950 flex items-center justify-center font-bold text-base shadow-sm">
                <span className="translate-y-[-0.5px]">C</span>
              </div>
              <span className="text-base font-semibold tracking-tight text-white">
                Crux
              </span>
            </div>
            <span className="hidden sm:inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-neutral-800/90 text-neutral-300 border border-neutral-700/60">
              macOS Native
            </span>
          </div>

          {/* Navigation Anchors */}
          <nav className="hidden md:flex items-center gap-8 text-sm text-neutral-400 font-medium">
            <a
              href="#architecture"
              className="hover:text-neutral-100 transition-colors"
            >
              Architecture
            </a>
            <a
              href="#features"
              className="hover:text-neutral-100 transition-colors"
            >
              Engine
            </a>
            <a
              href="#migration"
              className="hover:text-neutral-100 transition-colors"
            >
              Migration
            </a>
            <a
              href="#performance"
              className="hover:text-neutral-100 transition-colors"
            >
              Benchmarks
            </a>
          </nav>

          {/* Action CTAs */}
          <div className="flex items-center gap-3">
            {onLaunchWebEditor && (
              <button
                onClick={onLaunchWebEditor}
                className="hidden sm:inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-medium text-neutral-300 hover:text-white bg-neutral-900 hover:bg-neutral-800 border border-neutral-800 transition-all cursor-pointer"
              >
                <span>Launch Web Studio</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            )}

            <a
              href="/downloads/crux.dmg"
              download="crux.dmg"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-white text-neutral-950 hover:bg-neutral-100 active:scale-[0.98] transition-all shadow-sm cursor-pointer no-underline"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download DMG</span>
            </a>
          </div>
        </div>
      </header>

      {/* Main Hero Section */}
      <main className="relative z-10">
        <section className="pt-20 pb-16 md:pt-28 md:pb-24 px-6 max-w-6xl mx-auto text-center">
          {/* Subtle announcement pill */}
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-900/90 border border-neutral-800/80 text-neutral-300 text-xs font-medium mb-6 animate-fade-in shadow-inner">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Crux v0.1.0 Universal Release for macOS</span>
            <span className="text-neutral-600">|</span>
            <a
              href="#migration"
              className="text-neutral-400 hover:text-white flex items-center gap-1"
            >
              <span>Instant Migration</span>
              <ArrowRight className="w-3 h-3" />
            </a>
          </div>

          {/* Hero Taglines */}
          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-semibold tracking-tight text-white max-w-4xl mx-auto leading-[1.08] mb-6">
            The native desktop IDE for spatial software engineering.
          </h1>

          <p className="text-base sm:text-lg md:text-xl text-neutral-400 max-w-2xl mx-auto font-normal leading-relaxed mb-10">
            Engineered from bare silicon with Rust and WebGPU. Shift away from sluggish,
            single-file browser editors to real-time synchronized AST-CRDT architecture.
          </p>

          {/* Primary Call to Action */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-5">
            <a
              href="/downloads/crux.dmg"
              download="crux.dmg"
              className="w-full sm:w-auto inline-flex flex-col items-center justify-center px-8 py-3.5 rounded-2xl bg-white text-neutral-950 hover:bg-neutral-100 active:scale-[0.99] transition-all shadow-lg shadow-white/5 cursor-pointer group no-underline"
            >
              <div className="flex items-center gap-2.5">
                {/* Apple Logo SVG */}
                <svg
                  className="w-5 h-5 fill-current"
                  viewBox="0 0 170 170"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path d="M150.37 130.25c-2.45 5.66-5.35 10.87-8.71 15.66-4.58 6.53-8.33 11.05-11.22 13.56-4.48 4.12-9.28 6.23-14.42 6.35-3.69 0-8.14-1.05-13.32-3.18-5.19-2.12-9.97-3.17-14.34-3.17-4.58 0-9.49 1.05-14.75 3.17-5.26 2.13-9.5 3.24-12.74 3.35-4.35.13-9.16-1.9-14.42-6.08-3.69-3.04-7.67-7.81-11.96-14.34-6.85-10.42-12.18-21.93-15.99-34.52-3.8-12.6-5.71-24.36-5.71-35.3 0-14.56 3.65-26.79 10.96-36.68 7.31-9.9 16.59-14.99 27.84-15.28 4.9 0 10.36 1.34 16.38 4.02 6.02 2.68 9.94 4.08 11.77 4.2 1.45-.12 5.62-1.63 12.51-4.52 6.89-2.9 12.38-4.24 16.48-4.02 11.53.58 20.73 4.88 27.6 12.91-10.03 6.09-14.94 14.73-14.73 25.92.22 8.7 3.51 16.03 9.87 22.01 6.36 5.98 13.9 9.39 22.61 10.23-2.17 6.52-4.85 13.19-8.04 20-3.19 6.81-6.19 12.86-9.01 18.15zM119.22 31.84c0-7.39 2.65-14.18 7.96-20.37 5.3-6.19 11.83-10.01 19.57-11.47.65 1.52.98 3.19.98 5 0 7.39-2.72 14.13-8.15 20.22-5.43 6.09-12 9.89-19.72 11.41-.22-1.52-.64-3.12-.64-4.79z" />
                </svg>
                <span className="text-sm font-semibold tracking-tight">
                  Download for macOS (Universal DMG)
                </span>
                <ArrowRight className="w-4 h-4 text-neutral-600 group-hover:translate-x-0.5 transition-transform" />
              </div>
              <span className="text-[11px] font-normal text-neutral-500 mt-0.5">
                Requires macOS 12.0+ · Apple Silicon & Intel
              </span>
            </a>

            {onLaunchWebEditor && (
              <button
                onClick={onLaunchWebEditor}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-4 rounded-2xl bg-neutral-900 hover:bg-neutral-800 border border-neutral-800/90 text-neutral-200 text-sm font-medium transition-all active:scale-[0.99] cursor-pointer"
              >
                <span>Try in Browser</span>
                <ExternalLink className="w-4 h-4 text-neutral-500" />
              </button>
            )}
          </div>

          {/* Terminal Curl Installer option */}
          <div className="flex items-center justify-center gap-2 text-xs text-neutral-500 font-mono">
            <span>or via terminal:</span>
            <button
              onClick={copyBrewCommand}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-neutral-900 border border-neutral-800 hover:border-neutral-700 text-neutral-400 hover:text-neutral-200 transition-all cursor-pointer"
            >
              <span>curl -fsSL https://codecrux.us/install.sh | bash</span>
              {copiedCurl ? (
                <Check className="w-3 h-3 text-emerald-400" />
              ) : (
                <Copy className="w-3 h-3" />
              )}
            </button>
          </div>

          {/* UI Preview Mockup Card */}
          <div className="mt-14 relative mx-auto max-w-5xl">
            {/* Ambient window glow */}
            <div className="absolute -inset-1 rounded-3xl bg-gradient-to-b from-neutral-700/20 to-transparent blur-xl -z-10" />

            <div className="rounded-2xl border border-neutral-800/90 bg-[#0d0e11] overflow-hidden shadow-2xl text-left">
              {/* Window Titlebar */}
              <div className="px-4 py-3 bg-[#111216] border-b border-neutral-800/80 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-[#ff5f56]/80" />
                  <div className="w-3 h-3 rounded-full bg-[#ffbd2e]/80" />
                  <div className="w-3 h-3 rounded-full bg-[#27c93f]/80" />
                  <span className="ml-3 text-xs font-medium text-neutral-400 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    <span>Crux Studio — compiler/engine.rs</span>
                  </span>
                </div>

                <div className="flex items-center gap-2 text-xs font-mono text-neutral-500">
                  <span className="px-2 py-0.5 rounded bg-neutral-800/60 text-neutral-400">
                    sub-15ms WebGPU
                  </span>
                  <span className="hidden sm:inline px-2 py-0.5 rounded bg-neutral-800/60 text-emerald-400">
                    CRDT In-Sync
                  </span>
                </div>
              </div>

              {/* Editor Workspace Mockup Inner */}
              <div className="grid grid-cols-12 min-h-[420px] text-xs">
                {/* File Tree Left Pane */}
                <div className="hidden md:block col-span-3 border-r border-neutral-800/60 bg-[#0d0e11]/90 p-4 font-mono text-neutral-400 space-y-2">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-neutral-500 mb-3 flex items-center justify-between">
                    <span>EXPLORER</span>
                    <GitBranch className="w-3.5 h-3.5 text-neutral-600" />
                  </div>
                  <div className="flex items-center gap-2 text-neutral-300">
                    <span className="text-neutral-600">▾</span>
                    <span>src</span>
                  </div>
                  <div className="pl-4 space-y-1.5 text-neutral-400">
                    <div className="flex items-center gap-2 py-1 px-2 rounded bg-neutral-800/60 text-white font-medium">
                      <FileCode2 className="w-3.5 h-3.5 text-blue-400" />
                      <span>engine.rs</span>
                    </div>
                    <div className="flex items-center gap-2 py-1 px-2 hover:text-neutral-200 cursor-pointer">
                      <FileCode2 className="w-3.5 h-3.5 text-amber-400" />
                      <span>ast_crdt.rs</span>
                    </div>
                    <div className="flex items-center gap-2 py-1 px-2 hover:text-neutral-200 cursor-pointer">
                      <FileCode2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>renderer.metal</span>
                    </div>
                    <div className="flex items-center gap-2 py-1 px-2 hover:text-neutral-200 cursor-pointer">
                      <FileCode2 className="w-3.5 h-3.5 text-purple-400" />
                      <span>ipc.rs</span>
                    </div>
                  </div>

                  <div className="pt-6">
                    <div className="p-3 rounded-xl bg-neutral-900/80 border border-neutral-800/80 space-y-1.5">
                      <div className="text-[10px] font-medium text-neutral-400 uppercase tracking-wider flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                        <span>Connected Peers</span>
                      </div>
                      <div className="text-[11px] text-neutral-300 font-sans">
                        Sarah L. <span className="text-neutral-500">(Boston)</span>
                      </div>
                      <div className="text-[11px] text-neutral-300 font-sans">
                        Alex M. <span className="text-neutral-500">(Zurich)</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Editor Content Center/Right */}
                <div className="col-span-12 md:col-span-9 bg-[#0a0a0d] p-5 font-mono flex flex-col justify-between">
                  <div className="space-y-1.5 leading-relaxed text-neutral-300">
                    <div className="text-neutral-600">
                      {"// Crux Native WebGPU & AST-CRDT Execution Core"}
                    </div>
                    <div>
                      <span className="text-purple-400">pub async fn</span>{" "}
                      <span className="text-blue-400">dispatch_spatial_frame</span>
                      (ctx: &amp;
                      <span className="text-emerald-400">GpuDeviceContext</span>) -&gt;{" "}
                      <span className="text-amber-400">Result</span>&lt;(), EngineError&gt; &#123;
                    </div>
                    <div className="pl-4 text-neutral-400">
                      <span className="text-purple-400">let</span> ast ={" "}
                      <span className="text-neutral-200">parse_ast_incremental</span>
                      (&amp;buffer).await?;
                    </div>
                    <div className="pl-4 text-neutral-400">
                      <span className="text-purple-400">let</span> frame_buffer = ctx.
                      <span className="text-blue-300">acquire_next_metal_texture</span>()?;
                    </div>
                    <div className="pl-4 text-neutral-500">
                      {"// Bypasses the HTML DOM entirely: Direct hardware rasterization"}
                    </div>
                    <div className="pl-4 text-neutral-300">
                      render_pipeline.
                      <span className="text-emerald-300">render_quad_tree</span>(
                        &amp;ast,
                        frame_buffer.view(),
                        <span className="text-amber-300">14.2 /* ms */</span>
                      );
                    </div>
                    <div className="pl-4 text-neutral-400">
                      sync_crdt_delta_peers(&amp;ast.delta_vector()).await?;
                    </div>
                    <div>&#125;</div>
                  </div>

                  {/* Terminal / Telemetry HUD Bar */}
                  <div className="mt-8 pt-4 border-t border-neutral-800/80 flex flex-wrap items-center justify-between gap-4 text-[11px] text-neutral-400">
                    <div className="flex items-center gap-3">
                      <span className="flex items-center gap-1 text-emerald-400">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Metal v3 Render Enclave</span>
                      </span>
                      <span>•</span>
                      <span>Target: Universal macOS aarch64 + x86_64</span>
                    </div>
                    <div className="flex items-center gap-2 text-neutral-500">
                      <span>FPS: 120</span>
                      <span>Memory: 48 MB</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 3-Column Feature Grid */}
        <section id="features" className="py-20 px-6 max-w-6xl mx-auto border-t border-neutral-800/60">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <h2 className="text-xs font-semibold tracking-widest text-neutral-400 uppercase mb-3">
              Engine Specifications
            </h2>
            <p className="text-3xl sm:text-4xl font-semibold tracking-tight text-white">
              Built for performance that software developers can feel.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Feature 1: WebGPU */}
            <div className="p-8 rounded-2xl bg-neutral-900/40 border border-neutral-800/70 hover:border-neutral-700/80 transition-all group">
              <div className="w-10 h-10 rounded-xl bg-neutral-800/80 border border-neutral-700/50 flex items-center justify-center text-neutral-200 mb-6 group-hover:text-white transition-colors">
                <Zap className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2.5">
                WebGPU Rendering
              </h3>
              <p className="text-sm text-neutral-400 leading-relaxed">
                Renders text, multi-file canvases, and spatial nodes through direct GPU
                pipelines with sub-15ms latency, completely bypassing the HTML DOM.
              </p>
              <div className="mt-6 pt-6 border-t border-neutral-800/60 text-xs font-mono text-neutral-400">
                120 FPS continuous rasterization
              </div>
            </div>

            {/* Feature 2: Semantic AST-CRDTs */}
            <div className="p-8 rounded-2xl bg-neutral-900/40 border border-neutral-800/70 hover:border-neutral-700/80 transition-all group">
              <div className="w-10 h-10 rounded-xl bg-neutral-800/80 border border-neutral-700/50 flex items-center justify-center text-neutral-200 mb-6 group-hover:text-white transition-colors">
                <Cpu className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2.5">
                Semantic AST-CRDTs
              </h3>
              <p className="text-sm text-neutral-400 leading-relaxed">
                Rust-backed syntax tree synchronization preserves code semantics during
                collaborative merges, preventing syntax corruption and invalid states.
              </p>
              <div className="mt-6 pt-6 border-t border-neutral-800/60 text-xs font-mono text-neutral-400">
                Peer-to-peer WebRTC &amp; Yjs engine
              </div>
            </div>

            {/* Feature 3: One-Click Migration */}
            <div className="p-8 rounded-2xl bg-neutral-900/40 border border-neutral-800/70 hover:border-neutral-700/80 transition-all group">
              <div className="w-10 h-10 rounded-xl bg-neutral-800/80 border border-neutral-700/50 flex items-center justify-center text-neutral-200 mb-6 group-hover:text-white transition-colors">
                <Sliders className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2.5">
                One-Click Migration
              </h3>
              <p className="text-sm text-neutral-400 leading-relaxed">
                Automatically scans and ingests your VS Code, Cursor, and Windsurf
                settings, muscle-memory shortcuts, themes, extensions, and AI agent rules.
              </p>
              <div className="mt-6 pt-6 border-t border-neutral-800/60 text-xs font-mono text-neutral-400">
                Zero manual setup or re-mapping
              </div>
            </div>
          </div>
        </section>

        {/* Deep Dive Architecture Section */}
        <section id="architecture" className="py-20 px-6 max-w-6xl mx-auto border-t border-neutral-800/60">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <div className="text-xs font-semibold tracking-widest text-neutral-400 uppercase mb-3">
                System Architecture
              </div>
              <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight text-white mb-6">
                Native Rust IPC. Subprocess isolation. Zero bloat.
              </h2>
              <p className="text-base text-neutral-400 leading-relaxed mb-6">
                Unlike Electron apps that bundle an entire Chromium instance per window,
                Crux operates on a lightweight native macOS runtime compiled through
                Tauri and Rust.
              </p>

              <div className="space-y-3.5 text-sm text-neutral-300">
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center shrink-0">
                    <Check className="w-3.5 h-3.5" />
                  </div>
                  <span>Instant cold boot in under 180 milliseconds</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center shrink-0">
                    <Check className="w-3.5 h-3.5" />
                  </div>
                  <span>Direct OS process spawning via native Rust execution pipeline</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center shrink-0">
                    <Check className="w-3.5 h-3.5" />
                  </div>
                  <span>Cryptographic workspace presence signed with Ed25519 keys</span>
                </div>
              </div>

              <div className="mt-8">
                <a
                  href="/downloads/crux.dmg"
                  download="crux.dmg"
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-neutral-100 hover:bg-white text-neutral-950 font-medium text-xs transition-all cursor-pointer no-underline"
                >
                  <Download className="w-4 h-4" />
                  <span>Download macOS Installer (.dmg)</span>
                </a>
              </div>
            </div>

            {/* Performance Benchmark Comparison */}
            <div id="performance" className="p-8 rounded-2xl bg-neutral-900/50 border border-neutral-800/80">
              <div className="text-xs font-semibold uppercase tracking-wider text-neutral-400 mb-6">
                Efficiency Benchmarks (macOS M3 Max)
              </div>

              <div className="space-y-6 text-sm">
                <div>
                  <div className="flex justify-between text-xs mb-2">
                    <span className="font-medium text-neutral-200">Idle Memory Usage</span>
                    <span className="text-emerald-400 font-mono">42 MB (Crux) vs 680 MB (Electron)</span>
                  </div>
                  <div className="h-2 w-full bg-neutral-800 rounded-full overflow-hidden flex">
                    <div className="bg-emerald-400 h-full w-[8%]" />
                    <div className="bg-neutral-600 h-full w-[92%]" />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-2">
                    <span className="font-medium text-neutral-200">Input to Photon Latency</span>
                    <span className="text-emerald-400 font-mono">4.2 ms vs 24.8 ms</span>
                  </div>
                  <div className="h-2 w-full bg-neutral-800 rounded-full overflow-hidden flex">
                    <div className="bg-emerald-400 h-full w-[17%]" />
                    <div className="bg-neutral-600 h-full w-[83%]" />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-2">
                    <span className="font-medium text-neutral-200">Binary Package Size</span>
                    <span className="text-emerald-400 font-mono">18.4 MB vs 240 MB</span>
                  </div>
                  <div className="h-2 w-full bg-neutral-800 rounded-full overflow-hidden flex">
                    <div className="bg-emerald-400 h-full w-[10%]" />
                    <div className="bg-neutral-600 h-full w-[90%]" />
                  </div>
                </div>
              </div>

              <div className="mt-8 p-4 rounded-xl bg-neutral-950 border border-neutral-800/70 text-xs font-mono text-neutral-400">
                <span className="text-neutral-500">$</span> crux --profile-telemetry
                <br />
                <span className="text-emerald-400">✓ Native Mach-O universal binary verified</span>
                <br />
                <span className="text-neutral-400">✓ Metal 3 pipeline initialized in 14.8ms</span>
              </div>
            </div>
          </div>
        </section>

        {/* Migration Banner Section */}
        <section id="migration" className="py-20 px-6 max-w-6xl mx-auto border-t border-neutral-800/60">
          <div className="p-10 rounded-3xl bg-neutral-900/30 border border-neutral-800/70 text-center max-w-4xl mx-auto">
            <div className="w-12 h-12 rounded-2xl bg-neutral-800/80 border border-neutral-700/60 flex items-center justify-center text-neutral-200 mx-auto mb-6">
              <Sliders className="w-6 h-6" />
            </div>
            <h2 className="text-2xl sm:text-3xl font-semibold text-white tracking-tight mb-4">
              Bring your entire workspace in under two seconds.
            </h2>
            <p className="text-neutral-400 text-sm sm:text-base max-w-xl mx-auto leading-relaxed mb-8">
              Crux reads your host machine configuration for VS Code, Cursor, and Windsurf.
              Your muscle memory, keybindings, and AI rules are preserved out of the box.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-3">
              <a
                href="/downloads/crux.dmg"
                download="crux.dmg"
                className="px-6 py-3 rounded-xl bg-white text-neutral-950 hover:bg-neutral-100 text-xs font-semibold transition-all cursor-pointer flex items-center gap-2 no-underline"
              >
                <Download className="w-4 h-4" />
                <span>Get Crux for macOS</span>
              </a>
              {onLaunchWebEditor && (
                <button
                  onClick={onLaunchWebEditor}
                  className="px-6 py-3 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-neutral-200 text-xs font-medium border border-neutral-700/60 transition-all cursor-pointer"
                >
                  Test Migration in Browser
                </button>
              )}
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-neutral-800/60 py-12 px-6 max-w-6xl mx-auto text-xs text-neutral-500">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 rounded-md bg-white text-neutral-950 flex items-center justify-center font-bold text-xs">
              C
            </div>
            <span className="text-neutral-300 font-medium">Crux Software</span>
            <span className="text-neutral-600">·</span>
            <span>Bare-metal spatial IDE</span>
          </div>

          <div className="flex items-center gap-6">
            <a
              href="https://github.com/hrgang-hrushi/collab-editor"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-neutral-300 transition-colors"
            >
              GitHub
            </a>
            <a
              href="#architecture"
              className="hover:text-neutral-300 transition-colors"
            >
              Architecture
            </a>
            <a
              href="/downloads/crux.dmg"
              download="crux.dmg"
              className="hover:text-neutral-300 transition-colors"
            >
              Direct DMG
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
