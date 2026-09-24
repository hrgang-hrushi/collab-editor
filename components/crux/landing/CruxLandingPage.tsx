"use client";

import React, { useState } from "react";
import {
  Download,
  Terminal,
  Zap,
  Cpu,
  ArrowRight,
  Sliders,
  Copy,
  Check,
  ShieldCheck,
  ExternalLink,
  Code2,
  FileCode2,
  Bot,
  Activity,
} from "lucide-react";

import MacosMenuBar from "./MacosMenuBar";
import CruxNavbar from "./CruxNavbar";
import WaitlistModal from "./WaitlistModal";
import HeroWindow3D from "./HeroWindow3D";
import MigrationWidget from "./MigrationWidget";
import PerformanceVisualizer from "./PerformanceVisualizer";
import AgenticTerminalSandbox from "./AgenticTerminalSandbox";
import SpatialRewindSection from "./SpatialRewindSection";
import EngineeringWall from "./EngineeringWall";
import PricingAndTrustSection from "./PricingAndTrustSection";
import AeyeCtaSection from "@/components/aeye/AeyeCtaSection";
import CruxBrandLogo from "../CruxBrandLogo";

interface CruxLandingPageProps {
  onLaunchWebEditor?: () => void;
}

export default function CruxLandingPage({ onLaunchWebEditor }: CruxLandingPageProps) {
  const [isWaitlistOpen, setIsWaitlistOpen] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);

  const copyCurlCommand = () => {
    navigator.clipboard.writeText("curl -fsSL https://codecrux.us/install.sh | bash");
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  return (
    <div
      className="min-h-screen w-full bg-[#000000] text-white font-sans antialiased selection:bg-white selection:text-black relative overflow-x-hidden"
      style={{
        fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
      }}
    >
      {/* Background Grid Pattern (Strict 1px #222222 Hairline Grid) */}
      <div className="fixed inset-0 crux-dot-grid opacity-30 pointer-events-none z-0" />

      {/* Hardware Brutalist macOS Native Menubar */}
      <MacosMenuBar onOpenWaitlist={() => setIsWaitlistOpen(true)} />

      {/* Hardware Brutalist Nav Header */}
      <CruxNavbar
        onOpenWaitlist={() => setIsWaitlistOpen(true)}
        onLaunchWebEditor={onLaunchWebEditor}
      />

      {/* Waitlist Modal */}
      <WaitlistModal
        isOpen={isWaitlistOpen}
        onClose={() => setIsWaitlistOpen(false)}
      />

      {/* ========================================================================= */}
      {/* HERO SECTION                                                             */}
      {/* ========================================================================= */}
      <main className="relative z-10 pt-28 sm:pt-36 pb-20">
        <section className="px-6 max-w-6xl mx-auto text-center">
          {/* Announcement Badge */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-none bg-[#111111] border border-[#222222] text-[#888888] text-xs font-mono mb-8 select-none">
            <span className="w-1.5 h-1.5 rounded-none bg-white" />
            <span className="text-white font-bold">Crux v0.1.0 Architecture Preview</span>
            <span className="text-[#444444]">|</span>
            <button
              onClick={() => setIsWaitlistOpen(true)}
              className="text-white hover:underline flex items-center gap-1 transition-none cursor-pointer"
            >
              <span>Request Priority Seat</span>
              <ArrowRight className="w-3 h-3 text-white" />
            </button>
          </div>

          {/* Hero Headline */}
          <h1 className="text-4xl sm:text-6xl md:text-7xl font-extrabold tracking-tight text-white max-w-5xl mx-auto leading-[1.04] mb-6 font-sans">
            The native collaborative IDE for{" "}
            <span className="text-white underline decoration-[#444444] underline-offset-8">
              high-velocity engineering.
            </span>
          </h1>

          {/* Sub-headline */}
          <p className="text-base sm:text-lg md:text-xl text-[#888888] max-w-2xl mx-auto font-normal leading-relaxed mb-10 font-sans">
            Engineered from bare silicon with Rust and WebGPU. Sub-15ms rendering latency,
            decentralized AST-CRDT real-time sync, and zero Chromium overhead.
          </p>

          {/* Primary Action Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-6">
            <button
              onClick={() => setIsWaitlistOpen(true)}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-8 py-4 rounded-none bg-white hover:bg-[#111111] hover:text-white text-black border border-white font-bold text-xs uppercase tracking-wider transition-none cursor-pointer group"
            >
              <Terminal className="w-4 h-4 text-black group-hover:text-white" />
              <span>Join Private Waitlist</span>
              <ArrowRight className="w-4 h-4 text-black group-hover:text-white" />
            </button>

            {onLaunchWebEditor && (
              <button
                onClick={onLaunchWebEditor}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-4 rounded-none bg-[#000000] hover:bg-white hover:text-black border border-[#222222] hover:border-white text-white text-xs font-semibold uppercase tracking-wider transition-none cursor-pointer"
              >
                <span>Try Studio In Browser</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Terminal Quick Installer Option */}
          <div className="flex items-center justify-center gap-2 text-xs text-[#888888] font-mono mb-10">
            <span>or verify binary via shell:</span>
            <button
              onClick={copyCurlCommand}
              className="inline-flex items-center gap-2 px-3 py-1 rounded-none bg-[#111111] border border-[#222222] hover:border-white text-[#888888] hover:text-white transition-none cursor-pointer"
            >
              <span>curl -fsSL https://codecrux.us/install.sh | bash</span>
              {copiedCurl ? (
                <Check className="w-3.5 h-3.5 text-white stroke-[3]" />
              ) : (
                <Copy className="w-3.5 h-3.5 text-[#888888]" />
              )}
            </button>
          </div>

          {/* Interactive 3D Hero Window Asset */}
          <HeroWindow3D />
        </section>

        {/* ========================================================================= */}
        {/* MODULAR SECTION 1: UNIVERSAL MIGRATION ENGINE                            */}
        {/* ========================================================================= */}
        <MigrationWidget />

        {/* ========================================================================= */}
        {/* MODULAR SECTION 2: SUB-15MS PERFORMANCE VISUALIZER                       */}
        {/* ========================================================================= */}
        <PerformanceVisualizer />

        {/* ========================================================================= */}
        {/* MODULAR SECTION 3: AGENTIC TERMINAL SANDBOX                              */}
        {/* ========================================================================= */}
        <AgenticTerminalSandbox />

        {/* ========================================================================= */}
        {/* MODULAR SECTION 4: SPATIAL CANVAS & TIME-TRAVEL REWIND                   */}
        {/* ========================================================================= */}
        <SpatialRewindSection />

        {/* ========================================================================= */}
        {/* ARCHITECTURE DEEP DIVE SECTION (Rust + Metal + Tauri)                     */}
        {/* ========================================================================= */}
        <section id="architecture" className="py-24 px-6 max-w-6xl mx-auto border-t border-[#222222]">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <div className="text-xs font-mono uppercase tracking-widest text-[#888888] mb-3 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-white" />
                <span>[BARE-METAL SYSTEM ARCHITECTURE]</span>
              </div>
              <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-white mb-6 font-sans">
                Native Rust IPC. Direct GPU Text Shaders. Zero Web Bloat.
              </h2>
              <p className="text-base text-[#888888] leading-relaxed mb-8 font-sans">
                Every mainstream modern code editor runs on Chromium. That means every open tab,
                every keystroke, and every extension fights with hundreds of megabytes of JavaScript
                garbage collection pauses. Crux replaces the entire web stack with native Mach-O binaries.
              </p>

              <div className="space-y-4 text-xs font-mono text-white">
                <div className="p-3.5 rounded-none bg-[#111111] border border-[#222222] flex items-center gap-3">
                  <div className="w-6 h-6 rounded-none bg-[#000000] border border-[#222222] text-white flex items-center justify-center shrink-0">
                    <Check className="w-3.5 h-3.5 text-white stroke-[3]" />
                  </div>
                  <div>
                    <span className="font-bold text-white">Direct CAMetalLayer Rasterization:</span>
                    <span className="text-[#888888] ml-1">Glyphs rendered via instanced GPU quad shaders without DOM layout thrashing.</span>
                  </div>
                </div>

                <div className="p-3.5 rounded-none bg-[#111111] border border-[#222222] flex items-center gap-3">
                  <div className="w-6 h-6 rounded-none bg-[#000000] border border-[#222222] text-white flex items-center justify-center shrink-0">
                    <Check className="w-3.5 h-3.5 text-white stroke-[3]" />
                  </div>
                  <div>
                    <span className="font-bold text-white">Decentralized AST-CRDT Protocol:</span>
                    <span className="text-[#888888] ml-1">Real-time multiplayer synchronization preserves code semantics rather than blind character offsets.</span>
                  </div>
                </div>

                <div className="p-3.5 rounded-none bg-[#111111] border border-[#222222] flex items-center gap-3">
                  <div className="w-6 h-6 rounded-none bg-[#000000] border border-[#222222] text-white flex items-center justify-center shrink-0">
                    <Check className="w-3.5 h-3.5 text-white stroke-[3]" />
                  </div>
                  <div>
                    <span className="font-bold text-white">Subprocess Isolation &amp; PTY Streaming:</span>
                    <span className="text-[#888888] ml-1">Compilers and local AI agents execute as asynchronous OS threads with 0.14ms response times.</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Architecture Telemetry Box */}
            <div className="p-8 rounded-none bg-[#000000] border border-[#222222] relative">
              <div className="text-xs font-mono uppercase tracking-wider text-[#888888] pb-4 border-b border-[#222222] flex items-center justify-between">
                <span>Kernel Pipeline Execution Stack</span>
                <span className="text-white font-bold bg-[#111111] border border-[#222222] px-2 py-0.5">120 FPS STABLE</span>
              </div>

              <div className="space-y-4 pt-6 text-xs font-mono">
                <div className="p-3 rounded-none bg-[#111111] border border-[#222222] space-y-1.5">
                  <div className="flex justify-between text-white">
                    <span className="font-bold text-white">Layer 1: Native macOS Host</span>
                    <span className="text-[#888888]">Tauri v2 + Rust Core</span>
                  </div>
                  <p className="text-[11px] text-[#888888]">
                    Mach-O aarch64 &amp; x86_64 binary. Memory footprint: 38MB. Zero Chromium bundle.
                  </p>
                </div>

                <div className="p-3 rounded-none bg-[#111111] border border-[#222222] space-y-1.5">
                  <div className="flex justify-between text-white">
                    <span className="font-bold text-white">Layer 2: WebGPU &amp; Metal v3</span>
                    <span className="text-[#888888]">4.2ms Input Latency</span>
                  </div>
                  <p className="text-[11px] text-[#888888]">
                    Direct hardware vertex buffer for 250k+ lines. Bypasses the CSS box model completely.
                  </p>
                </div>

                <div className="p-3 rounded-none bg-[#111111] border border-[#222222] space-y-1.5">
                  <div className="flex justify-between text-white">
                    <span className="font-bold text-white">Layer 3: Yjs + AST-CRDT Engine</span>
                    <span className="text-[#888888]">&lt;1ms P2P Sync</span>
                  </div>
                  <p className="text-[11px] text-[#888888]">
                    Decentralized WebRTC data channels with cryptographic workspace signatures.
                  </p>
                </div>
              </div>

              <div className="mt-8 pt-4 border-t border-[#222222] flex items-center justify-between text-[11px] font-mono text-[#888888]">
                <span className="flex items-center gap-1.5 text-white">
                  <ShieldCheck className="w-3.5 h-3.5 text-white" />
                  <span>Verified memory safe via Rust compiler guarantees</span>
                </span>
                <span className="text-[#444444]">Build: release-0.1.0</span>
              </div>
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* MODULAR SECTION 5: ENGINEERING WALL                                       */}
        {/* ========================================================================= */}
        <EngineeringWall onOpenWaitlist={() => setIsWaitlistOpen(true)} />

        {/* ========================================================================= */}
        {/* MODULAR SECTION 6: PRICING & TRUST SECTION                                */}
        {/* ========================================================================= */}
        <PricingAndTrustSection onOpenWaitlist={() => setIsWaitlistOpen(true)} />

        {/* Crux Insider Dispatch Section */}
        <AeyeCtaSection />
      </main>

      {/* Sleek Minimalist Footer */}
      <footer className="border-t border-[#222222] py-14 px-6 max-w-6xl mx-auto text-xs text-[#888888] relative z-10 font-mono">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <CruxBrandLogo size={20} withText={true} />
            <div className="w-[1px] h-3 bg-[#222222]" />
            <span>Ultra-Performance Native IDE</span>
            <div className="w-[1px] h-3 bg-[#222222]" />
            <span className="text-white font-mono">Rust + WebGPU</span>
          </div>

          <div className="flex items-center gap-6 font-mono text-[11px]">
            <a
              href="https://github.com/hrgang-hrushi/collab-editor"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#888888] hover:text-white transition-none no-underline"
            >
              GitHub
            </a>
            <a
              href="#architecture"
              className="text-[#888888] hover:text-white transition-none no-underline"
            >
              Architecture
            </a>
            <a
              href="#benchmarks"
              className="text-[#888888] hover:text-white transition-none no-underline"
            >
              Benchmarks
            </a>
            <button
              onClick={() => setIsWaitlistOpen(true)}
              className="text-white hover:underline transition-none cursor-pointer"
            >
              Waitlist
            </button>
          </div>
        </div>

        <div className="mt-8 pt-8 border-t border-[#222222] flex flex-col sm:flex-row items-center justify-between gap-4 text-[11px] text-[#444444]">
          <span>© 2026 Crux Systems Inc. All rights reserved.</span>
          <span>Engineered for macOS Apple Silicon &amp; Intel.</span>
        </div>
      </footer>
    </div>
  );
}
