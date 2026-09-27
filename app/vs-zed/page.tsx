import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Crux vs Zed — Architectural Comparison of Native Rust Code Editors",
  description:
    "Technical head-to-head comparison: Crux IDE vs Zed. WebGPU & Metal compute shaders vs GPUI, decentralized P2P WebRTC AST-CRDT vs centralized cloud CRDT, and native PTY HyperTerminal vs chat panels.",
  alternates: {
    canonical: "https://codecrux.us/vs-zed",
  },
};

export default function VsZedPage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "headline": "Crux IDE vs Zed Editor: Architectural Comparison",
    "description": "Comparison between Crux and Zed across rendering engines, collaboration topology, and AI integration.",
    "author": {
      "@type": "Organization",
      "name": "Crux Systems",
      "url": "https://codecrux.us",
    },
    "datePublished": "2026-09-24",
    "dateModified": "2026-09-27",
  };

  return (
    <div className="min-h-screen bg-[#000000] text-white font-sans antialiased selection:bg-[#0055FF]/30 selection:text-white">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />

      <header className="border-b border-[#222222] bg-[#000000] sticky top-0 z-50">
        <div className="max-w-[1280px] mx-auto px-6 h-14 flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 no-underline">
              <CruxBrandLogo size={20} />
            </Link>
            <span className="text-[#444444]">/</span>
            <span className="text-[#0055FF] font-bold">COMPARISON // CRUX VS ZED</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/benchmarks" className="text-[#888888] hover:text-white no-underline uppercase">
              Benchmarks
            </Link>
            <Link href="/ast-crdt" className="text-[#888888] hover:text-white no-underline uppercase">
              AST-CRDT
            </Link>
            <Link href="/pricing" className="text-[#888888] hover:text-white no-underline uppercase">
              Pricing
            </Link>
            <Link
              href="/ide"
              className="px-3 py-1.5 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold uppercase no-underline rounded-none"
            >
              LAUNCH IDE ↵
            </Link>
          </div>
        </div>
      </header>

      <main className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [HEAD-TO-HEAD // SYSTEMS ARCHITECTURE]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Crux vs Zed.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Zed is a fantastic, pioneering Rust editor. Here is a factual, nuanced architectural analysis of where Crux and Zed align, and where our engineering design choices differ.
          </p>
        </div>

        {/* Feature Comparison Table */}
        <section className="my-14 border border-[#222222] overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#222222] bg-[#111114] text-[#888888]">
                <th className="p-4 uppercase">Architectural Pillar</th>
                <th className="p-4 uppercase text-[#0055FF] font-bold">Crux IDE</th>
                <th className="p-4 uppercase text-white">Zed Editor</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#222222] text-[#cccccc]">
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 font-sans text-white font-medium">Display &amp; GPU Rasterization</td>
                <td className="p-4 text-[#0055FF] font-bold">Direct WebGPU / Metal Compute Shaders</td>
                <td className="p-4">GPUI (Custom Retained 2D Quad Engine)</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 font-sans text-white font-medium">Input-to-Photon Latency</td>
                <td className="p-4 text-[#0055FF] font-bold">4.2 ms</td>
                <td className="p-4">12.4 ms</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 font-sans text-white font-medium">Idle Memory Footprint</td>
                <td className="p-4 text-[#0055FF] font-bold">38 MB</td>
                <td className="p-4">140 MB</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 font-sans text-white font-medium">Collaboration Topology</td>
                <td className="p-4 text-[#22c55e] font-bold">Decentralized P2P WebRTC Mesh (Zero Cloud)</td>
                <td className="p-4">Centralized Zed Cloud Collaboration Relay</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 font-sans text-white font-medium">CRDT Synchronization Unit</td>
                <td className="p-4 text-[#0055FF] font-bold">Abstract Syntax Tree (AST-CRDT)</td>
                <td className="p-4">Text Rope Character Sequences</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 font-sans text-white font-medium">Terminal Subsystem</td>
                <td className="p-4 text-white">Universal PTY with Host CLI Auto-Discovery</td>
                <td className="p-4">Alacritty terminal integration</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 font-sans text-white font-medium">AI Coding Agent Paradigm</td>
                <td className="p-4 text-white">Autonomous HyperTerminal running local CLIs (agy, claude, codex)</td>
                <td className="p-4">Built-in side panel assistant &amp; inline edit model</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 font-sans text-white font-medium">Air-Gapped / Self-Hosted Readiness</td>
                <td className="p-4 text-[#22c55e] font-bold">100% Air-Gapped (Standalone relay binary)</td>
                <td className="p-4">Requires Zed server for collaboration features</td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* 3 Core Philosophical Differences */}
        <section className="my-14 grid grid-cols-1 md:grid-cols-3 gap-6 font-sans text-xs">
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <h3 className="text-white font-semibold text-base mb-2">1. WebGPU vs GPUI</h3>
            <p className="text-[#888888] leading-relaxed">
              Zed created GPUI, a remarkable 2D UI framework written in Rust. Crux takes a different approach: text formatting, syntax highlights, and token colors are uploaded directly into WebGPU / Metal storage buffers, allowing compute shaders to perform rasterization in parallel across GPU execution cores.
            </p>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <h3 className="text-white font-semibold text-base mb-2">2. P2P Mesh vs Central Server</h3>
            <p className="text-[#888888] leading-relaxed">
              When pairing in Zed, all keystrokes and channel events pass through Zed&apos;s cloud infrastructure. Crux uses an encrypted peer-to-peer WebRTC mesh: keystrokes flow directly between developer workstations over local LAN or direct P2P data channels with zero third-party intermediaries.
            </p>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <h3 className="text-white font-semibold text-base mb-2">3. Any Agent CLI vs Built-In Panel</h3>
            <p className="text-[#888888] leading-relaxed">
              Instead of locking you into a single proprietary assistant side-panel, Crux&apos;s HyperTerminal auto-discovers and orchestrates any system coding CLI (`agy`, `claude`, `codex`, `open-code`) directly in isolated POSIX namespaces with full tool calling.
            </p>
          </div>
        </section>
      </main>

      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-center font-mono text-xs text-[#555555]">
        <div>Crux IDE · Engineered for High-Velocity Engineering · <Link href="/" className="text-[#0055FF] no-underline">Return to Overview</Link></div>
      </footer>
    </div>
  );
}
