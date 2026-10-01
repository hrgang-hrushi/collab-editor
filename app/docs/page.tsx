import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Code Crux Documentation — Quickstart, P2P Rooms & Local Agent Terminal",
  description:
    "Official developer documentation for Code Crux (Crux IDE, https://codecrux.us). Learn how to launch the web workstation, configure native POSIX PTY agents, create decentralized AST-CRDT pair programming rooms, and customize WebGPU compute pipelines.",
  keywords: [
    "Code Crux Docs",
    "CodeCrux Documentation",
    "Crux IDE manual",
    "Crux quickstart guide",
    "P2P collaborative room setup",
    "HyperTerminal AI configuration",
    "codecrux.us docs",
  ],
  alternates: {
    canonical: "https://codecrux.us/docs",
  },
  openGraph: {
    type: "website",
    url: "https://codecrux.us/docs",
    title: "Code Crux Developer Documentation",
    description:
      "Quickstart guide, command palette reference, P2P room sync, and AI terminal setup for Code Crux.",
    siteName: "Code Crux (Crux IDE)",
  },
};

export default function DocsPage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "@id": "https://codecrux.us/docs#docs",
    "headline": "Code Crux IDE Developer Guide and Documentation",
    "name": "Code Crux Documentation",
    "url": "https://codecrux.us/docs",
    "author": {
      "@type": "Organization",
      "name": "Code Crux Systems",
    },
    "publisher": {
      "@type": "Organization",
      "name": "Code Crux Systems",
      "logo": "https://codecrux.us/crux-icon.png",
    },
    "breadcrumb": {
      "@type": "BreadcrumbList",
      "itemListElement": [
        {
          "@type": "ListItem",
          "position": 1,
          "name": "Home",
          "item": "https://codecrux.us",
        },
        {
          "@type": "ListItem",
          "position": 2,
          "name": "Documentation",
          "item": "https://codecrux.us/docs",
        },
      ],
    },
  };

  return (
    <div className="min-h-screen bg-[#000000] text-white font-sans antialiased selection:bg-[#0055FF]/30 selection:text-white">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />

      {/* Header */}
      <header className="border-b border-[#222222] bg-[#000000] sticky top-0 z-50">
        <div className="max-w-[1280px] mx-auto px-6 h-14 flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 no-underline">
              <CruxBrandLogo size={20} />
            </Link>
            <span className="text-[#444444]">/</span>
            <span className="text-[#0055FF] font-bold">MANUAL // SYSTEM DOCUMENTATION</span>
          </div>
          <nav className="flex items-center gap-4">
            <Link href="/about" className="text-[#888888] hover:text-white no-underline uppercase">
              About
            </Link>
            <Link href="/pricing" className="text-[#888888] hover:text-white no-underline uppercase">
              Pricing
            </Link>
            <Link href="/blog" className="text-[#888888] hover:text-white no-underline uppercase">
              Blog
            </Link>
            <Link href="/benchmarks" className="text-[#888888] hover:text-white no-underline uppercase">
              Benchmarks
            </Link>
            <Link
              href="/ide"
              className="px-3 py-1.5 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold uppercase no-underline rounded-none"
            >
              LAUNCH IDE ↵
            </Link>
          </nav>
        </div>
      </header>

      {/* Main Body */}
      <main className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [KERNEL ARCHITECTURE &amp; OPERATOR MANUAL]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Code Crux Documentation.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Essential operational guides for running the Code Crux bare-metal collaborative editor,
            binding host CLI coding agents, establishing encrypted P2P peer meshes, and optimizing WebGPU rasterization.
          </p>
        </div>

        {/* Quickstart Section */}
        <section className="py-12 border-b border-[#222222]">
          <h2 className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-4 font-bold">
            01 // ZERO-INSTALL WEB WORKSTATION
          </h2>
          <div className="border border-[#222222] bg-[#0c0c0e] p-6 space-y-4">
            <p className="text-sm text-[#aaaaaa] leading-relaxed">
              Code Crux compiles to standard WebAssembly (Wasm) and WebGPU pipelines, allowing full editor execution directly in modern Chromium, Safari, and Firefox browsers without any client installation.
            </p>
            <div className="p-4 bg-[#000000] border border-[#222222] font-mono text-xs text-white">
              <span className="text-[#555555]">$ </span>
              <span>open </span>
              <a href="https://codecrux.us/ide" className="text-[#0055FF] underline">
                https://codecrux.us/ide
              </a>
            </div>
          </div>
        </section>

        {/* Keybindings Reference */}
        <section className="py-12 border-b border-[#222222]">
          <h2 className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-4 font-bold">
            02 // MECHANICAL KEYBOARD SHORTCUTS
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
            <div className="border border-[#222222] bg-[#0c0c0e] p-4 flex items-center justify-between">
              <span className="text-[#888888]">Open Zero-State Omnibar / Commands</span>
              <span className="bg-[#111111] border border-[#333333] px-2 py-1 text-white font-bold">Cmd + K</span>
            </div>
            <div className="border border-[#222222] bg-[#0c0c0e] p-4 flex items-center justify-between">
              <span className="text-[#888888]">Toggle Native HyperTerminal / PTY</span>
              <span className="bg-[#111111] border border-[#333333] px-2 py-1 text-white font-bold">Ctrl + `</span>
            </div>
            <div className="border border-[#222222] bg-[#0c0c0e] p-4 flex items-center justify-between">
              <span className="text-[#888888]">Dispatch AI Coding Agent Task</span>
              <span className="bg-[#111111] border border-[#333333] px-2 py-1 text-white font-bold">Cmd + I</span>
            </div>
            <div className="border border-[#222222] bg-[#0c0c0e] p-4 flex items-center justify-between">
              <span className="text-[#888888]">Create Decentralized P2P Room</span>
              <span className="bg-[#111111] border border-[#333333] px-2 py-1 text-white font-bold">Cmd + Shift + P</span>
            </div>
          </div>
        </section>

        {/* AST-CRDT & AI Agent Configuration */}
        <section className="py-12 grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="border border-[#222222] p-8 bg-[#0c0c0e]">
            <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
              [DECENTRALIZED P2P ROOMS]
            </div>
            <h3 className="text-xl font-medium text-white mb-3">AST-CRDT Peer Mesh</h3>
            <p className="text-xs text-[#888888] leading-relaxed mb-4">
              To start a collaborative session without third-party servers, open the Omnibar, generate a deterministic room hash, and share the cryptographic room link. All edits sync via WebRTC data channels directly between peers.
            </p>
            <Link href="/ast-crdt" className="text-xs font-mono text-[#0055FF] hover:underline">
              Read AST-CRDT Protocol Spec →
            </Link>
          </div>

          <div className="border border-[#222222] p-8 bg-[#0c0c0e]">
            <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
              [LOCAL AGENT DAEMON]
            </div>
            <h3 className="text-xl font-medium text-white mb-3">HyperTerminal Bridge</h3>
            <p className="text-xs text-[#888888] leading-relaxed mb-4">
              Crux scans your host environment for CLI agents including AntiGravity (`agy`), Anthropic Claude Code (`claude`), and OpenAI Codex (`codex`). Direct socket bridges stream completions directly to your active buffer.
            </p>
            <Link href="/amoeba-coding" className="text-xs font-mono text-[#0055FF] hover:underline">
              Read Amoeba Coding Spec →
            </Link>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-xs font-mono text-[#555555]">
        <div className="max-w-[1280px] mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>© Code Crux Systems 2026. Built for high-velocity software engineering.</div>
          <div className="flex items-center gap-4">
            <Link href="/" className="hover:text-white">Home</Link>
            <Link href="/about" className="hover:text-white">About</Link>
            <Link href="/pricing" className="hover:text-white">Pricing</Link>
            <Link href="/blog" className="hover:text-white">Blog</Link>
            <Link href="/services" className="hover:text-white">Services</Link>
            <Link href="/docs" className="hover:text-white text-white">Docs</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
