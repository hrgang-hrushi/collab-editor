import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "About Code Crux (Crux IDE) — Mission, Architecture & Engineering Team",
  description:
    "Learn about Code Crux (Crux IDE, https://codecrux.us), our mission to liberate software engineering from Electron memory bloat, our bare-metal Rust and WebGPU compute architecture, and our local-first AI engineering vision.",
  keywords: [
    "About Code Crux",
    "About CodeCrux",
    "Code Crux",
    "CodeCrux",
    "Crux IDE team",
    "Crux founding story",
    "bare-metal IDE mission",
    "codecrux.us about",
    "Code Crux Systems",
    "Rust WebGPU IDE",
  ],
  alternates: {
    canonical: "https://codecrux.us/about",
  },
  openGraph: {
    type: "website",
    url: "https://codecrux.us/about",
    title: "About Code Crux — Bare-Metal Systems Engineering",
    description:
      "Code Crux is engineered from raw silicon up to deliver sub-15ms latency, 38MB memory footprint, and decentralized AST-CRDT real-time sync.",
    siteName: "Code Crux (Crux IDE)",
  },
};

export default function AboutPage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "AboutPage",
    "@id": "https://codecrux.us/about#webpage",
    "url": "https://codecrux.us/about",
    "name": "About Code Crux (Crux IDE)",
    "description":
      "Learn about Code Crux, the bare-metal collaborative code editor engineered in Rust with direct WebGPU and Metal compute shaders.",
    "mainEntity": {
      "@type": "Organization",
      "@id": "https://codecrux.us/#organization",
      "name": "Code Crux Systems",
      "alternateName": ["Code Crux", "CodeCrux", "Crux IDE", "Crux Systems"],
      "url": "https://codecrux.us",
      "logo": "https://codecrux.us/crux-icon.png",
      "foundingDate": "2024",
      "founders": [
        {
          "@type": "Person",
          "name": "Hrushikesh Gangala",
          "jobTitle": "Chief Architect & Founder",
        },
      ],
      "sameAs": [
        "https://github.com/hrgang-hrushi/collab-editor",
        "https://x.com/codecrux",
        "https://discord.gg/codecrux",
      ],
      "contactPoint": {
        "@type": "ContactPoint",
        "email": "core@codecrux.us",
        "contactType": "technical support",
        "availableLanguage": "English",
      },
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
          "name": "About",
          "item": "https://codecrux.us/about",
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
            <span className="text-[#0055FF] font-bold">ABOUT // MISSION &amp; ARCHITECTURE</span>
          </div>
          <nav className="flex items-center gap-4">
            <Link href="/pricing" className="text-[#888888] hover:text-white no-underline uppercase">
              Pricing
            </Link>
            <Link href="/blog" className="text-[#888888] hover:text-white no-underline uppercase">
              Blog
            </Link>
            <Link href="/services" className="text-[#888888] hover:text-white no-underline uppercase">
              Services
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

      {/* Hero Section */}
      <main className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [ORIGIN MANIFESTO // BARE-METAL COMPUTING]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Engineered from Raw Silicon.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Code Crux (Crux IDE) was founded to dismantle the era of sluggish Electron text wrappers. We build
            high-velocity developer tools grounded in Rust, direct WebGPU and Metal compute pipelines, decentralized
            AST-CRDT synchronization, and autonomous local AI agents.
          </p>
        </div>

        {/* Core Principles Grid */}
        <section className="py-12 border-b border-[#222222]">
          <h2 className="text-xs font-mono text-[#888888] uppercase tracking-wider mb-8">
            01 // CORE AXIOMS OF CODE CRUX
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="border border-[#222222] bg-[#0c0c0e] p-6 rounded-none">
              <div className="text-xs font-mono text-[#0055FF] mb-2 font-bold">[AXIOM 01]</div>
              <h3 className="text-lg font-medium text-white mb-3">Sub-15ms Input-to-Photon</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Key presses must never queue behind a V8 garbage collection sweep or DOM reflow pass. By compiling
                directly to GPU compute storage buffers, keystrokes paint in 4.2ms on modern 120Hz displays.
              </p>
            </div>

            <div className="border border-[#222222] bg-[#0c0c0e] p-6 rounded-none">
              <div className="text-xs font-mono text-[#0055FF] mb-2 font-bold">[AXIOM 02]</div>
              <h3 className="text-lg font-medium text-white mb-3">Decentralized AST Integrity</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Code is not flat text lines; it is an Abstract Syntax Tree. Our AST-CRDT engine replicates structural
                AST nodes over encrypted WebRTC peer meshes without central cloud lock-in or character offset drift.
              </p>
            </div>

            <div className="border border-[#222222] bg-[#0c0c0e] p-6 rounded-none">
              <div className="text-xs font-mono text-[#0055FF] mb-2 font-bold">[AXIOM 03]</div>
              <h3 className="text-lg font-medium text-white mb-3">Air-Gapped Sovereign AI</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Developer code is proprietary intellectual property. Crux executes AI agent workflows on host
                silicon and local POSIX sockets with zero non-consensual telemetry sent to centralized servers.
              </p>
            </div>
          </div>
        </section>

        {/* Founding & Architecture Story */}
        <section className="py-12 border-b border-[#222222] grid grid-cols-1 lg:grid-cols-12 gap-10">
          <div className="lg:col-span-4">
            <h2 className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
              02 // THE PROBLEM
            </h2>
            <div className="text-2xl font-normal text-white">Why We Built Code Crux</div>
          </div>
          <div className="lg:col-span-8 text-sm text-[#aaaaaa] space-y-4 leading-relaxed">
            <p>
              In 2015, the software engineering industry traded mechanical performance for web convenience. Text editors
              became Chromium browser instances running JavaScript interpreters. Today, modern IDEs routinely consume
              800MB to 1.5GB of RAM at idle, stutter when scrolling through 200k-line monorepos, and lock teams into
              fragile cloud subscription servers.
            </p>
            <p>
              When autonomous coding agents (Claude Code, Google Gemini, OpenAI Codex) emerged, this foundation cracked.
              Multi-agent swarms streaming thousands of tokens per second overwhelm traditional character-based editors,
              producing syntax drift, broken bracket pairs, and UI freezing.
            </p>
            <p>
              Code Crux replaces this legacy stack with a native Rust memory model, lock-free ring buffers, and
              direct WebGPU shader pipelines. The result is an editor that launches in 0.08 seconds, idles at 38MB of
              RAM, and enables instantaneous peer-to-peer collaboration across global engineering teams.
            </p>
          </div>
        </section>

        {/* Company & Support Information */}
        <section className="py-12 grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="border border-[#222222] p-8 bg-[#0a0a0c]">
            <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
              [HEADQUARTERS &amp; OPERATING DETAILS]
            </div>
            <h3 className="text-xl font-medium text-white mb-4">Code Crux Systems</h3>
            <div className="space-y-3 text-xs font-mono text-[#888888]">
              <div><strong className="text-white">Primary Domain:</strong> https://codecrux.us</div>
              <div><strong className="text-white">Headquarters:</strong> San Francisco, California &amp; Global Distributed Mesh</div>
              <div><strong className="text-white">Inquiries:</strong> core@codecrux.us</div>
              <div><strong className="text-white">Open Source Repo:</strong> github.com/hrgang-hrushi/collab-editor</div>
              <div><strong className="text-white">License Model:</strong> Dual-licensed (Community Open Engine / Enterprise Air-Gapped)</div>
            </div>
          </div>

          <div className="border border-[#222222] p-8 bg-[#0a0a0c]">
            <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
              [EXPLORE ARCHITECTURAL MODULES]
            </div>
            <h3 className="text-xl font-medium text-white mb-4">Deep Technical Documentation</h3>
            <ul className="space-y-2 text-xs font-mono text-[#0055FF]">
              <li><Link href="/pricing" className="hover:underline">Transparent Per-Seat &amp; Air-Gapped Pricing →</Link></li>
              <li><Link href="/blog" className="hover:underline">Code Crux Engineering Blog &amp; Research →</Link></li>
              <li><Link href="/services" className="hover:underline">Enterprise Air-Gapped &amp; Custom Relay Services →</Link></li>
              <li><Link href="/benchmarks" className="hover:underline">Measured Hardware Benchmarks Matrix →</Link></li>
              <li><Link href="/ast-crdt" className="hover:underline">Decentralized AST-CRDT Protocol Whitepaper →</Link></li>
              <li><Link href="/amoeba-coding" className="hover:underline">Amoeba Coding: Multi-Agent Mutation Architecture →</Link></li>
              <li><Link href="/vs-cursor" className="hover:underline">Crux vs Cursor: Technical Comparison →</Link></li>
            </ul>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-xs font-mono text-[#555555]">
        <div className="max-w-[1280px] mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>© Code Crux Systems 2026. Built for high-velocity software engineering.</div>
          <div className="flex items-center gap-4">
            <Link href="/" className="hover:text-white">Home</Link>
            <Link href="/about" className="hover:text-white text-white">About</Link>
            <Link href="/pricing" className="hover:text-white">Pricing</Link>
            <Link href="/blog" className="hover:text-white">Blog</Link>
            <Link href="/services" className="hover:text-white">Services</Link>
            <Link href="/llms.txt" className="hover:text-white">llms.txt</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
