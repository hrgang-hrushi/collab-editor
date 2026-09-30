import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Crux vs Cursor — Bare-Metal Rust & WebGPU vs Electron AI Wrapper",
  description:
    "Architectural comparison: Crux IDE vs Cursor. 4.2ms latency vs 52.1ms in Cursor, 38MB RAM vs 840MB, decentralized P2P AST-CRDT pair programming, and native local agent execution without cloud proxy lock-in.",
  keywords: [
    "Crux vs Cursor",
    "Cursor alternative",
    "Cursor AI vs Crux",
    "Crux IDE vs Cursor",
    "Cursor editor memory",
    "Cursor latency",
    "Amoeba coding Cursor",
    "Croc vs Cursor",
    "AI code editor comparison",
    "WebGPU vs Electron",
    "Rust AI code editor",
  ],
  alternates: {
    canonical: "https://codecrux.us/vs-cursor",
  },
  openGraph: {
    title: "Crux vs Cursor — Bare-Metal Rust & WebGPU vs Electron AI Wrapper",
    description:
      "Factual architectural comparison: Crux vs Cursor. 4.2ms input-to-photon latency vs 52.1ms, 38MB RAM vs 840MB, and native AST-CRDT pair programming.",
    url: "https://codecrux.us/vs-cursor",
    siteName: "Crux IDE",
    images: [
      {
        url: "https://codecrux.us/og-image.png",
        width: 1200,
        height: 630,
        alt: "Crux IDE vs Cursor Comparison",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux vs Cursor — Bare-Metal Rust vs Electron AI Wrapper",
    description:
      "4.2ms input-to-photon latency vs 52.1ms in Cursor, 38MB RAM vs 840MB, and decentralized AST-CRDT synchronization.",
    images: ["https://codecrux.us/og-image.png"],
  },
};

export default function VsCursorPage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "TechArticle",
        "@id": "https://codecrux.us/vs-cursor#article",
        "headline": "Crux IDE vs Cursor: Architectural & Performance Analysis",
        "description":
          "An objective, deep-dive comparison between Crux IDE and Cursor across latency, memory overhead, multiplayer synchronization, and AI integration architecture.",
        "author": {
          "@type": "Organization",
          "name": "Crux Systems",
          "url": "https://codecrux.us",
        },
        "publisher": {
          "@type": "Organization",
          "name": "Crux Systems",
          "url": "https://codecrux.us",
        },
        "datePublished": "2026-09-24",
        "dateModified": "2026-09-30",
        "mainEntityOfPage": "https://codecrux.us/vs-cursor",
      },
      {
        "@type": "FAQPage",
        "@id": "https://codecrux.us/vs-cursor#faq",
        "mainEntity": [
          {
            "@type": "Question",
            "name": "Is Crux faster than Cursor?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "Yes. Crux measures 4.2ms input-to-photon latency compared to 52.1ms in Cursor. Because Cursor is an Electron fork of VS Code, it renders every line of code inside the Chromium DOM and executes through the V8 JavaScript runtime. Crux compiles text tokens directly into GPU storage buffers via WebGPU and Metal compute shaders, achieving 120 FPS refresh with zero garbage collection freezes.",
            },
          },
          {
            "@type": "Question",
            "name": "How does memory consumption compare between Crux and Cursor?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "Crux consumes 38 MB at idle, whereas Cursor consumes 840 MB or more. Cursor runs multiple Chromium renderer helper processes, an internal Node.js extension host, and local indexing daemons. Crux is written in pure Rust with direct memory management, resulting in an 22x reduction in baseline RAM footprint.",
            },
          },
          {
            "@type": "Question",
            "name": "Does Cursor support real-time collaborative pair programming like Crux?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "Cursor does not provide native real-time peer-to-peer collaborative editing. Crux features a decentralized AST-CRDT engine running over encrypted WebRTC data channels, enabling instant multiplayer pair programming with spatial cursor presence and zero cloud servers.",
            },
          },
          {
            "@type": "Question",
            "name": "How do AI workflows differ between Crux and Cursor?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "Cursor routes user requests through centralized cloud proxies and custom Electron webviews. Crux provides an autonomous HyperTerminal powered by a native POSIX pseudo-terminal (PTY) that auto-discovers host-installed CLI agents (AntiGravity agy, Anthropic Claude Code, OpenAI Codex, OpenCode). Your proprietary code never leaves your local workstation unless you explicitly direct it.",
            },
          },
        ],
      },
      {
        "@type": "BreadcrumbList",
        "@id": "https://codecrux.us/vs-cursor#breadcrumbs",
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
            "name": "Crux vs Cursor",
            "item": "https://codecrux.us/vs-cursor",
          },
        ],
      },
    ],
  };

  return (
    <div
      className="min-h-screen bg-[#000000] text-white antialiased selection:bg-[#0055FF]/30 selection:text-white"
      style={{
        fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
      }}
    >
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
            <span className="text-[#0055FF] font-bold">COMPARISON // CRUX VS CURSOR</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/benchmarks" className="text-[#888888] hover:text-white no-underline uppercase">
              Benchmarks
            </Link>
            <Link href="/amoeba-coding" className="text-[#888888] hover:text-white no-underline uppercase">
              Amoeba Coding
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
            [ARCHITECTURAL AUDIT // BARE-METAL VS ELECTRON AI FORK]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal tracking-tight text-white leading-tight">
            Crux vs Cursor.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Cursor demonstrated the demand for AI assistance in code editing. But running an AI assistant inside a
            forked Electron browser creates an architectural dead end: bloated memory usage, 50ms+ input latency,
            cloud lock-in, and zero native peer-to-peer collaboration. Here is how Crux rebuilds the foundation.
          </p>
        </div>

        {/* 4 Contrast Metrics */}
        <section className="my-14 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">INPUT-TO-PHOTON</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">4.2ms vs 52.1ms</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Crux is 12.4x faster. Keystrokes bypass DOM recalculations entirely.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">IDLE MEMORY USAGE</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">38MB vs 840MB</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Crux is 22x leaner. Zero Chromium helper processes consuming your battery.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">REAL-TIME COLLABORATION</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">P2P AST-CRDT vs None</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Decentralized peer mesh synchronization without relying on cloud relays.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">AI INFRASTRUCTURE</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">Local PTY vs Cloud Proxy</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Direct OS execution for agy, Claude Code, and Codex with air-gap readiness.
            </div>
          </div>
        </section>

        {/* Feature Comparison Table */}
        <section className="my-14 border border-[#222222] overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#222222] bg-[#111114] text-[#888888]">
                <th className="p-4 uppercase">Core Dimension</th>
                <th className="p-4 uppercase text-[#0055FF] font-bold">Crux IDE</th>
                <th className="p-4 uppercase text-white">Cursor (Anysphere)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#222222] text-[#cccccc]">
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Core Runtime</td>
                <td className="p-4 text-[#0055FF] font-bold">Native Rust + WebGPU / Metal Compute</td>
                <td className="p-4">Electron + Chromium Blink + Node.js (VS Code Fork)</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Input Latency</td>
                <td className="p-4 text-[#0055FF] font-bold">4.2 ms (Sub-15ms guaranteed)</td>
                <td className="p-4">52.1 ms (Spikes to 140ms during heavy indexing)</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Multiplayer Sync Engine</td>
                <td className="p-4 text-[#0055FF] font-bold">P2P AST-CRDT over WebRTC (Zero Server)</td>
                <td className="p-4">No native real-time multiplayer pair programming</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Agent Integration Method</td>
                <td className="p-4 text-[#0055FF] font-bold">Native POSIX PTY auto-discovery ($PATH)</td>
                <td className="p-4">Proprietary cloud API wrapper &amp; chat sidebar</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Air-Gapped Operation</td>
                <td className="p-4 text-[#0055FF] font-bold">100% Air-Gapped ready (Zero Cloud Telemetry)</td>
                <td className="p-4">Requires cloud connection for primary features</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Monorepo Scroll Rate (250K Lines)</td>
                <td className="p-4 text-[#0055FF] font-bold">120 FPS phosphor refresh</td>
                <td className="p-4">16 FPS (Frequent DOM garbage collection stutter)</td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* Detailed Breakdown */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal text-white mb-6">
            The Fundamental Architectural Divide
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">1. Electron Fork vs Ground-Up Kernel</h3>
              <p className="text-[#888888] leading-relaxed">
                Cursor is built by patching Microsoft&apos;s open-source VS Code repository. It inherits the entire Chromium
                DOM stack, JavaScript event queues, and Node.js process orchestration. Crux was written from scratch in Rust.
                Every line of code is rendered directly on the GPU, yielding instant startup and fluid navigation.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">2. Chat Box vs Native HyperTerminal</h3>
              <p className="text-[#888888] leading-relaxed">
                Cursor concentrates AI into a sidebar chat box and inline diff overlays that often drop brackets or
                scramble indentations. Crux features the HyperTerminal: an integrated native PTY shell where CLI coding
                agents like AntiGravity (`agy`), Claude Code (`claude`), and OpenAI Codex operate directly on the
                filesystem and AST sockets with complete transparency.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">3. Zero Telemetry &amp; Air-Gapped Privacy</h3>
              <p className="text-[#888888] leading-relaxed">
                Modern enterprise teams cannot send proprietary algorithms through third-party cloud wrappers. Crux works
                with 100% offline isolation. You can connect local Ollama, vLLM, or self-hosted endpoint weights,
                maintaining strict security compliance with zero telemetry leakage.
              </p>
            </div>
          </div>
        </section>

        {/* FAQ Section */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal text-white mb-6">
            Frequently Asked Questions: Crux vs Cursor
          </h2>
          <div className="space-y-4">
            <div className="p-6 border border-[#222222] bg-[#08080a]">
              <h3 className="text-white font-semibold text-base mb-2">
                Can I migrate my keybindings and settings from Cursor to Crux?
              </h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Yes. Crux includes a 1-click migration daemon that imports your VS Code / Cursor keybindings, themes,
                and snippet collections into Crux&apos;s high-performance native format.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#08080a]">
              <h3 className="text-white font-semibold text-base mb-2">
                Can I use Claude 3.5 Sonnet, Gemini 1.5 Pro, and GPT-4o in Crux?
              </h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Yes. Crux supports all major foundation models either through host CLI tools (Claude Code, AntiGravity, Codex)
                or direct API keys configured in your private local environment.
              </p>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="my-14 p-8 border border-[#222222] bg-[#0c0c10] flex flex-col md:flex-row items-center justify-between gap-6">
          <div>
            <h2 className="text-2xl font-bold text-white mb-2">
              Switch from Bloated Electron to Bare Metal.
            </h2>
            <p className="text-xs text-[#888888] max-w-xl">
              Experience 4.2ms input-to-photon latency, 38MB RAM, and decentralized pair programming today.
            </p>
          </div>
          <Link
            href="/ide"
            className="px-6 py-3 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono text-xs font-bold uppercase no-underline rounded-none shrink-0"
          >
            Launch Crux Web IDE ↵
          </Link>
        </section>
      </main>

      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-center font-mono text-xs text-[#555555]">
        <div>Crux IDE · Bare-Metal Architecture vs Cursor · <Link href="/" className="text-[#0055FF] no-underline">Return to Overview</Link></div>
      </footer>
    </div>
  );
}
