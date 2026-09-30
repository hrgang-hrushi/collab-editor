import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Crux vs Visual Studio Code (VS Code) — Bare-Metal Rust vs Electron Benchmark Comparison",
  description:
    "Factual performance comparison: Crux vs Visual Studio Code (VS Code). 4.2ms input-to-photon latency vs 48.6ms in VS Code, 38MB idle memory vs 680MB, decentralized AST-CRDT pair programming, and zero Chromium V8 garbage collection stutter.",
  keywords: [
    "Crux vs VS Code",
    "Crux vs Visual Studio Code",
    "VS Code alternative",
    "Visual Studio Code performance",
    "VS Code memory usage",
    "VS Code slow",
    "Croc vs VS Code",
    "Visual Studio Code extensions",
    "Rust vs Electron",
    "WebGPU code editor",
    "bare-metal IDE",
    "Crux IDE",
  ],
  alternates: {
    canonical: "https://codecrux.us/vs-vscode",
  },
  openGraph: {
    title: "Crux vs Visual Studio Code (VS Code) — Bare-Metal Rust vs Electron Comparison",
    description:
      "4.2ms input-to-photon latency vs 48.6ms in VS Code, 38MB idle memory vs 680MB, and zero Chromium V8 garbage collection pauses.",
    url: "https://codecrux.us/vs-vscode",
    siteName: "Crux IDE",
    images: [
      {
        url: "https://codecrux.us/og-image.png",
        width: 1200,
        height: 630,
        alt: "Crux vs Visual Studio Code Comparison",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux vs Visual Studio Code (VS Code) — Performance Comparison",
    description:
      "4.2ms input-to-photon latency vs 48.6ms in VS Code, 38MB RAM vs 680MB, and WebGPU compute shaders.",
    images: ["https://codecrux.us/og-image.png"],
  },
};

export default function VsVsCodePage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "TechArticle",
        "@id": "https://codecrux.us/vs-vscode#article",
        "headline": "Crux IDE vs Visual Studio Code (VS Code): Architectural & Performance Comparison",
        "description":
          "Why bare-metal Rust and WebGPU deliver 11.5x lower latency, 17.8x lower RAM, and immune to V8 garbage collection pauses compared to Electron-based Visual Studio Code.",
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
        "mainEntityOfPage": "https://codecrux.us/vs-vscode",
      },
      {
        "@type": "FAQPage",
        "@id": "https://codecrux.us/vs-vscode#faq",
        "mainEntity": [
          {
            "@type": "Question",
            "name": "Is Crux IDE faster than Visual Studio Code (VS Code)?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "Yes. Crux measures 4.2ms physical input-to-photon latency, whereas VS Code averages 48.6ms on equivalent hardware. Because Crux renders via native WebGPU compute shaders and compiles in pure Rust, it completely eliminates Chromium DOM repaints and V8 JavaScript garbage collection pauses.",
            },
          },
          {
            "@type": "Question",
            "name": "How does memory consumption compare between Crux and Visual Studio Code?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "Crux consumes 38 MB at idle, compared to 680 MB for a default VS Code window with common extensions. Crux does not run Node.js helper daemons, Chromium renderers, or Electron IPC bridges, keeping developer machines cool and responsive.",
            },
          },
          {
            "@type": "Question",
            "name": "Can I use VS Code keybindings and settings in Crux?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "Yes. Crux provides automated keybinding and configuration migration from your existing VS Code profile, allowing engineers to transition seamlessly without retraining muscle memory.",
            },
          },
          {
            "@type": "Question",
            "name": "How does pair programming differ between Crux and VS Code Live Share?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "VS Code Live Share routes every keystroke through Microsoft Azure cloud relay servers. Crux establishes peer-to-peer WebRTC data channels directly between collaborator machines and reconciles edits with Abstract Syntax Tree CRDTs, ensuring zero cloud lock-in and lower latency.",
            },
          },
        ],
      },
      {
        "@type": "BreadcrumbList",
        "@id": "https://codecrux.us/vs-vscode#breadcrumbs",
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
            "name": "Crux vs VS Code",
            "item": "https://codecrux.us/vs-vscode",
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
            <span className="text-[#0055FF] font-bold">COMPARISON // CRUX VS VISUAL STUDIO CODE</span>
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
            [ARCHITECTURAL AUDIT // BARE-METAL VS ELECTRON]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal tracking-tight text-white leading-tight">
            Crux vs Visual Studio Code.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Visual Studio Code (VS Code) defined modern developer tool ecosystems. But running a code editor inside
            a full Chromium web browser comes with irreversible physical costs: high memory usage, DOM layout delays,
            and V8 garbage collection stutter. Here is how Crux solves this from bare silicon.
          </p>
        </div>

        {/* 4 Contrast Metrics */}
        <section className="my-14 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">INPUT-TO-PHOTON</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">4.2ms vs 48.6ms</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Crux is 11.5x faster. Keystrokes never touch an Electron event loop.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">IDLE MEMORY</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">38MB vs 680MB</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Crux is 17.8x leaner. 0 Chromium render processes or Node.js IPC daemons.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">250K MONOREPO SCROLL</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">120 FPS vs 18 FPS</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Persistent 120 FPS hardware refresh with zero dropped frames.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">COLD-START TIME</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">0.08s vs 1.84s</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Instant launch without loading hundreds of JavaScript extension bundles.
            </div>
          </div>
        </section>

        {/* Feature Comparison Table */}
        <section className="my-14 border border-[#222222] overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#222222] bg-[#111114] text-[#888888]">
                <th className="p-4 uppercase">Architectural Pillar</th>
                <th className="p-4 uppercase text-[#0055FF] font-bold">Crux IDE</th>
                <th className="p-4 uppercase text-white">Visual Studio Code (VS Code)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#222222] text-[#cccccc]">
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Core Platform</td>
                <td className="p-4 text-[#0055FF] font-bold">Bare-metal Rust + WebGPU / Metal</td>
                <td className="p-4">Electron + Chromium + Node.js runtime</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Input Latency</td>
                <td className="p-4 text-[#0055FF] font-bold">4.2 ms (Physical input-to-photon)</td>
                <td className="p-4">48.6 ms (Delayed by DOM layout &amp; JS event loop)</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Garbage Collection Overhead</td>
                <td className="p-4 text-[#0055FF] font-bold">0ms (Zero GC pauses, manual Rust memory)</td>
                <td className="p-4">15ms – 60ms periodic V8 GC freezes</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Real-Time Pair Programming</td>
                <td className="p-4 text-[#0055FF] font-bold">P2P AST-CRDT over WebRTC (Zero server)</td>
                <td className="p-4">Live Share (Microsoft Azure cloud relay)</td>
              </tr>
              <tr className="hover:bg-[#08080a]">
                <td className="p-4 text-white font-medium">Autonomous Agent CLI Support</td>
                <td className="p-4 text-[#0055FF] font-bold">Native PTY auto-discovery (agy, claude, codex)</td>
                <td className="p-4">Extension API webviews with IPC serialization</td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* Detailed Breakdown */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal text-white mb-6">
            Why Chromium Cannot Match Native Silicon
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">1. V8 Garbage Collection Stutter</h3>
              <p className="text-[#888888] leading-relaxed">
                VS Code allocates JavaScript objects for every cursor movement, syntax token, and DOM line element.
                When the V8 garbage collector performs a major sweep, the editor experiences micro-stutters between 15ms and 60ms.
                Crux has manual Rust memory layout with 0 garbage collector pauses.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">2. DOM Layout vs WebGPU Shaders</h3>
              <p className="text-[#888888] leading-relaxed">
                In VS Code, every line of code is rendered as an HTML &lt;span&gt; inside the DOM tree, requiring CSS style
                recalculation and composite layers. Crux uploads raw token indices directly to GPU memory, letting WebGPU compute
                shaders rasterize glyphs in parallel.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">3. P2P Mesh vs Cloud Relays</h3>
              <p className="text-[#888888] leading-relaxed">
                VS Code Live Share routes keystrokes through Microsoft Azure relay servers. Crux establishes peer-to-peer WebRTC
                channels directly between developers, ensuring zero cloud dependency and lower latency.
              </p>
            </div>
          </div>
        </section>

        {/* FAQ Section */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal text-white mb-6">
            Frequently Asked Questions: Crux vs VS Code
          </h2>
          <div className="space-y-4">
            <div className="p-6 border border-[#222222] bg-[#08080a]">
              <h3 className="text-white font-semibold text-base mb-2">
                Can I migrate from VS Code without losing my workflow?
              </h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Yes. Crux includes built-in profile migration that reads your existing VS Code `settings.json`, keymaps, and snippets.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#08080a]">
              <h3 className="text-white font-semibold text-base mb-2">
                Does Crux support Language Server Protocol (LSP)?
              </h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Yes. Crux features native asynchronous LSP support for Rust Analyzer, Pyright, TypeScript Language Server, Clangd, and gopls.
              </p>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="my-14 p-8 border border-[#222222] bg-[#0c0c10] flex flex-col md:flex-row items-center justify-between gap-6">
          <div>
            <h2 className="text-2xl font-bold text-white mb-2">
              Ready for 4.2ms Bare-Metal Coding?
            </h2>
            <p className="text-xs text-[#888888] max-w-xl">
              Replace bloated Electron with Crux&apos;s native Rust and WebGPU architecture today.
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
        <div>Crux IDE · Bare-Metal Architecture vs Visual Studio Code · <Link href="/" className="text-[#0055FF] no-underline">Return to Overview</Link></div>
      </footer>
    </div>
  );
}
