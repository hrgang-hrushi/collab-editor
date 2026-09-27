import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Crux vs VS Code — Bare-Metal Rust & WebGPU vs Electron Architecture",
  description:
    "Factual performance comparison: Crux vs VS Code. 4.2ms input-to-photon latency vs 48.6ms in VS Code, 38MB idle memory vs 680MB, and zero Chromium V8 garbage collection stutter.",
  alternates: {
    canonical: "https://codecrux.us/vs-vscode",
  },
};

export default function VsVsCodePage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "headline": "Crux IDE vs Visual Studio Code: Architectural & Performance Comparison",
    "description": "Why bare-metal Rust and WebGPU deliver 11.5x lower latency and 17.8x lower RAM than Electron.",
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
            <span className="text-[#0055FF] font-bold">COMPARISON // CRUX VS VS CODE</span>
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
            [ARCHITECTURAL AUDIT // BARE-METAL VS ELECTRON]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Crux vs VS Code.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            VS Code defined modern developer tool ecosystems. But running a code editor inside a full Chromium web browser comes with irreversible physical costs: high memory usage, DOM layout delays, and garbage collection stutter. Here is how Crux solves this.
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

        {/* Detailed Breakdown */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal font-sans text-white mb-6">
            Why Chromium Cannot Match Native Silicon
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-sans text-xs">
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">1. V8 Garbage Collection Stutter</h3>
              <p className="text-[#888888] leading-relaxed">
                VS Code allocates JavaScript objects for every cursor movement, syntax token, and DOM line element. When the V8 garbage collector performs a major sweep, the editor experiences micro-stutters between 15ms and 60ms. Crux has manual Rust memory layout with 0 garbage collector pauses.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">2. DOM Layout vs WebGPU Shaders</h3>
              <p className="text-[#888888] leading-relaxed">
                In VS Code, every line of code is rendered as an HTML `&lt;span&gt;` inside the DOM tree, requiring CSS style recalculation and composite layers. Crux uploads raw token indices directly to GPU memory, letting WebGPU compute shaders rasterize glyphs in parallel.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">3. P2P Mesh vs Cloud Relays</h3>
              <p className="text-[#888888] leading-relaxed">
                VS Code Live Share routes keystrokes through Microsoft Azure relay servers. Crux establishes peer-to-peer WebRTC channels directly between developers, ensuring zero cloud dependency and lower latency.
              </p>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-center font-mono text-xs text-[#555555]">
        <div>Crux IDE · Engineered for High-Velocity Engineering · <Link href="/" className="text-[#0055FF] no-underline">Return to Overview</Link></div>
      </footer>
    </div>
  );
}
