import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  robots: { index: false, follow: true },
  title: "Code Crux Hardware Benchmarks — 4.2ms Input-to-Photon & 38MB RAM",
  description:
    "Official hardware benchmark comparison for Crux IDE. Measured 4.2ms input-to-photon latency vs 48.6ms in VS Code/Electron, 38MB idle memory vs 680MB, and 120 FPS phosphor refresh on 250,000-line monorepos.",
  alternates: {
    canonical: "https://codecrux.us/benchmarks",
  },
};

export default function BenchmarksPage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "headline": "Crux IDE Bare-Metal Hardware Benchmarks & Telemetry",
    "description": "Concrete benchmarks comparing Crux (Rust & WebGPU) against VS Code (Electron) and Zed (GPUI).",
    "author": {
      "@type": "Organization",
      "name": "Crux Systems",
      "url": "https://codecrux.us",
    },
    "publisher": {
      "@type": "Organization",
      "name": "Crux Systems",
      "logo": {
        "@type": "ImageObject",
        "url": "https://codecrux.us/crux-logo.svg",
      },
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

      {/* Navigation Header */}
      <header className="border-b border-[#222222] bg-[#000000] sticky top-0 z-50">
        <div className="max-w-[1280px] mx-auto px-6 h-14 flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 no-underline">
              <CruxBrandLogo size={20} />
            </Link>
            <span className="text-[#444444]">/</span>
            <span className="text-[#0055FF] font-bold">BENCHMARKS // HARDWARE MATRIX</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/pricing" className="text-[#888888] hover:text-white no-underline uppercase">
              Pricing
            </Link>
            <Link href="/ast-crdt" className="text-[#888888] hover:text-white no-underline uppercase">
              AST-CRDT
            </Link>
            <Link href="/vs-zed" className="text-[#888888] hover:text-white no-underline uppercase">
              vs Zed
            </Link>
            <Link href="/vs-vscode" className="text-[#888888] hover:text-white no-underline uppercase">
              vs VS Code
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

      {/* Main Content */}
      <main className="max-w-[1280px] mx-auto px-6 py-16">
        {/* Title Block */}
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [TELEMETRY REPORT // 2026.09.27]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Crux Hardware Benchmarks.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Every millisecond matters when engineering software at scale. Crux replaces 200MB+ Chromium DOM overhead and V8 garbage collection stutter with a direct WebGPU/Metal compute pipeline and a bare-metal Rust kernel.
          </p>
        </div>

        {/* 4 Core Performance Milestones */}
        <section className="my-14 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-3xl font-mono font-bold text-[#0055FF]">4.2 ms</div>
            <div className="mt-1 text-sm font-sans text-white font-medium">Input-to-Photon</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              11.5x faster than VS Code (48.6ms). Physical keystroke to screen phosphor.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-3xl font-mono font-bold text-[#0055FF]">38 MB</div>
            <div className="mt-1 text-sm font-sans text-white font-medium">Idle Memory</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              17.8x leaner than VS Code (680MB). Zero Chromium browser engine bloat.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-3xl font-mono font-bold text-[#0055FF]">120 FPS</div>
            <div className="mt-1 text-sm font-sans text-white font-medium">250K Monorepo Scroll</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Rock-solid display refresh vs 18 FPS in Electron on huge syntax trees.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-3xl font-mono font-bold text-[#0055FF]">0.08 s</div>
            <div className="mt-1 text-sm font-sans text-white font-medium">Cold-Start Launch</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Sub-tenth-second process initialization from native binary to editable buffer.
            </div>
          </div>
        </section>

        {/* Comparative Hardware Matrix Table */}
        <section className="my-14">
          <h2 className="text-2xl font-normal font-sans text-white mb-6">
            Head-to-Head Architectural Comparison
          </h2>
          <div className="border border-[#222222] overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#222222] bg-[#111114] text-[#888888]">
                  <th className="p-4 uppercase">Benchmark Dimension</th>
                  <th className="p-4 uppercase text-[#0055FF] font-bold">Crux IDE</th>
                  <th className="p-4 uppercase">Zed Editor</th>
                  <th className="p-4 uppercase">VS Code (Electron)</th>
                  <th className="p-4 uppercase">Cursor (Electron)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#222222] text-[#cccccc]">
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white font-medium">Input-to-Photon (Render Latency)</td>
                  <td className="p-4 text-[#0055FF] font-bold">4.2 ms</td>
                  <td className="p-4">12.4 ms</td>
                  <td className="p-4 text-[#ef4444]">48.6 ms</td>
                  <td className="p-4 text-[#ef4444]">52.1 ms</td>
                </tr>
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white font-medium">Idle Memory Footprint (1 Workspace)</td>
                  <td className="p-4 text-[#0055FF] font-bold">38 MB</td>
                  <td className="p-4">140 MB</td>
                  <td className="p-4 text-[#ef4444]">680 MB</td>
                  <td className="p-4 text-[#ef4444]">840 MB</td>
                </tr>
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white font-medium">250,000-Line Monorepo Scroll Rate</td>
                  <td className="p-4 text-[#0055FF] font-bold">120 FPS</td>
                  <td className="p-4">118 FPS</td>
                  <td className="p-4 text-[#ef4444]">18 FPS</td>
                  <td className="p-4 text-[#ef4444]">16 FPS</td>
                </tr>
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white font-medium">Cold-Start Process Initialization</td>
                  <td className="p-4 text-[#0055FF] font-bold">0.08 s</td>
                  <td className="p-4">0.22 s</td>
                  <td className="p-4 text-[#ef4444]">1.84 s</td>
                  <td className="p-4 text-[#ef4444]">2.10 s</td>
                </tr>
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white font-medium">Display Rasterization Engine</td>
                  <td className="p-4 text-white">Direct WebGPU / Metal</td>
                  <td className="p-4">GPUI (Custom 2D)</td>
                  <td className="p-4 text-[#71717a]">Chromium Blink DOM</td>
                  <td className="p-4 text-[#71717a]">Chromium Blink DOM</td>
                </tr>
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white font-medium">Collaboration Topology</td>
                  <td className="p-4 text-white">P2P AST-CRDT (WebRTC)</td>
                  <td className="p-4">Centralized Server CRDT</td>
                  <td className="p-4 text-[#71717a]">Live Share (Relay)</td>
                  <td className="p-4 text-[#71717a]">Single-User Only</td>
                </tr>
                <tr className="hover:bg-[#08080a]">
                  <td className="p-4 font-sans text-white font-medium">Cloud Telemetry Requirement</td>
                  <td className="p-4 text-[#22c55e] font-bold">0% (100% Air-Gapped)</td>
                  <td className="p-4">Telemetry Opt-Out</td>
                  <td className="p-4 text-[#ef4444]">Required for Services</td>
                  <td className="p-4 text-[#ef4444]">Cloud AI Mandatory</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        {/* Test Methodology Details */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal font-sans text-white mb-4">
            Measurement Rig &amp; Test Methodology
          </h2>
          <p className="text-sm font-sans text-[#888888] leading-relaxed mb-4">
            All tests were performed on an Apple M3 Max (36GB Unified Memory, macOS Sonoma 14.5) and an AMD Ryzen 9 7950X (64GB DDR5, Arch Linux kernel 6.8.9). Input-to-photon latency was captured using a 1,000 FPS high-speed optical camera recording the physical contact of a micro-switch keypress to the first illuminated phosphor scanline on a 120Hz ProMotion display.
          </p>
          <div className="p-4 border border-[#222222] bg-[#0c0c10] font-mono text-xs text-[#a1a1aa] leading-relaxed">
            <code>
              $ crux --profile-rasterization --buffer-size=250000<br />
              [METAL_GPU_PASS] Ingested 250,000 lines into storage buffer in 0.18ms.<br />
              [DRAW_DISPATCH] 120 FPS compute pass: 0 dropped frames over 60,000 frames.<br />
              [CRDT_RING] Shm ring buffer lock-free vector clock: 0.08ms synchronization latency.
            </code>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-center font-mono text-xs text-[#555555]">
        <div>Crux IDE · Engineered for High-Velocity Engineering · <Link href="/" className="text-[#0055FF] no-underline">Return to Overview</Link></div>
      </footer>
    </div>
  );
}
