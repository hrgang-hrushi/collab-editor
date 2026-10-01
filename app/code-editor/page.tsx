import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Code Editor — Free Native & Online Collaborative Code Editor | Code Crux",
  description:
    "Looking for a code editor? Code Crux is the ultra-fast bare-metal code editor built in Rust with direct WebGPU hardware acceleration, 4.2ms input-to-photon latency, 38MB idle memory, and decentralized AST-CRDT real-time sync. Run code online or on macOS, Linux, and Windows.",
  keywords: [
    "code editor",
    "code",
    "online code editor",
    "best code editor",
    "free code editor",
    "code editor for mac",
    "code editor for linux",
    "code editor for windows",
    "collaborative code editor",
    "rust code editor",
    "webgpu code editor",
    "fastest code editor",
    "Code Crux",
    "Crux IDE",
    "codecrux.us",
  ],
  alternates: {
    canonical: "https://codecrux.us/code-editor",
  },
  openGraph: {
    type: "website",
    url: "https://codecrux.us/code-editor",
    title: "Code Editor — Free Native & Online Collaborative Editor | Code Crux",
    description:
      "Sub-15ms latency, 38MB memory footprint, and decentralized P2P real-time sync. Built from raw silicon for programmers.",
    siteName: "Code Crux (Crux IDE)",
  },
};

export default function CodeEditorPage() {
  const comparisons = [
    {
      metric: "Input-to-Photon Latency",
      crux: "4.2 ms",
      vscode: "48.6 ms",
      cursor: "52.1 ms",
      zed: "12.4 ms",
      winner: "Crux (11.5x faster)",
    },
    {
      metric: "Idle Memory Consumption",
      crux: "38 MB",
      vscode: "680 MB",
      cursor: "840 MB",
      zed: "140 MB",
      winner: "Crux (17.8x leaner)",
    },
    {
      metric: "250,000-Line Scroll Rate",
      crux: "120 FPS",
      vscode: "18 FPS",
      cursor: "16 FPS",
      zed: "118 FPS",
      winner: "Crux (Consistent 120 FPS)",
    },
    {
      metric: "Cold Start Launch Time",
      crux: "0.08 s",
      vscode: "1.84 s",
      cursor: "2.10 s",
      zed: "0.22 s",
      winner: "Crux (Near-instant)",
    },
    {
      metric: "Real-Time Collaboration",
      crux: "P2P WebRTC AST-CRDT",
      vscode: "Cloud Live Share",
      cursor: "Single User",
      zed: "Central Server CRDT",
      winner: "Crux (100% Serverless)",
    },
    {
      metric: "Telemetry & Air-Gap",
      crux: "0% Telemetry (Air-Gapped)",
      vscode: "Telemetry Required",
      cursor: "Cloud AI Required",
      zed: "Telemetry Opt-Out",
      winner: "Crux (100% Sovereign)",
    },
  ];

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "ItemPage",
    "@id": "https://codecrux.us/code-editor#webpage",
    "url": "https://codecrux.us/code-editor",
    "name": "Code Editor — Free Native & Online Collaborative Code Editor | Code Crux",
    "description":
      "Code Crux is the ultra-fast native and online collaborative code editor engineered in Rust with direct WebGPU acceleration.",
    "about": [
      { "@type": "Thing", "name": "Code Editor" },
      { "@type": "Thing", "name": "Code" },
      { "@type": "Thing", "name": "Source Code Editor" },
      { "@type": "Thing", "name": "Integrated Development Environment" },
    ],
    "mainEntity": {
      "@type": "SoftwareApplication",
      "name": "Code Crux Code Editor",
      "applicationCategory": "DeveloperApplication",
      "operatingSystem": "macOS, Linux, Windows, Web",
      "offers": {
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD",
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
          "name": "Code Editor",
          "item": "https://codecrux.us/code-editor",
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
            <span className="text-[#0055FF] font-bold">CODE EDITOR // BENCHMARKS &amp; ARCHITECTURE</span>
          </div>
          <nav className="flex items-center gap-4">
            <Link href="/code" className="text-[#888888] hover:text-white no-underline uppercase">
              Code Online
            </Link>
            <Link href="/pricing" className="text-[#888888] hover:text-white no-underline uppercase">
              Pricing
            </Link>
            <Link href="/benchmarks" className="text-[#888888] hover:text-white no-underline uppercase">
              Benchmarks
            </Link>
            <Link
              href="/ide"
              className="px-3 py-1.5 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold uppercase no-underline rounded-none"
            >
              LAUNCH EDITOR ↵
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <main className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [THE NEXT-GENERATION BARE-METAL CODE EDITOR]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            The Code Editor Built from Raw Silicon.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Code Crux is engineered specifically to eliminate the 50ms latency lag and multi-gigabyte memory consumption of Electron code editors.
            Combining a Rust kernel with direct WebGPU compute shaders and decentralized AST-CRDT real-time sync, it delivers the most responsive coding experience in the world.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-4">
            <Link
              href="/ide"
              className="px-6 py-3 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold text-xs uppercase no-underline inline-block rounded-none"
            >
              LAUNCH IN BROWSER ↵
            </Link>
            <Link
              href="/vs-vscode"
              className="px-6 py-3 border border-[#333333] hover:border-white text-white font-mono text-xs uppercase no-underline inline-block rounded-none bg-[#0a0a0c]"
            >
              COMPARE VS CODE
            </Link>
            <Link
              href="/vs-cursor"
              className="px-6 py-3 border border-[#333333] hover:border-white text-white font-mono text-xs uppercase no-underline inline-block rounded-none bg-[#0a0a0c]"
            >
              COMPARE CURSOR
            </Link>
          </div>
        </div>

        {/* Comparison Matrix Table */}
        <section className="py-12 border-b border-[#222222]">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            01 // CODE EDITOR BENCHMARK MATRIX
          </div>
          <h2 className="text-2xl font-normal text-white mb-6">
            Crux vs Traditional Code Editors
          </h2>
          <div className="overflow-x-auto border border-[#222222]">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-[#111111] text-[#888888] border-b border-[#222222]">
                <tr>
                  <th className="p-3.5">METRIC</th>
                  <th className="p-3.5 text-white font-bold bg-[#161616]">CRUX</th>
                  <th className="p-3.5">VS CODE</th>
                  <th className="p-3.5">CURSOR</th>
                  <th className="p-3.5">ZED</th>
                  <th className="p-3.5 text-[#0055FF]">VERDICT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#222222]">
                {comparisons.map((row, idx) => (
                  <tr key={idx} className="hover:bg-[#0a0a0c]">
                    <td className="p-3.5 text-white font-medium">{row.metric}</td>
                    <td className="p-3.5 text-white font-bold bg-[#0d0d0f] text-[#0055FF]">{row.crux}</td>
                    <td className="p-3.5 text-[#888888]">{row.vscode}</td>
                    <td className="p-3.5 text-[#888888]">{row.cursor}</td>
                    <td className="p-3.5 text-[#888888]">{row.zed}</td>
                    <td className="p-3.5 text-[#22c55e] font-semibold">{row.winner}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Feature Columns */}
        <section className="py-12 border-b border-[#222222]">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            02 // CORE CODE EDITOR CAPABILITIES
          </div>
          <h2 className="text-2xl font-normal text-white mb-8">
            Why Engineers Choose Code Crux
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="border border-[#222222] bg-[#0c0c0e] p-6 rounded-none">
              <h3 className="text-lg font-medium text-white mb-2">Native WebGPU Shaders</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Text rendering, cursor motion, and syntax parsing execute in parallel on the GPU at 120 FPS.
                No dropped frames, even on multi-million line files.
              </p>
            </div>
            <div className="border border-[#222222] bg-[#0c0c0e] p-6 rounded-none">
              <h3 className="text-lg font-medium text-white mb-2">AST-CRDT Pair Coding</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Collaborate in real-time over direct WebRTC peer connections. Synchronizes structural Abstract Syntax Tree nodes to completely prevent syntax invalidation.
              </p>
            </div>
            <div className="border border-[#222222] bg-[#0c0c0e] p-6 rounded-none">
              <h3 className="text-lg font-medium text-white mb-2">Autonomous AI Integration</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Connect Claude Code, Google Gemini, and OpenAI Codex through local POSIX sockets with zero API proxy delays or cloud tracking.
              </p>
            </div>
          </div>
        </section>

        {/* Deep Links */}
        <section className="py-12">
          <div className="border border-[#222222] bg-[#0c0c0e] p-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div>
              <div className="text-xs font-mono text-[#0055FF] font-bold mb-1">[GET STARTED]</div>
              <h3 className="text-2xl font-medium text-white mb-2">Experience the fastest code editor today</h3>
              <p className="text-xs text-[#888888] max-w-xl leading-relaxed">
                Launch directly in your browser or explore our transparent pricing for teams and air-gapped enterprise deployments.
              </p>
            </div>
            <div className="flex items-center gap-3 font-mono text-xs">
              <Link
                href="/code"
                className="px-5 py-2.5 bg-[#0055FF] hover:bg-[#0044CC] text-white uppercase no-underline font-bold rounded-none"
              >
                Code Online ↵
              </Link>
              <Link
                href="/pricing"
                className="px-5 py-2.5 border border-[#333333] hover:border-white text-white uppercase no-underline bg-[#111111] rounded-none"
              >
                Pricing Plans
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-xs font-mono text-[#555555]">
        <div className="max-w-[1280px] mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>© Code Crux Systems 2026. Built for high-velocity software engineering.</div>
          <div className="flex items-center gap-4">
            <Link href="/" className="hover:text-white">Home</Link>
            <Link href="/code" className="hover:text-white">Code Online</Link>
            <Link href="/code-editor" className="hover:text-white text-white">Code Editor</Link>
            <Link href="/benchmarks" className="hover:text-white">Benchmarks</Link>
            <Link href="/pricing" className="hover:text-white">Pricing</Link>
            <Link href="/docs" className="hover:text-white">Docs</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
