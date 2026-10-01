import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Code Crux Engineering Blog — Systems Research, AST-CRDT & Local AI",
  description:
    "Technical research and engineering blog from Code Crux Systems: Deep-dives into AST-CRDT distributed consensus, WebGPU compute shader rasterization, Amoeba coding multi-agent mutations, and local-first AI architectures.",
  keywords: [
    "Code Crux Blog",
    "CodeCrux Blog",
    "Code Crux research",
    "AST-CRDT engineering",
    "WebGPU code editor architecture",
    "Amoeba coding research",
    "Bare-metal IDE engineering",
    "Crux IDE blog",
    "codecrux.us blog",
  ],
  alternates: {
    canonical: "https://codecrux.us/blog",
  },
  openGraph: {
    type: "website",
    url: "https://codecrux.us/blog",
    title: "Code Crux Engineering Blog & Research",
    description:
      "Deep-dives into AST-CRDT peer consensus, WebGPU shader rendering, and Amoeba multi-agent mutation engines.",
    siteName: "Code Crux (Crux IDE)",
  },
};

export default function BlogPage() {
  const articles = [
    {
      slug: "ast-crdt",
      title: "Inside AST-CRDT: Why Line-Based Operational Transformation Breaks for AI Swarms",
      date: "2026-09-28",
      category: "DISTRIBUTED SYSTEMS",
      readingTime: "8 min read",
      summary:
        "Traditional collaborative editors treat documents as 1D character streams. When autonomous coding agents stream concurrent diffs, line collisions and syntax errors are inevitable. Here is how our Abstract Syntax Tree CRDT synchronizes structural nodes directly over WebRTC data channels.",
      link: "/ast-crdt",
    },
    {
      slug: "amoeba-coding",
      title: "Amoeba Coding: Real-Time Cellular Software Mutations at 120 FPS via WebGPU",
      date: "2026-09-24",
      category: "AGENTIC ARCHITECTURE",
      readingTime: "11 min read",
      summary:
        "How Crux achieves high-throughput concurrent agentic writes without dropping frames or corrupting parse trees. Comparing lock-free ring buffers against Electron DOM reflow throttles.",
      link: "/amoeba-coding",
    },
    {
      slug: "benchmarks",
      title: "Why We Abandoned Electron: The Physics of 4.2ms Input-to-Photon Latency in Rust & Metal",
      date: "2026-09-20",
      category: "HARDWARE TELEMETRY",
      readingTime: "9 min read",
      summary:
        "A rigorous empirical breakdown of input latency, idle memory footprint, and cold-start execution between Crux, Zed, Cursor, and Visual Studio Code on Apple Silicon and modern x86_64 hardware.",
      link: "/benchmarks",
    },
    {
      slug: "vs-cursor",
      title: "Bare-Metal Rust Engine vs Electron AI Wrapper: Architectural Deep Dive",
      date: "2026-09-15",
      category: "COMPARATIVE ANALYSIS",
      readingTime: "7 min read",
      summary:
        "Analyzing memory allocation patterns, V8 GC stall penalties, and local POSIX PTY integration between Crux and Cursor for software engineering teams.",
      link: "/vs-cursor",
    },
    {
      slug: "vs-claude",
      title: "Running Anthropic Claude Code (Plot) Locally Inside Native POSIX PTY Shells",
      date: "2026-09-10",
      category: "AGENT INTEGRATION",
      readingTime: "6 min read",
      summary:
        "Eliminating browser middleware and cloud relays: How Crux's automated agent discovery daemon binds directly to host-installed CLI agents over local Unix domain sockets.",
      link: "/vs-claude",
    },
    {
      slug: "vs-gemini",
      title: "Leveraging Google Gemini 1M+ Token Context Within Decentralized AST Trees",
      date: "2026-09-05",
      category: "LLM WORKFLOWS",
      readingTime: "6 min read",
      summary:
        "Full-repository context digestion without cloud latency: Coupling Gemini 1.5 Pro and 2.0 Flash reasoning directly to Crux workspace memory structures.",
      link: "/vs-gemini",
    },
    {
      slug: "vs-chatgpt",
      title: "OpenAI ChatGPT & Codex (JGPT): Direct AST AST Diff Execution Without Copy-Pasting",
      date: "2026-08-30",
      category: "DEVELOPER VELOCITY",
      readingTime: "5 min read",
      summary:
        "Streaming structured code completions directly into active editor buffers via zero-copy GPU memory mapped buffers.",
      link: "/vs-chatgpt",
    },
  ];

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Blog",
    "@id": "https://codecrux.us/blog#blog",
    "name": "Code Crux Engineering Blog",
    "description":
      "Technical research, systems performance benchmarks, and distributed CRDT architecture from the Code Crux Systems team.",
    "publisher": {
      "@type": "Organization",
      "@id": "https://codecrux.us/#organization",
      "name": "Code Crux Systems",
      "logo": "https://codecrux.us/crux-icon.png",
    },
    "blogPost": articles.map((a) => ({
      "@type": "BlogPosting",
      "headline": a.title,
      "datePublished": a.date,
      "description": a.summary,
      "url": `https://codecrux.us${a.link}`,
      "author": {
        "@type": "Organization",
        "name": "Code Crux Systems",
      },
    })),
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
          "name": "Blog",
          "item": "https://codecrux.us/blog",
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
            <span className="text-[#0055FF] font-bold">RESEARCH // ENGINEERING DISPATCH</span>
          </div>
          <nav className="flex items-center gap-4">
            <Link href="/about" className="text-[#888888] hover:text-white no-underline uppercase">
              About
            </Link>
            <Link href="/pricing" className="text-[#888888] hover:text-white no-underline uppercase">
              Pricing
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

      {/* Main Body */}
      <main className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [KERNEL RESEARCH PAPERS // ARCHITECTURAL DISPATCH]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Code Crux Research &amp; Engineering.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Rigorous technical dispatches detailing the engineering behind bare-metal collaborative editing,
            WebGPU compute shaders, decentralized AST-CRDT consensus algorithms, and multi-agent AI execution.
          </p>
        </div>

        {/* Articles List */}
        <section className="divide-y divide-[#222222] border-b border-[#222222]">
          {articles.map((item, index) => (
            <article key={index} className="py-8 grid grid-cols-1 lg:grid-cols-12 gap-6 hover:bg-[#0a0a0c] transition-none p-4">
              <div className="lg:col-span-3 text-xs font-mono text-[#888888] space-y-1">
                <div className="text-[#0055FF] font-bold">[{item.category}]</div>
                <div>{item.date}</div>
                <div className="text-[#555555]">{item.readingTime}</div>
              </div>
              <div className="lg:col-span-9 space-y-3">
                <h2 className="text-xl sm:text-2xl font-normal text-white">
                  <Link href={item.link} className="hover:text-[#0055FF] no-underline">
                    {item.title}
                  </Link>
                </h2>
                <p className="text-sm text-[#888888] leading-relaxed">
                  {item.summary}
                </p>
                <div>
                  <Link
                    href={item.link}
                    className="inline-flex items-center gap-1.5 text-xs font-mono text-[#0055FF] hover:underline"
                  >
                    <span>Read Whitepaper</span>
                    <span>→</span>
                  </Link>
                </div>
              </div>
            </article>
          ))}
        </section>

        {/* Machine Readable & RSS Callout */}
        <section className="mt-12 p-8 border border-[#222222] bg-[#0c0c0e] flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div>
            <div className="text-xs font-mono text-[#0055FF] font-bold mb-1">[MACHINE-READABLE SPECIFICATIONS]</div>
            <h3 className="text-lg font-medium text-white mb-2">Are you an AI search crawler or agent?</h3>
            <p className="text-xs text-[#888888] max-w-2xl leading-relaxed">
              Code Crux exposes LLM-optimized architectural documentation with zero markdown overhead. Fetch the raw
              whitepapers via <code className="text-white bg-[#111111] px-1 py-0.5">/llms.txt</code> or our full specification dump.
            </p>
          </div>
          <div className="flex items-center gap-3 font-mono text-xs">
            <Link
              href="/llms.txt"
              className="px-4 py-2 border border-[#333333] hover:border-white text-white no-underline bg-[#111111]"
            >
              llms.txt
            </Link>
            <Link
              href="/llms-full.txt"
              className="px-4 py-2 border border-[#333333] hover:border-white text-white no-underline bg-[#111111]"
            >
              llms-full.txt
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
            <Link href="/blog" className="hover:text-white text-white">Blog</Link>
            <Link href="/services" className="hover:text-white">Services</Link>
            <Link href="/sitemap.xml" className="hover:text-white">sitemap.xml</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
