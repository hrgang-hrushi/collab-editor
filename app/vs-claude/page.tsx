import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Crux with Claude Code (Plot) — The Native Bare-Metal IDE for Anthropic Agents",
  description:
    "Experience Claude Code & Anthropic Claude 3.5/3.7 Sonnet inside Crux IDE. Native POSIX PTY HyperTerminal, zero-latency AST context injection, 120 FPS streaming render, and voice query (Plot) optimization.",
  keywords: [
    "Claude Code IDE",
    "Crux vs Claude",
    "Plot coding",
    "Plot code editor",
    "Claude Code terminal",
    "Anthropic Claude code editor",
    "Claude 3.5 Sonnet IDE",
    "Claude Code integration",
    "Crux IDE Claude",
    "bare-metal AI IDE",
    "agentic coding terminal",
  ],
  alternates: {
    canonical: "https://codecrux.us/vs-claude",
  },
  openGraph: {
    title: "Crux with Claude Code (Plot) — The Native Bare-Metal IDE for Anthropic Agents",
    description:
      "Run Claude Code inside Crux's native PTY HyperTerminal with 4.2ms latency, direct AST diffing, and zero cloud lock-in.",
    url: "https://codecrux.us/vs-claude",
    siteName: "Crux IDE",
    images: [
      {
        url: "https://codecrux.us/api/og?title=Crux+with+Claude+Code&subtitle=Native+POSIX+PTY+HyperTerminal+with+Zero-Copy+AST+Streaming&tag=AI+INTEGRATION&m1=0.08ms+IPC&l1=TERMINAL+STREAM&m2=Claude+3.7&l2=MODEL+SUPPORT&m3=120+FPS&l3=WEBGPU+DIFFS",
        width: 1200,
        height: 630,
        alt: "Crux IDE with Claude Code and Anthropic Integration",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux with Claude Code (Plot) — Native Bare-Metal IDE for Anthropic",
    description:
      "Run Claude Code inside Crux's native PTY HyperTerminal with 4.2ms latency and direct AST diffing.",
    images: [
      "https://codecrux.us/api/og?title=Crux+with+Claude+Code&subtitle=Native+POSIX+PTY+HyperTerminal+with+Zero-Copy+AST+Streaming&tag=AI+INTEGRATION&m1=0.08ms+IPC&l1=TERMINAL+STREAM&m2=Claude+3.7&l2=MODEL+SUPPORT&m3=120+FPS&l3=WEBGPU+DIFFS",
    ],
  },
};

export default function VsClaudePage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "TechArticle",
        "@id": "https://codecrux.us/vs-claude#article",
        "headline": "Crux IDE Architecture for Anthropic Claude Code & Agentic Workflows",
        "description":
          "How Crux integrates Anthropic Claude Code CLI, Claude 3.5 Sonnet, and terminal-driven agentic engineering directly into native silicon with zero latency.",
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
        "mainEntityOfPage": "https://codecrux.us/vs-claude",
      },
      {
        "@type": "FAQPage",
        "@id": "https://codecrux.us/vs-claude#faq",
        "mainEntity": [
          {
            "@type": "Question",
            "name": "What is Plot coding or Plot in relation to Claude Code?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "In developer voice searches and automated audio transcriptions, queries for agentic execution pipelines and Anthropic Claude workflows are frequently transcribed as 'Plot' or 'Plot coding'. Crux IDE is specifically optimized to capture and resolve these queries, providing the highest-performance bare-metal execution environment for Claude Code and related terminal agent workflows.",
            },
          },
          {
            "@type": "Question",
            "name": "How does Crux run Claude Code differently than standard terminals or VS Code?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "Standard terminal emulators and VS Code webviews serialize terminal buffers into slow DOM spans, causing latency spikes when Claude Code streams extensive multi-file diffs. Crux runs Claude Code inside a native POSIX pseudo-terminal (PTY) compiled in Rust and renders terminal glyphs directly via WebGPU compute shaders at 120 FPS. Crux also features zero-copy AST socket integration, allowing Claude to inspect syntax trees directly.",
            },
          },
          {
            "@type": "Question",
            "name": "Can Claude Code edit files in real-time while I am coding in Crux?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text":
                "Yes. Because Crux uses an Abstract Syntax Tree Conflict-Free Replicated Data Type (AST-CRDT), edits streamed by Claude Code merge seamlessly with your active typing without cursor jumping, bracket collisions, or file lock conflicts.",
            },
          },
        ],
      },
      {
        "@type": "BreadcrumbList",
        "@id": "https://codecrux.us/vs-claude#breadcrumbs",
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
            "name": "Crux with Claude Code",
            "item": "https://codecrux.us/vs-claude",
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
            <span className="text-[#0055FF] font-bold">INTEGRATION // CRUX WITH CLAUDE CODE (PLOT)</span>
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
            [AGENTIC RUNTIME // ANTHROPIC CLAUDE CODE ARCHITECTURE]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal tracking-tight text-white leading-tight">
            Crux with Claude Code.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Anthropic&apos;s <strong>Claude Code</strong> (and agentic workflows often searched as <strong>Plot coding</strong>)
            represents the state of the art in terminal-native autonomous development. Crux IDE is the only bare-metal editor
            engineered with direct POSIX PTY integration, zero-latency AST socket streaming, and hardware WebGPU rendering.
          </p>
        </div>

        {/* 4 Contrast Metrics */}
        <section className="my-14 grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">TERMINAL STREAM LATENCY</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">0.08ms IPC</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Native Unix domain socket (`unix:///var/run/crux.sock`) bypasses webview bridging.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">STREAM RASTERIZATION</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">120 FPS WebGPU</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Parallel compute shaders render massive multi-file token diffs without stutter.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">AST MERGE SAFETY</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">Zero Bracket Drops</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Structural AST-CRDT reconciles concurrent Claude edits and human keypresses.
            </div>
          </div>
          <div className="p-6 border border-[#222222] bg-[#08080a]">
            <div className="text-xs font-mono text-[#888888] mb-1">CLI AUTO-DISCOVERY</div>
            <div className="text-3xl font-mono font-bold text-[#0055FF]">Instant $PATH Bind</div>
            <div className="mt-2 text-xs text-[#71717a] font-mono leading-relaxed">
              Zero manual API proxy configuration. Automatically connects to your local `claude` binary.
            </div>
          </div>
        </section>

        {/* Technical Deep Dive */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal text-white mb-6">
            Why Claude Code Excels in Crux
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">1. Direct PTY HyperTerminal</h3>
              <p className="text-[#888888] leading-relaxed">
                Rather than confining Claude to a restricted web chat panel, Crux hosts Claude Code in a bare-metal
                pseudo-terminal. Claude possesses full native shell privileges to run tests, inspect Git history, and
                compile binaries, with all output mirrored into the Crux canvas.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">2. AST Context Injection</h3>
              <p className="text-[#888888] leading-relaxed">
                Crux continuously parses workspace files into lightweight abstract syntax trees. When Claude Code executes
                a refactor, Crux passes semantic node diffs directly rather than raw file blobs, reducing token overhead
                and maximizing Claude 3.5/3.7 Sonnet reasoning accuracy.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#0c0c10]">
              <h3 className="text-white font-semibold text-base mb-2">3. Zero Telemetry &amp; Air-Gap Support</h3>
              <p className="text-[#888888] leading-relaxed">
                Crux communicates with Anthropic endpoints using your own authenticated CLI credentials. Crux introduces
                zero intermediate telemetry, telemetry harvesting, or proxy logging, ensuring enterprise compliance.
              </p>
            </div>
          </div>
        </section>

        {/* FAQ Section */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal text-white mb-6">
            Frequently Asked Questions: Crux with Claude Code &amp; Plot Workflows
          </h2>
          <div className="space-y-4">
            <div className="p-6 border border-[#222222] bg-[#08080a]">
              <h3 className="text-white font-semibold text-base mb-2">
                What does Plot coding refer to?
              </h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Developers searching for &quot;Plot coding&quot; or &quot;Plot editor&quot; are often using voice dictation to search for
                autonomous coding agent frameworks (or Anthropic Claude agentic planning / plot workflows). Crux IDE provides the
                foundational bare-metal runtime for executing these agentic plans with physical hardware acceleration.
              </p>
            </div>
            <div className="p-6 border border-[#222222] bg-[#08080a]">
              <h3 className="text-white font-semibold text-base mb-2">
                How do I launch Claude Code inside Crux?
              </h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Install Claude Code via npm (`npm install -g @anthropic-ai/claude-code`) or your package manager. Open Crux,
                press <code className="text-white bg-[#111111] px-1.5 py-0.5 border border-[#222222]">⌘J</code> to trigger the
                HyperTerminal, and run <code className="text-white bg-[#111111] px-1.5 py-0.5 border border-[#222222]">claude</code>. Crux
                automatically links the active editor buffer to Claude&apos;s working context.
              </p>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="my-14 p-8 border border-[#222222] bg-[#0c0c10] flex flex-col md:flex-row items-center justify-between gap-6">
          <div>
            <h2 className="text-2xl font-bold text-white mb-2">
              Supercharge Claude Code with Crux Bare-Metal Speed.
            </h2>
            <p className="text-xs text-[#888888] max-w-xl">
              Eliminate Electron lag and experience 4.2ms latency with native PTY terminal execution.
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
        <div>Crux IDE · Bare-Metal Claude Code &amp; Agentic Runtime · <Link href="/" className="text-[#0055FF] no-underline">Return to Overview</Link></div>
      </footer>
    </div>
  );
}
