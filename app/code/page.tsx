import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  title: "Code Online — Instant Bare-Metal Code Editor & Compiler | Code Crux",
  description:
    "Write code, run code, and collaborate in real-time. Code Crux is the ultra-fast web and native code editor engineered in Rust with direct WebGPU acceleration, 4.2ms input latency, and zero install required. Code in Rust, Python, TypeScript, C++, Go, and more.",
  keywords: [
    "code",
    "code online",
    "code editor",
    "write code",
    "run code",
    "code editor online",
    "free code editor",
    "collaborative code",
    "online code editor",
    "code playground",
    "code ide",
    "code compiler online",
    "fastest code editor",
    "bare metal code editor",
    "Code Crux",
    "CodeCrux",
    "codecrux.us",
  ],
  alternates: {
    canonical: "https://codecrux.us/code",
  },
  openGraph: {
    type: "website",
    url: "https://codecrux.us/code",
    title: "Code Online — Instant Bare-Metal Code Editor | Code Crux",
    description:
      "Write, edit, and run code instantly in your browser with sub-15ms latency. Zero install, multi-language support, and decentralized P2P collaboration.",
    siteName: "Code Crux (Crux IDE)",
  },
};

export default function CodePage() {
  const supportedLanguages = [
    { name: "Rust", ext: ".rs", desc: "Native systems programming with zero-cost abstractions and borrow-checker intelligence." },
    { name: "Python", ext: ".py", desc: "Scientific computing, AI scripts, data modeling, and rapid prototype scripting." },
    { name: "TypeScript", ext: ".ts", desc: "Type-safe modern web engineering with instant LSP token analysis." },
    { name: "JavaScript", ext: ".js", desc: "Full ECMAScript runtime support with high-throughput V8 / JavaScriptCore interop." },
    { name: "C / C++", ext: ".cpp", desc: "High-performance systems code, memory control, and embedded firmware routines." },
    { name: "Go", ext: ".go", desc: "Concurrent microservices, goroutine tooling, and networked cloud primitives." },
    { name: "HTML5 & CSS3", ext: ".html", desc: "Declarative layout, WebGPU canvas shaders, and brutalist monochrome styling." },
    { name: "JSON & YAML", ext: ".json", desc: "Configuration structures, AST node serialization, and deterministic schema specs." },
  ];

  const features = [
    {
      code: "01",
      title: "Zero-Latency Input-to-Photon",
      detail: "Measured at 4.2ms. When you type code in Crux, keypresses bypass heavy browser DOM wrappers and render directly via WebGPU compute shaders.",
    },
    {
      code: "02",
      title: "Real-Time Collaborative Code Sync",
      detail: "Share a cryptographic P2P link to code together with peers over encrypted WebRTC data channels using our decentralized AST-CRDT protocol.",
    },
    {
      code: "03",
      title: "Instant In-Browser Execution",
      detail: "Zero install, zero account required. Open the editor and start writing code immediately on any device, operating system, or screen size.",
    },
    {
      code: "04",
      title: "Local AI Coding Agents",
      detail: "Execute complex code mutations with Anthropic Claude Code, Google Gemini, and OpenAI Codex via our zero-overhead native terminal bridge.",
    },
  ];

  const faqs = [
    {
      q: "Can I write and edit code in Crux without installing anything?",
      a: "Yes. Code Crux compiles to WebAssembly (Wasm) and WebGPU pipelines, allowing you to write, edit, and inspect code immediately in modern browsers at https://codecrux.us/ide.",
    },
    {
      q: "How does Code Crux achieve lower latency than other code editors?",
      a: "Traditional editors (VS Code, Cursor) render text through Chromium's DOM tree and V8 JavaScript engine, causing 40-50ms of input delay. Crux uploads syntax tokens directly to GPU memory buffers, rendering text frames in 4.2ms at 120 FPS.",
    },
    {
      q: "What programming languages can I code in?",
      a: "Code Crux supports syntax highlighting, auto-completion, and indentation for Rust, Python, TypeScript, JavaScript, C, C++, Go, HTML, CSS, JSON, Markdown, and custom domain-specific grammars.",
    },
    {
      q: "How do I collaborate on code in real time?",
      a: "Press Cmd+Shift+P inside the editor to generate an encrypted room URL. Anyone with the URL can join your session. Changes replicate peer-to-peer using our conflict-free AST-CRDT engine with zero server intermediate logging.",
    },
    {
      q: "Is Code Crux free for individual developers?",
      a: "Yes. The Community Edition of Code Crux is free forever ($0/month) for individual software engineers, students, and open source developers.",
    },
  ];

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "WebPage",
    "@id": "https://codecrux.us/code#webpage",
    "url": "https://codecrux.us/code",
    "name": "Code Online — Instant Bare-Metal Code Editor | Code Crux",
    "description":
      "Write, edit, and run code in Rust, Python, TypeScript, and 20+ languages in your browser with 4.2ms latency.",
    "about": [
      { "@type": "Thing", "name": "Code" },
      { "@type": "Thing", "name": "Source Code" },
      { "@type": "Thing", "name": "Code Editor" },
      { "@type": "Thing", "name": "Computer Programming" },
      { "@type": "Thing", "name": "Software Development" },
    ],
    "mainEntity": {
      "@type": "SoftwareApplication",
      "name": "Code Crux Web Code Editor",
      "applicationCategory": "DeveloperApplication",
      "operatingSystem": "Web, macOS, Linux, Windows",
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
          "name": "Code",
          "item": "https://codecrux.us/code",
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
            <span className="text-[#0055FF] font-bold">CODE // INSTANT WORKSTATION</span>
          </div>
          <nav className="flex items-center gap-4">
            <Link href="/about" className="text-[#888888] hover:text-white no-underline uppercase">
              About
            </Link>
            <Link href="/pricing" className="text-[#888888] hover:text-white no-underline uppercase">
              Pricing
            </Link>
            <Link href="/benchmarks" className="text-[#888888] hover:text-white no-underline uppercase">
              Benchmarks
            </Link>
            <Link href="/docs" className="text-[#888888] hover:text-white no-underline uppercase">
              Docs
            </Link>
            <Link
              href="/ide"
              className="px-3 py-1.5 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold uppercase no-underline rounded-none"
            >
              START CODING ↵
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <main className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [THE WEB ENGINE FOR HIGH-VELOCITY PROGRAMMERS]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Code Fast. Code Free. Code Bare-Metal.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Code Crux is the ultra-responsive collaborative code editor designed to replace bloated Electron wrappers.
            Write and edit code with 4.2ms latency, direct WebGPU hardware acceleration, decentralized P2P sync,
            and autonomous local AI agents.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-4">
            <Link
              href="/ide"
              className="px-6 py-3 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold text-xs uppercase no-underline inline-block rounded-none"
            >
              LAUNCH ONLINE CODE EDITOR ↵
            </Link>
            <Link
              href="/benchmarks"
              className="px-6 py-3 border border-[#333333] hover:border-white text-white font-mono text-xs uppercase no-underline inline-block rounded-none bg-[#0a0a0c]"
            >
              VIEW HARDWARE BENCHMARKS
            </Link>
          </div>
        </div>

        {/* Live Code Preview Mockup in Brutalist Style */}
        <section className="py-12 border-b border-[#222222]">
          <div className="border border-[#222222] bg-[#0c0c0e]">
            {/* Window title bar */}
            <div className="h-9 bg-[#111111] border-b border-[#222222] px-4 flex items-center justify-between font-mono text-xs text-[#888888]">
              <div className="flex items-center gap-3">
                <span className="w-2.5 h-2.5 bg-[#222222] inline-block" />
                <span className="text-white font-bold">main.rs</span>
                <span className="text-[#555555]">· 120 FPS WebGPU Canvas</span>
              </div>
              <div className="flex items-center gap-4 text-[11px]">
                <span className="text-[#0055FF]">● 4.2ms LATENCY</span>
                <span className="text-[#444444]">|</span>
                <span>P2P SYNC: READY</span>
              </div>
            </div>

            {/* Code Body */}
            <div className="p-6 font-mono text-xs sm:text-sm text-[#cccccc] leading-relaxed overflow-x-auto bg-[#000000]">
              <pre className="text-left">
                <code>
                  <span className="text-[#555555]">01 // Code Crux: Ultra-performance native collaborative editor</span>{"\n"}
                  <span className="text-[#555555]">02 // Compile and run code with zero V8 GC interruptions</span>{"\n"}
                  <span className="text-[#0055FF]">use</span> crux_kernel::&#123;AstCrdt, WebGpuPipeline, PeerMesh&#125;;{"\n"}
                  {"\n"}
                  <span className="text-[#0055FF]">pub async fn</span> <span className="text-white font-bold">init_code_session</span>() -&gt; Result&lt;(), EngineError&gt; &#123;{"\n"}
                  {"    "}<span className="text-[#888888]">// Allocate lock-free AST mutation ring buffer</span>{"\n"}
                  {"    "}<span className="text-[#0055FF]">let</span> mut buffer = AstCrdt::new_ring_buffer(38 * 1024 * 1024);{"\n"}
                  {"    "}buffer.bind_webgpu_compute_shaders().await?;{"\n"}
                  {"\n"}
                  {"    "}<span className="text-[#888888]">// Synchronize peer-to-peer over encrypted WebRTC</span>{"\n"}
                  {"    "}<span className="text-[#0055FF]">let</span> mesh = PeerMesh::connect_encrypted_channel().await?;{"\n"}
                  {"    "}println!(<span className="text-[#0055FF]">&quot;[CODE CRUX] Engine online: 4.2ms input-to-photon.&quot;</span>);{"\n"}
                  {"    "}Ok(()){"\n"}
                  &#125;
                </code>
              </pre>
            </div>
          </div>
        </section>

        {/* Supported Languages Grid */}
        <section className="py-12 border-b border-[#222222]">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            01 // MULTI-LANGUAGE CODE RUNTIME
          </div>
          <h2 className="text-2xl font-normal text-white mb-8">
            Write Code in Any Major Language
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {supportedLanguages.map((lang, idx) => (
              <div key={idx} className="border border-[#222222] bg-[#0c0c0e] p-5 rounded-none">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-white text-base">{lang.name}</span>
                  <span className="font-mono text-xs text-[#0055FF] bg-[#111111] px-1.5 py-0.5 border border-[#222222]">
                    {lang.ext}
                  </span>
                </div>
                <p className="text-xs text-[#888888] leading-relaxed">
                  {lang.desc}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* Why Code in Crux: Core Differentiators */}
        <section className="py-12 border-b border-[#222222]">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            02 // WHY PROGRAMMERS CODE IN CRUX
          </div>
          <h2 className="text-2xl font-normal text-white mb-8">
            Built for Extreme Developer Velocity
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {features.map((feat, idx) => (
              <div key={idx} className="border border-[#222222] bg-[#0c0c0e] p-6 rounded-none">
                <div className="text-xs font-mono text-[#0055FF] font-bold mb-2">[{feat.code}]</div>
                <h3 className="text-lg font-medium text-white mb-2">{feat.title}</h3>
                <p className="text-xs text-[#888888] leading-relaxed">{feat.detail}</p>
              </div>
            ))}
          </div>
        </section>

        {/* FAQs */}
        <section className="py-12 border-b border-[#222222]">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            03 // FREQUENTLY ASKED QUESTIONS ABOUT CODING
          </div>
          <h2 className="text-2xl font-normal text-white mb-8">
            Code Editor FAQs
          </h2>
          <div className="divide-y divide-[#222222]">
            {faqs.map((faq, idx) => (
              <div key={idx} className="py-6">
                <h3 className="text-base font-medium text-white mb-2">{faq.q}</h3>
                <p className="text-xs text-[#888888] leading-relaxed max-w-3xl">{faq.a}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Bottom CTA */}
        <section className="pt-12 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div>
            <h2 className="text-2xl font-medium text-white mb-2">Ready to write code at bare-metal speed?</h2>
            <p className="text-xs text-[#888888]">
              Launch the Code Crux web editor right now in your browser. No downloads or signups.
            </p>
          </div>
          <Link
            href="/ide"
            className="px-6 py-3 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold text-xs uppercase no-underline inline-block rounded-none"
          >
            START CODING NOW ↵
          </Link>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-xs font-mono text-[#555555]">
        <div className="max-w-[1280px] mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>© Code Crux Systems 2026. Built for high-velocity software engineering.</div>
          <div className="flex items-center gap-4">
            <Link href="/" className="hover:text-white">Home</Link>
            <Link href="/code" className="hover:text-white text-white">Code</Link>
            <Link href="/about" className="hover:text-white">About</Link>
            <Link href="/pricing" className="hover:text-white">Pricing</Link>
            <Link href="/benchmarks" className="hover:text-white">Benchmarks</Link>
            <Link href="/docs" className="hover:text-white">Docs</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
