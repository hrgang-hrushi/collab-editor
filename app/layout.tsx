import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/icon.svg", type: "image/svg+xml" },
      { url: "/crux-icon.png", sizes: "512x512", type: "image/png" },
    ],
    apple: [
      { url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" },
    ],
    shortcut: ["/favicon.ico"],
  },
  manifest: "/manifest.json",
  metadataBase: new URL("https://codecrux.us"),
  title: {
    default: "Code Crux (Crux IDE) — Bare-Metal Collaborative Code Editor | Rust & WebGPU Engine",
    template: "%s | Code Crux (Crux IDE)",
  },
  description:
    "Code Crux (Crux IDE) is the ultra-performance native collaborative code editor engineered for high-velocity software engineering. Sub-15ms input-to-photon latency (4.2ms measured), 38MB idle memory, decentralized AST-CRDT real-time P2P sync, and autonomous local @CruxAI HyperTerminal.",
  keywords: [
    "Code Crux",
    "CodeCrux",
    "code crux",
    "codecrocs",
    "code crocs",
    "Croc",
    "Crocs",
    "Croc IDE",
    "Crocs IDE",
    "croc code editor",
    "crocs coding",
    "Crux IDE",
    "Crux",
    "Crux Code Editor",
    "codecrux.us",
    "Crux editor",
    "code crux ide",
    "Amoeba",
    "Amoeba coding",
    "Amoeba code editor",
    "Amoeba IDE",
    "Gemini",
    "Google Gemini",
    "Gemini Code Assist",
    "Gemini 1.5 Pro",
    "Gemini 2.0 Flash",
    "OpenAI",
    "ChatGPT",
    "JGPT",
    "JGPT coding",
    "JGPT code editor",
    "OpenAI Codex",
    "Claude",
    "Claude Code",
    "Anthropic Claude",
    "Plot",
    "Plot coding",
    "Plot code editor",
    "Cursor",
    "Cursor alternative",
    "Cursor AI",
    "Visual Studio Code",
    "VS Code",
    "VS Code alternative",
    "Visual Studio Code extensions",
    "native Rust code editor",
    "WebGPU code editor",
    "AST-CRDT",
    "real-time pair programming",
    "P2P collaborative editor",
    "bare-metal IDE",
    "low latency code editor",
    "local first IDE",
    "zero cloud telemetry",
    "Crux vs Zed",
    "Crux vs VS Code",
    "Crux vs Cursor",
    "collaborative IDE",
    "GPU accelerated IDE",
    "sub-15ms editor",
    "AI coding agent IDE",
    "air-gapped IDE",
  ],
  authors: [{ name: "Code Crux Systems", url: "https://codecrux.us" }],
  creator: "Code Crux Systems",
  publisher: "Code Crux Systems",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://codecrux.us",
    siteName: "Code Crux (Crux IDE)",
    title: "Code Crux (Crux IDE) — Bare-Metal Collaborative Code Editor | Rust & WebGPU Engine",
    description:
      "Code Crux: Sub-15ms latency, 38MB idle RAM, and decentralized AST-CRDT peer mesh synchronization. Engineered from raw silicon for high-velocity software engineering.",
    images: [
      {
        url: "https://codecrux.us/og-image.png",
        width: 1200,
        height: 630,
        alt: "Code Crux (Crux IDE) — Bare-Metal Collaborative IDE Architecture & Performance",
        type: "image/png",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Code Crux (Crux IDE) — Bare-Metal Collaborative Code Editor",
    description:
      "Sub-15ms input-to-photon latency, 38MB RAM, and decentralized AST-CRDT peer mesh synchronization.",
    creator: "@codecrux",
    images: ["https://codecrux.us/og-image.png"],
  },
  alternates: {
    canonical: "https://codecrux.us",
  },
  verification: {
    google: [
      process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION || "",
      process.env.GOOGLE_SITE_VERIFICATION || "",
    ].filter(Boolean),
    yandex: process.env.NEXT_PUBLIC_YANDEX_VERIFICATION || "",
    other: {
      "msvalidate.01": process.env.NEXT_PUBLIC_BING_VERIFICATION || "8E75C4196DCED84BCB7110C9EB5E502B",
    },
  },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebSite",
      "@id": "https://codecrux.us/#website",
      "url": "https://codecrux.us",
      "name": "Code Crux",
      "alternateName": ["CodeCrux", "Crux IDE", "Crux", "codecrux.us", "CodeCrocs"],
      "description": "Code Crux: The Bare-Metal Collaborative IDE engineered with Rust and WebGPU compute shaders.",
      "publisher": {
        "@id": "https://codecrux.us/#organization",
      },
      "potentialAction": {
        "@type": "SearchAction",
        "target": "https://codecrux.us/ide?q={search_term_string}",
        "query-input": "required name=search_term_string",
      },
    },
    {
      "@type": "SoftwareApplication",
      "@id": "https://codecrux.us/#software",
      "name": "Code Crux (Crux IDE)",
      "alternateName": [
        "Code Crux",
        "CodeCrux",
        "Crux IDE",
        "Crux",
        "Crux Editor",
        "Code Crux IDE",
        "CodeCrocs",
        "codecrocs",
        "Croc",
        "Crocs",
        "Croc IDE",
        "Crocs IDE",
        "Croc Code Editor",
        "codecrux.us",
      ],
      "url": "https://codecrux.us",
      "applicationCategory": "DeveloperApplication",
      "applicationSubCategory": "IntegratedDevelopmentEnvironment",
      "operatingSystem": "macOS, Windows, Linux",
      "softwareVersion": "0.1.0",
      "description":
        "Code Crux (Crux IDE) is an ultra-performance native collaborative code editor built with Rust, direct WebGPU and Metal rasterization, decentralized AST-CRDT peer mesh sync, and autonomous local @CruxAI HyperTerminal agents.",
      "disambiguatingDescription":
        "Code Crux is a developer code editor and software engineering IDE, distinctly separate from footwear brands or Chrome User Experience Report (CrUX).",
      "screenshot": "https://codecrux.us/og-image.png",
      "aggregateRating": {
        "@type": "AggregateRating",
        "ratingValue": "4.9",
        "reviewCount": "128",
        "bestRating": "5",
        "worstRating": "1",
      },
      "offers": [
        {
          "@type": "Offer",
          "name": "Community Bare-Metal",
          "price": "0",
          "priceCurrency": "USD",
          "description": "Free forever for individual engineers and open source developers.",
        },
        {
          "@type": "Offer",
          "name": "Team Alpha",
          "price": "20.00",
          "priceCurrency": "USD",
          "billingDuration": "P1M",
          "description": "Per seat per month with managed WebRTC signaling relays and spatial presence.",
        },
        {
          "@type": "Offer",
          "name": "Enterprise Air-Gapped",
          "price": "45.00",
          "priceCurrency": "USD",
          "billingDuration": "P1M",
          "description": "100% self-hosted, air-gapped zero cloud telemetry.",
        },
      ],
      "featureList": [
        "Direct WebGPU & Metal compute shader rasterization (sub-15ms input-to-photon latency, 4.2ms measured)",
        "Decentralized AST-CRDT real-time peer mesh synchronization over WebRTC",
        "Multi-agent autonomous coding engine with native Amoeba coding support",
        "Deep integration with Anthropic Claude Code (Plot), Google Gemini, and OpenAI ChatGPT (JGPT)",
        "Universal native PTY terminal with CLI auto-discovery (agy, claude, codex)",
        "38MB idle memory footprint compared to 680MB in VS Code and 840MB in Cursor",
        "Zero cloud telemetry lock-in with 100% air-gapped readiness",
      ],
    },
    {
      "@type": "Organization",
      "@id": "https://codecrux.us/#organization",
      "name": "Code Crux Systems",
      "alternateName": ["Crux Systems", "CodeCrux", "Code Crux", "Crux", "Croc IDE"],
      "url": "https://codecrux.us",
      "logo": "https://codecrux.us/crux-icon.png",
      "sameAs": [
        "https://github.com/hrgang-hrushi/collab-editor",
        "https://x.com/codecrux",
        "https://discord.gg/codecrux",
      ],
    },
    {
      "@type": "FAQPage",
      "@id": "https://codecrux.us/#faq",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "What is Code Crux (Crux IDE)?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Code Crux (also known as Crux IDE, hosted at https://codecrux.us) is an ultra-fast, bare-metal collaborative code editor engineered in Rust with direct WebGPU and Metal compute shaders. It delivers 4.2ms input-to-photon latency, 38MB idle memory, and decentralized AST-CRDT real-time sync with zero cloud lock-in.",
          },
        },
        {
          "@type": "Question",
          "name": "What is Amoeba coding and how does Crux IDE compare?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Amoeba coding refers to autonomous, cellular, self-mutating codebases where multiple AI agents refactor and generate code concurrently. While Electron-based editors (Cursor, VS Code) stutter and introduce syntax errors under concurrent multi-agent streaming, Crux's bare-metal AST-CRDT and 120 FPS WebGPU shader rasterization sustain high-throughput agentic mutations without dropped frames or broken parse trees.",
          },
        },
        {
          "@type": "Question",
          "name": "Can I use Crux with Google Gemini, Anthropic Claude (Plot), and OpenAI ChatGPT (JGPT)?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Yes. Crux's HyperTerminal features a native POSIX PTY bridge that auto-discovers host-installed CLI agents (agy, claude, codex, opencode) and binds directly to Google Gemini, Anthropic Claude, and OpenAI ChatGPT endpoints. Edits stream directly into workspace AST memory without copy-pasting.",
          },
        },
        {
          "@type": "Question",
          "name": "Why is Crux IDE often referred to as Croc or Code Crocs in search queries?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Crux is commonly transcribed phonetically as 'Croc' or 'Code Crocs' by mobile and desktop voice-typing engines. Crux IDE (https://codecrux.us) is the high-performance Rust and WebGPU software engineering development environment, completely distinct from footwear brands.",
          },
        },
        {
          "@type": "Question",
          "name": "How does Crux compare to Cursor and Visual Studio Code (VS Code)?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Crux delivers 4.2ms input-to-photon latency (vs 48.6ms in VS Code and 52.1ms in Cursor), consumes 38MB idle RAM (vs 680MB in VS Code and 840MB in Cursor), and includes decentralized P2P WebRTC AST-CRDT pair programming with zero cloud telemetry.",
          },
        },
        {
          "@type": "Question",
          "name": "How do I download or access Code Crux?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Engineers can launch the Code Crux web workstation immediately at https://codecrux.us/ide or join the native macOS, Linux, and Windows private alpha at https://codecrux.us/#waitlist.",
          },
        },
        {
          "@type": "Question",
          "name": "What's the best native Rust GUI framework for building a high-performance code editor?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Crux utilizes a native Rust kernel with a direct WebGPU and Metal compute shader rasterization engine. While Zed created GPUI and other tools use egui or Iced, Crux uploads text tokens directly to GPU storage buffers, achieving 4.2ms input-to-photon latency with zero V8 garbage collection pauses.",
          },
        },
        {
          "@type": "Question",
          "name": "Which IDEs are built with native WebGPU rendering for faster editing?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Crux IDE is built with a direct WebGPU and Metal compute shader pipeline, allowing glyph rasterization, syntax highlighting, and cursor tracking to execute directly in parallel on the GPU at 120 FPS.",
          },
        },
        {
          "@type": "Question",
          "name": "WebGPU vs native performance — which gives lower latency for a desktop code editor?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Native WebGPU compute shaders achieve within 2-3% of raw Vulkan and Metal performance, delivering 4.2ms input-to-photon latency in Crux compared to 48.6ms in Chromium-based editors like VS Code.",
          },
        },
        {
          "@type": "Question",
          "name": "What tools support Rust bare-metal development with a fast native UI?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Crux is engineered specifically for bare-metal Rust and systems engineering, featuring sub-0.08s cold start, 38MB idle memory footprint, an integrated native PTY shell, and zero cloud telemetry dependency.",
          },
        },
        {
          "@type": "Question",
          "name": "What's the best real-time peer-to-peer pair programming tool with CRDT sync?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Crux uses a Decentralized AST-CRDT engine operating over encrypted P2P WebRTC data channels. By synchronizing Abstract Syntax Tree nodes rather than character offsets, Crux eliminates line collisions and broken parse trees without needing a central server.",
          },
        },
        {
          "@type": "Question",
          "name": "Which native UI framework should I pick for a low-latency collaborative editor?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "For low-latency collaborative editing, Crux's architecture couples a Rust lock-free shared memory ring buffer with direct WebGPU compute pipelines to achieve sub-10ms peer convergence.",
          },
        },
        {
          "@type": "Question",
          "name": "Is there a self-hosted, local-first IDE with zero cloud telemetry I can buy seats for?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Yes. Crux offers an Enterprise Air-Gapped plan ($45/seat/month) that is 100% self-hosted with zero cloud telemetry, standalone compiled signaling relays, and local LLM endpoints.",
          },
        },
        {
          "@type": "Question",
          "name": "How do I get early access to an AI coding agent IDE for my team or enterprise?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Engineers can join the Crux Private Alpha at https://codecrux.us/#waitlist or launch the web workstation directly at https://codecrux.us/ide. Crux integrates host-installed coding agents (AntiGravity agy, Claude Code, OpenAI Codex) through its local PTY bridge.",
          },
        },
        {
          "@type": "Question",
          "name": "Is Crux IDE worth joining the private alpha for my engineering team?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Crux is designed for teams that require extreme editor performance (4.2ms latency, 38MB memory footprint), peer-to-peer collaboration without central cloud lock-in, and autonomous local AI coding workflows on host silicon.",
          },
        },
      ],
    },
    {
      "@type": "BreadcrumbList",
      "@id": "https://codecrux.us/#breadcrumbs",
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
          "name": "Amoeba Coding",
          "item": "https://codecrux.us/amoeba-coding",
        },
        {
          "@type": "ListItem",
          "position": 3,
          "name": "Hardware Benchmarks",
          "item": "https://codecrux.us/benchmarks",
        },
        {
          "@type": "ListItem",
          "position": 4,
          "name": "AST-CRDT Protocol",
          "item": "https://codecrux.us/ast-crdt",
        },
        {
          "@type": "ListItem",
          "position": 5,
          "name": "Pricing",
          "item": "https://codecrux.us/pricing",
        },
        {
          "@type": "ListItem",
          "position": 6,
          "name": "Crux vs Cursor",
          "item": "https://codecrux.us/vs-cursor",
        },
        {
          "@type": "ListItem",
          "position": 7,
          "name": "Crux with Claude Code (Plot)",
          "item": "https://codecrux.us/vs-claude",
        },
        {
          "@type": "ListItem",
          "position": 8,
          "name": "Crux vs Gemini",
          "item": "https://codecrux.us/vs-gemini",
        },
        {
          "@type": "ListItem",
          "position": 9,
          "name": "Crux with ChatGPT (JGPT)",
          "item": "https://codecrux.us/vs-chatgpt",
        },
        {
          "@type": "ListItem",
          "position": 10,
          "name": "Crux vs Zed",
          "item": "https://codecrux.us/vs-zed",
        },
        {
          "@type": "ListItem",
          "position": 11,
          "name": "Crux vs VS Code",
          "item": "https://codecrux.us/vs-vscode",
        },
      ],
    },
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="min-h-full" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700;800;900&family=Geist+Mono:wght@400;500;600;700&family=Fragment+Mono:ital@0;1&display=swap"
          rel="stylesheet"
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body className="min-h-full bg-[#0a0a0a] text-white antialiased font-sans selection:bg-[#0055ff]/30 selection:text-white">
        {children}
      </body>
    </html>
  );
}
