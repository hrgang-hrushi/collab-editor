import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  icons: { icon: "/crux-icon.png" },
  metadataBase: new URL("https://codecrux.us"),
  title: "Crux — Bare-Metal Collaborative IDE | Rust & WebGPU Engine",
  description:
    "Crux is the native collaborative IDE engineered for high-velocity engineering. Sub-15ms input-to-photon latency (4.2ms measured), 38MB idle memory, decentralized AST-CRDT real-time P2P sync, and autonomous local @CruxAI HyperTerminal.",
  keywords: [
    "Crux IDE",
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
  ],
  authors: [{ name: "Crux Systems", url: "https://codecrux.us" }],
  creator: "Crux Systems",
  publisher: "Crux Systems",
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
    siteName: "Crux IDE",
    title: "Crux — Bare-Metal Collaborative IDE | Rust & WebGPU",
    description:
      "Sub-15ms latency, 38MB idle RAM, and decentralized AST-CRDT peer mesh synchronization. Engineered from raw silicon for high-velocity engineering.",
    images: [
      {
        url: "https://codecrux.us/crux-logo.svg",
        width: 1200,
        height: 630,
        alt: "Crux IDE Logo & Architecture",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux — Bare-Metal Collaborative IDE",
    description:
      "Sub-15ms input-to-photon latency, 38MB RAM, and decentralized AST-CRDT peer mesh synchronization.",
    creator: "@codecrux",
    images: ["https://codecrux.us/crux-logo.svg"],
  },
  alternates: {
    canonical: "https://codecrux.us",
  },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      "@id": "https://codecrux.us/#software",
      "name": "Crux IDE",
      "alternateName": ["Crux", "Crux Editor", "codecrux"],
      "url": "https://codecrux.us",
      "applicationCategory": "DeveloperApplication",
      "operatingSystem": "macOS, Windows, Linux",
      "softwareVersion": "0.1.0",
      "description":
        "Ultra-performance native collaborative IDE built with Rust, direct WebGPU and Metal rasterization, decentralized AST-CRDT peer mesh sync, and autonomous local @CruxAI HyperTerminal agents.",
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
        "Direct WebGPU & Metal compute shader rasterization (sub-15ms input-to-photon latency)",
        "Decentralized AST-CRDT real-time peer mesh synchronization over WebRTC",
        "Universal native PTY terminal with CLI auto-discovery (agy, claude, codex)",
        "38MB idle memory footprint compared to 680MB in Electron",
        "Zero cloud telemetry lock-in with 100% air-gapped readiness",
      ],
    },
    {
      "@type": "Organization",
      "@id": "https://codecrux.us/#organization",
      "name": "Crux Systems",
      "url": "https://codecrux.us",
      "logo": "https://codecrux.us/crux-logo.svg",
      "sameAs": ["https://github.com/hrgang-hrushi/collab-editor"],
    },
    {
      "@type": "FAQPage",
      "@id": "https://codecrux.us/#faq",
      "mainEntity": [
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
          "name": "Hardware Benchmarks",
          "item": "https://codecrux.us/benchmarks",
        },
        {
          "@type": "ListItem",
          "position": 3,
          "name": "AST-CRDT Protocol",
          "item": "https://codecrux.us/ast-crdt",
        },
        {
          "@type": "ListItem",
          "position": 4,
          "name": "Pricing",
          "item": "https://codecrux.us/pricing",
        },
        {
          "@type": "ListItem",
          "position": 5,
          "name": "Crux vs Zed",
          "item": "https://codecrux.us/vs-zed",
        },
        {
          "@type": "ListItem",
          "position": 6,
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
