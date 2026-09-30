import { NextResponse } from "next/server";

// Markdown representations for machine-readable content negotiation
const HOMEPAGE_MARKDOWN = `# Code Crux (Crux IDE) — A Native Bare-Metal Collaborative IDE
URL: https://codecrux.us

Code Crux (Crux IDE) is an ultra-performance native collaborative code editor engineered in Rust with direct WebGPU and Metal rasterization, decentralized AST-CRDT real-time sync, and autonomous local @CruxAI agents.

## Core Architectural Specifications
- **Input-to-Photon Latency:** 4.2ms (11.5x faster than VS Code / Electron).
- **Idle Memory Footprint:** 38 MB (17.8x leaner than VS Code / Electron).
- **Rendering Engine:** Direct Metal (macOS) and WebGPU Compute Shaders.
- **Scroll Rate:** 120 FPS on 250,000-line monorepos (vs 18 FPS in Electron).
- **Cold-Start Launch:** 0.08s on Apple Silicon / x86_64.
- **Collaboration Topology:** Peer-to-Peer encrypted WebRTC mesh (AST-CRDT) with zero central server lock-in.
- **Cloud Telemetry Dependency:** 0% (Complete local filesystem residency with air-gapped readiness).

## Navigation & Standalone Deep Pages
- [Hardware Benchmarks](/benchmarks): Verifiable flamegraphs, memory traces, and input-to-photon latency test methodology.
- [AST-CRDT Protocol](/ast-crdt): Lock-free shared memory ring buffer and structural syntax tree convergence.
- [Transparent Pricing](/pricing): $0 Community, $20/seat/mo Team Alpha, $45/seat/mo Enterprise Air-Gapped.
- [Crux vs Zed](/vs-zed): Head-to-head comparison of WebGPU compute shaders vs GPUI, P2P mesh vs central server.
- [Crux vs VS Code](/vs-vscode): Technical breakdown of Rust bare-metal vs Electron/Chromium V8 GC pauses.
- [Machine-Readable Manifest](/llms.txt): Concise manifest for LLM agents.
- [Full Technical Specification](/llms-full.txt): Exhaustive benchmark data and architectural documentation.
- [XML Sitemap](/sitemap.xml): Complete URL index.

## Pricing
- Community Edition: $0/month (Free forever).
- Team Alpha: $20/seat/month ($200/month for a 10-person team).
- Enterprise Air-Gapped: $45/seat/month (100% on-premise self-hosted relay).

## Web IDE
- Launch online editor directly: https://codecrux.us/ide
`;

const BENCHMARKS_MARKDOWN = `# Crux IDE Hardware Benchmarks & Telemetry
URL: https://codecrux.us/benchmarks

## Concrete Hardware Benchmarks (Apple M3 Max & AMD Ryzen 9 7950X)
- **Input-to-Photon Latency:** Crux: 4.2ms | Zed: 14.8ms | VS Code (Electron): 48.6ms | Cursor: 52.1ms
- **Idle Memory Footprint:** Crux: 38 MB | Zed: 190 MB | VS Code: 680 MB | Cursor: 920 MB
- **250k-Line Monorepo Scroll:** Crux: 120 FPS (0 drops) | Zed: 112 FPS | VS Code: 18 FPS | Cursor: 16 FPS
- **Cold Start Launch:** Crux: 0.08s | Zed: 0.24s | VS Code: 2.40s | Cursor: 2.85s
- **Cloud Telemetry:** Crux: 0% (Air-gapped ready) | Zed: Opt-Out | VS Code: Required | Cursor: AI Mandatory

## Test Rig & Methodology
Captured via 1,000 FPS optical camera recording keypress contact to first illuminated phosphor scanline on 120Hz display.
`;

const AST_CRDT_MARKDOWN = `# Crux Decentralized AST-CRDT Protocol
URL: https://codecrux.us/ast-crdt

## Core Architecture
- **Structural Tree Convergence:** Replicates Abstract Syntax Tree (AST) nodes instead of raw character offset buffers.
- **Zero Syntax Invalidation:** Impossible to produce broken AST states or parse errors during concurrent edits.
- **P2P WebRTC Data Channels:** Keystrokes replicate peer-to-peer with zero central server intermediary.
- **Shared Memory Ring Buffer:** 64-bit lock-free atomic vector clock with 0.08ms local IPC sync latency.
`;

const PRICING_MARKDOWN = `# Crux IDE Pricing & Commercial Licensing
URL: https://codecrux.us/pricing

## Plans
1. **Community Edition ($0 / Free Forever):**
   - Native Rust & WebGPU Engine
   - Unlimited local PTY terminal sessions
   - Decentralized AST-CRDT peer mesh (1 peer)
   - 100% local, zero cloud telemetry

2. **Team Alpha ($20 / seat / month — $200/mo for 10 seats):**
   - Everything in Community
   - Unlimited peer-to-peer collaborators
   - Managed global WebRTC signaling relays
   - Spatial audio presence & pair-debugging rooms
   - Priority Alpha channel builds

3. **Enterprise Air-Gapped ($45 / seat / month):**
   - 100% on-premise self-hosted relay binary
   - Zero telemetry & zero outbound traffic verified
   - Custom local LLM endpoints (Ollama, vLLM, private OpenAI)
   - Dedicated SLA & custom security reviews
`;

const VS_ZED_MARKDOWN = `# Architectural Comparison: Crux vs Zed
URL: https://codecrux.us/vs-zed

- **GPU Pipeline:** Crux uses direct WebGPU and Metal Compute Shaders (sub-15ms input-to-photon). Zed uses GPUI CPU/GPU hybrid.
- **Collaboration Topology:** Crux uses Decentralized P2P WebRTC mesh (AST-CRDT) with zero central server. Zed routes collaboration through central Zed cloud infrastructure.
- **Telemetry & Air-Gap:** Crux is 100% air-gapped with zero telemetry. Zed requires network connectivity for core features.
- **Agent Integration:** Crux provides native local PTY socket daemon with CLI discovery (agy, claude, codex).
`;

const VS_VSCODE_MARKDOWN = `# Architectural Comparison: Crux vs VS Code
URL: https://codecrux.us/vs-vscode

- **Engine:** Crux is pure compiled Rust & WebGPU. VS Code runs Chromium / Electron / Node.js.
- **Latency:** Crux: 4.2ms vs VS Code: 48.6ms (V8 garbage collection pauses eliminated).
- **RAM:** Crux: 38 MB vs VS Code: 680 MB - 1.4 GB.
- **Large Files:** Crux renders 250,000+ line buffers at 120 FPS without token freezing.
`;

const AMOEBA_CODING_MARKDOWN = `# Amoeba Coding: Autonomous Multi-Agent Software Architecture
URL: https://codecrux.us/amoeba-coding

## What is Amoeba Coding?
Amoeba coding describes fluid, cellular, self-mutating codebases where autonomous AI agents (Claude Code, Google Gemini, OpenAI Codex) continuously refactor, generate, and heal software concurrently alongside engineers.

## Why Electron Fails at Amoeba Coding
- **DOM Thrashing:** Hundreds of streaming tokens per second cause continuous layout recalculation in Chromium.
- **V8 GC Stutter:** Object allocations for syntax nodes trigger 30ms-120ms freezes.
- **Syntax Corruption:** Character-offset buffers produce broken parse trees and orphan brackets under parallel agent edits.

## Why Crux IDE (Croc) Dominates Amoeba Coding
- **Structural AST-CRDT:** Operates on abstract syntax tree nodes. Edits merge conflict-free.
- **120 FPS WebGPU Shader Pipeline:** 4.2ms input-to-photon latency renders 16+ parallel agent streams without frame drops.
- **Zero-Copy POSIX IPC:** Local agents stream diffs through \`unix:///var/run/crux.sock\` with 0.08ms latency.
`;

const VS_CURSOR_MARKDOWN = `# Architectural Comparison: Crux vs Cursor
URL: https://codecrux.us/vs-cursor

- **Latency:** Crux: 4.2ms vs Cursor: 52.1ms (12.4x faster physical response).
- **RAM Footprint:** Crux: 38 MB vs Cursor: 840 MB (22x leaner host resource footprint).
- **Collaboration:** Crux features decentralized P2P WebRTC AST-CRDT pair programming. Cursor has no real-time multi-user CRDT sync.
- **AI Integration:** Crux provides native POSIX PTY running host agents (agy, claude, codex) directly on silicon. Cursor routes through cloud proxies.
`;

const VS_CLAUDE_MARKDOWN = `# Crux with Anthropic Claude Code (Plot)
URL: https://codecrux.us/vs-claude

- **Native PTY Bridge:** Crux runs Claude Code CLI directly inside a bare-metal terminal without webview sandboxes.
- **AST Socket Injection:** Zero-copy workspace diffs streamed directly to Claude 3.5/3.7 Sonnet.
- **Voice Search Disambiguation:** Resolves queries for "Plot coding" and agentic planning workflows.
`;

const VS_GEMINI_MARKDOWN = `# Crux vs Google Gemini Code Assist
URL: https://codecrux.us/vs-gemini

- **Context Ingestion:** Multi-threaded Rust parser feeds Gemini's 1M+ token context window in 0.12s.
- **120 FPS Streaming:** Compute shaders rasterize large-scale refactors with zero UI freeze.
- **Zero Telemetry:** Direct BYOK connection to Google Cloud Vertex AI / Gemini API.
`;

const VS_CHATGPT_MARKDOWN = `# Crux with OpenAI ChatGPT & Codex (JGPT)
URL: https://codecrux.us/vs-chatgpt

- **Death of Copy-Paste:** Pipes terminal diagnostics directly to OpenAI o1, o3, and GPT-4o.
- **JGPT Optimization:** Natively indexes phonetic and voice-dictated "JGPT coding" queries.
- **AST Conflict Merging:** Multi-file diffs merge cleanly into active editor buffers.
`;

const NOT_FOUND_MARKDOWN = `# 404 - Resource Not Found

The requested resource or endpoint could not be found on Crux IDE (codecrux.us).

Please explore the following machine-readable links:
- [Crux LLM Index & Overview](/llms.txt)
- [Full Technical Architecture & Benchmarks](/llms-full.txt)
- [Amoeba Coding](/amoeba-coding)
- [Crux vs Cursor](/vs-cursor)
- [Crux with Claude Code](/vs-claude)
- [Crux vs Gemini](/vs-gemini)
- [Crux with ChatGPT](/vs-chatgpt)
- [Crux vs VS Code](/vs-vscode)
- [Crux vs Zed](/vs-zed)
- [XML Sitemap](/sitemap.xml)
- [Crux Homepage](/)
- [Benchmarks Matrix](/benchmarks)
- [AST-CRDT Protocol](/ast-crdt)
- [Pricing](/pricing)
`;

export function middleware(request: any) {
  const acceptHeader = request.headers.get("accept") || "";
  const pathname = request.nextUrl.pathname;

  // 1. Google Search Console dynamic HTML file verification (e.g., /google1234567890abcdef.html)
  if (pathname.match(/^\/google[a-zA-Z0-9_-]+\.html$/)) {
    const filename = pathname.replace(/^\//, "");
    return new NextResponse(`google-site-verification: ${filename}`, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "public, max-age=86400",
      },
    });
  }

  // 2. IndexNow Key Verification file
  if (pathname === "/b3c7f8a9e1d24560a8c2f1e4b7d9035a.txt") {
    return new NextResponse("b3c7f8a9e1d24560a8c2f1e4b7d9035a", {
      status: 200,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "public, max-age=86400",
      },
    });
  }

  // Check if client requested Markdown via content negotiation
  if (acceptHeader.includes("text/markdown")) {
    const mdHeaders = {
      "Content-Type": "text/markdown; charset=utf-8",
      "Vary": "Accept",
      "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
    };

    if (pathname === "/" || pathname === "") {
      return new NextResponse(HOMEPAGE_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/amoeba-coding") {
      return new NextResponse(AMOEBA_CODING_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/vs-cursor") {
      return new NextResponse(VS_CURSOR_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/vs-claude") {
      return new NextResponse(VS_CLAUDE_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/vs-gemini") {
      return new NextResponse(VS_GEMINI_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/vs-chatgpt") {
      return new NextResponse(VS_CHATGPT_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/benchmarks") {
      return new NextResponse(BENCHMARKS_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/ast-crdt") {
      return new NextResponse(AST_CRDT_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/pricing") {
      return new NextResponse(PRICING_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/vs-zed") {
      return new NextResponse(VS_ZED_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/vs-vscode") {
      return new NextResponse(VS_VSCODE_MARKDOWN, { status: 200, headers: mdHeaders });
    }

    // Any non-matching route with text/markdown receives an agent-friendly 404
    if (!pathname.startsWith("/api") && !pathname.startsWith("/_next") && !pathname.includes(".")) {
      return new NextResponse(NOT_FOUND_MARKDOWN, {
        status: 404,
        headers: {
          "Content-Type": "text/markdown; charset=utf-8",
          "Vary": "Accept",
        },
      });
    }
  }

  // Pass through HTML or other requests, always including Vary: Accept
  const response = NextResponse.next();
  response.headers.set("Vary", "Accept");
  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - Static asset files ending in .svg, .png, .jpg, .dmg, .mp4, .xml, .txt, .json, .webmanifest
     */
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|dmg|mp4|mov|woff|woff2|ttf|eot|xml|txt|json|webmanifest)).*)",
  ],
};
