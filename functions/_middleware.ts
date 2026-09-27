// Cloudflare Pages Functions Middleware for codecrux.us
// Implements acceptmarkdown.com content negotiation & agent-friendly 404s

const HOMEPAGE_MARKDOWN = `# Crux — A Native Bare-Metal Collaborative IDE
URL: https://codecrux.us

Crux is an ultra-performance native collaborative code editor engineered in Rust with direct WebGPU and Metal rasterization, decentralized AST-CRDT real-time sync, and autonomous local @CruxAI agents.

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

const NOT_FOUND_MARKDOWN = `# 404 - Resource Not Found

The requested resource or endpoint could not be found on Crux IDE (codecrux.us).

Please explore the following machine-readable links:
- [Crux LLM Index & Overview](/llms.txt)
- [Full Technical Architecture & Benchmarks](/llms-full.txt)
- [XML Sitemap](/sitemap.xml)
- [Crux Homepage](/)
- [Benchmarks Matrix](/benchmarks)
- [AST-CRDT Protocol](/ast-crdt)
- [Pricing](/pricing)
- [Crux vs Zed](/vs-zed)
- [Crux vs VS Code](/vs-vscode)
`;

export async function onRequest(context: any) {
  const request = context.request;
  const acceptHeader = request.headers.get("accept") || "";
  const url = new URL(request.url);
  const pathname = url.pathname;

  // Content negotiation for Accept: text/markdown
  if (acceptHeader.includes("text/markdown")) {
    const mdHeaders = {
      "Content-Type": "text/markdown; charset=utf-8",
      "Vary": "Accept",
      "Cache-Control": "public, max-age=3600",
    };

    if (pathname === "/" || pathname === "") {
      return new Response(HOMEPAGE_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/benchmarks") {
      return new Response(BENCHMARKS_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/ast-crdt") {
      return new Response(AST_CRDT_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/pricing") {
      return new Response(PRICING_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/vs-zed") {
      return new Response(VS_ZED_MARKDOWN, { status: 200, headers: mdHeaders });
    }
    if (pathname === "/vs-vscode") {
      return new Response(VS_VSCODE_MARKDOWN, { status: 200, headers: mdHeaders });
    }

    if (!pathname.startsWith("/api") && !pathname.includes(".")) {
      return new Response(NOT_FOUND_MARKDOWN, {
        status: 404,
        headers: {
          "Content-Type": "text/markdown; charset=utf-8",
          "Vary": "Accept",
        },
      });
    }
  }

  // Pass through to static assets or page handlers
  const response = await context.next();
  const headers = new Headers(response.headers);
  headers.set("Vary", "Accept");

  // Check for 404 response with Accept: text/markdown
  if (response.status === 404 && acceptHeader.includes("text/markdown")) {
    return new Response(NOT_FOUND_MARKDOWN, {
      status: 404,
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Vary": "Accept",
      },
    });
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
