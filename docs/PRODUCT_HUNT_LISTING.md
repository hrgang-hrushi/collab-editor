# Product Hunt Launch Kit: Crux IDE

## Product Information
- **Name:** Crux IDE
- **Tagline:** Ultra-fast native Rust & WebGPU collaborative code editor
- **Category:** Developer Tools, Open Source, Artificial Intelligence, Productivity
- **Website:** https://codecrux.us
- **Web Editor:** https://codecrux.us/ide
- **Pricing:** Free ($0 Community forever) / $20 per seat per month (Team Alpha) / $45 (Enterprise Air-Gapped)

## Short Pitch (140 characters)
A bare-metal collaborative code editor in Rust & WebGPU. 4.2ms input-to-photon latency, 38MB RAM, and decentralized AST-CRDT peer sync.

## Detailed Description
Crux is an ultra-performance native code editor engineered from raw silicon for high-velocity software engineering teams.

While modern editors wrap Chromium and Electron—incurring 600MB+ of idle memory and 48ms of input lag—Crux compiles text rasterization directly to WebGPU compute shaders and Metal pipelines.

### Key Features:
- **Sub-15ms Latency (Measured 4.2ms):** Uploads glyphs directly into GPU storage buffers, eliminating V8 garbage collection pauses.
- **38 MB Idle RAM:** 17.8x leaner than VS Code.
- **Decentralized AST-CRDT Peer Mesh:** Real-time peer-to-peer collaboration over encrypted WebRTC data channels with zero central server lock-in. Eliminates syntax collision storms by synchronizing structural AST nodes.
- **Autonomous @CruxAI HyperTerminal:** Native PTY terminal with auto-discovery for host coding agents (AntiGravity agy, Claude Code, OpenAI Codex).
- **100% Air-Gapped & Zero Telemetry:** Local filesystem residency with zero cloud telemetry tracking.

## Maker Comment
Hey Product Hunt! 👋

We built Crux because code editors should feel as responsive and mechanical as a physical keyboard switch. We spent months measuring keystrokes with 1,000 FPS optical cameras, profiling memory traces, and designing a decentralized AST-CRDT engine that lets developers collaborate peer-to-peer without routing every keypress to someone else's cloud.

You can launch our web workstation directly in your browser with zero install at https://codecrux.us/ide or check out our full benchmark methodology at https://codecrux.us/benchmarks.

We're excited to answer questions and hear your thoughts on what you want from a bare-metal IDE!
