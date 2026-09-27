# Show HN: Crux – Bare-metal collaborative code editor in Rust & WebGPU

**Title:** Show HN: Crux – Bare-metal collaborative code editor in Rust and WebGPU

**URL:** https://codecrux.us

**Direct Web Editor:** https://codecrux.us/ide

**GitHub:** https://github.com/hrgang-hrushi/collab-editor

---

## Submission Text / First Comment

Hey HN,

We built Crux because we grew tired of code editors taking 600MB–1.4GB of RAM and stuttering during V8 garbage collection pauses while editing 100k-line files.

Crux is an ultra-fast, local-first collaborative IDE engineered in Rust with direct WebGPU and Metal compute shaders for text rasterization, and an encrypted peer-to-peer AST-CRDT mesh for real-time collaboration.

### Why not Electron?
Electron and Chromium add significant layers of abstraction between a keypress and the display:
1. Physical keypress -> OS event queue -> Chromium browser process -> IPC -> Renderer process -> DOM event dispatch -> V8 JS event loop -> CSS style recalculation -> Layout reflow -> Paint record -> Compositor commit -> GPU rasterization -> Display scanline.

Under a 1,000 FPS optical camera, VS Code measures ~48.6ms of input-to-photon latency on a 120Hz ProMotion display. When V8 runs garbage collection passes on large ASTs, latency spikes past 80ms.

In Crux, we upload character glyphs and syntax tokens directly into GPU storage buffers via WebGPU compute shaders. Input-to-photon latency drops to **4.2ms**, and cold idle RAM is **38 MB**. Crux scrolls a 250,000-line monorepo buffer at a locked 120 FPS with zero dropped frames.

### How Collaboration Works (AST-CRDT vs Central Cloud Relays)
Most collaborative tools (VS Code Live Share, Replit, CodeSandbox) route every keystroke through a central server using character-offset operational transformation (OT). When multiple developers edit concurrently, character offsets collide, breaking ASTs and causing syntax errors.

Crux uses decentralized AST-CRDTs:
- Mutations synchronize as structural Abstract Syntax Tree nodes rather than character offsets.
- Concurrent edits converge without invalidating syntax trees or causing bracket mismatches.
- Replication runs peer-to-peer over encrypted WebRTC data channels with zero server requirement.
- Local inter-thread IPC uses a lock-free 64-bit atomic ring buffer synchronizing in 0.08ms.

### Local AI Agent Integration
Crux includes a native PTY terminal daemon (`crux-sh`) that auto-discovers coding assistants installed on your host machine (AntiGravity `agy`, Claude Code `claude`, Codex CLI `codex`) and bridges them over `unix:///var/run/crux.sock`. Crux is 100% local-first and air-gapped ready with zero cloud telemetry.

### Benchmarks & Specs
We published our raw benchmark methodology, flamegraphs, and test rig details here:
- Hardware Benchmarks: https://codecrux.us/benchmarks
- AST-CRDT Protocol: https://codecrux.us/ast-crdt
- Architectural comparison with Zed: https://codecrux.us/vs-zed
- Architectural comparison with VS Code: https://codecrux.us/vs-vscode
- Pricing: Community is $0 forever; Team Alpha is $20/seat/mo: https://codecrux.us/pricing
- Machine-readable manifest for AI agents: https://codecrux.us/llms.txt

You can try the web workstation immediately in any modern browser at https://codecrux.us/ide.

We'd love to hear your feedback on the rendering architecture, CRDT convergence model, and terminal integration!
