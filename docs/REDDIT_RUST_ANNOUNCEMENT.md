# Reddit Announcement: r/rust & r/programming

**Subreddits:** r/rust, r/programming, r/neovim

**Title:** How we achieved 4.2ms input-to-photon latency by compiling text rasterization to WebGPU compute shaders in Rust (Crux IDE)

---

## Post Body

Hi everyone,

Over the past year, our team has been building **Crux** (https://codecrux.us), a bare-metal native collaborative code editor written in Rust. We recently published our hardware benchmarks comparing Crux against Electron-based editors (VS Code, Cursor) and native editors (Zed), and wanted to share our technical notes on the rendering pipeline and CRDT implementation.

### The Physics of Input-to-Photon Latency
When evaluating editor responsiveness, subjective feel boils down to input-to-photon latency: the time elapsed between the physical micro-switch contact of a keypress and the first illuminated phosphor scanline on your display.

We set up a measurement rig using a 1,000 FPS optical camera recording keypresses on a 120Hz ProMotion display (Apple M3 Max and AMD Ryzen 9 7950X):
- **VS Code (Electron):** 48.6ms mean latency (frequent spikes past 80ms during V8 GC)
- **Zed (GPUI):** 14.8ms mean latency
- **Crux (Rust + WebGPU Compute Shaders):** **4.2ms mean latency**

### Why WebGPU Compute Shaders for Text Editing?
Rather than maintaining a retained-mode DOM or hybrid CPU/GPU canvas scene graph, Crux treats text editing as a streaming GPU compute problem:
1. File buffers are memory-mapped into contiguous virtual memory pages.
2. Syntax highlighting and tokenization run in parallel on GPU compute passes.
3. Glyph metrics and character coordinates are written directly to GPU storage buffers.
4. Fragment shaders rasterize glyphs in a single draw pass at a locked 120 FPS.

On a 250,000-line monorepo file:
- Ingestion into GPU storage buffers takes **0.18ms**.
- Crux scrolls smoothly at **120 FPS** with 0 dropped frames.
- Cold boot memory footprint is **38 MB** (compared to 680 MB in VS Code).

### Real-Time Collaboration: AST-CRDTs vs Character Offsets
Most collaborative editors use character-offset Operational Transformation (OT) or linear CRDTs (like RGA or YATA on raw strings). The major pain point in production pair-programming is syntax invalidation: if two engineers type concurrently inside an expression, character offsets collide, breaking the parse tree and throwing red squiggles across the entire buffer.

In Crux:
- We synchronize **Abstract Syntax Tree (AST)** mutation nodes rather than raw character streams.
- The CRDT operates over structural syntax nodes. Concurrent edits merge cleanly without bracket corruption or broken syntax trees.
- Data channels run peer-to-peer over encrypted WebRTC with zero central server routing. Keystrokes never touch a cloud database unless you run an explicit signaling relay.
- On the host machine, local thread-to-thread synchronization between the editor core and the PTY terminal runs via a 64-bit atomic ring buffer in **0.08ms**.

### Native Terminal & Local Agent Daemon
We also built a native POSIX PTY terminal daemon that detects host CLI tools (`agy` / AntiGravity, `claude` / Claude Code, `codex`) and bridges them over a local Unix domain socket (`unix:///var/run/crux.sock`). Crux is 100% air-gapped ready with zero cloud telemetry.

### Links & Technical Details
- Site & Architecture: https://codecrux.us
- Hardware Benchmarks: https://codecrux.us/benchmarks
- AST-CRDT Protocol: https://codecrux.us/ast-crdt
- Crux vs Zed: https://codecrux.us/vs-zed
- Crux vs VS Code: https://codecrux.us/vs-vscode
- Web Workstation (try in browser): https://codecrux.us/ide
- GitHub Repo: https://github.com/hrgang-hrushi/collab-editor

We'd love to answer any questions about our shader layout, ring buffer atomics, or CRDT tree merge resolution!
