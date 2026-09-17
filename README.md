# Crux Studio — Spatial Collaborative Architecture & Code Engine

> A high-performance, multiplayer-first coding environment merging the fluid, inline collaborative experience of Google Docs & Figma with a professional developer IDE, sandboxed code runner, multi-session terminal, autonomous coding agents, and infinite spatial architecture canvas.

---

## ⚡ Key Highlights & Capabilities

### 1. Dual-State Paradigm (Zenith IDE ↔ Nexus Spatial Canvas)
- **Zenith (IDE Shell):** Ultra-minimalist dark workstation with hierarchical file tree, multi-tab editor, CodeMirror 6 code engine, and integrated multi-session terminal suite.
- **Nexus Spatial Canvas (`Cmd+Space`):** Infinite 2D architectural plane to visualize multi-file dependencies, data flow, and live collaborative editing across visual code nodes.
- **Dynamic Wires & Connector Layer:** Animated cubic Bezier connector arrows linking modules to visually map imports and dataflow.

### 2. Full IDE & File System Capabilities
- **Web File System Access API:** Open any folder from your computer directly into the IDE with native browser directory pickers.
- **Hierarchical Nested File Tree:** Full folder hierarchies, breadcrumb navigation, quick file filter (`Filter files...`), drag-and-drop file/folder ingestion, and atomic ZIP export.
- **Live Code Execution:** Sandboxed Node.js and TypeScript runner supporting multi-file imports, transpilations, and live stdout/stderr capture.

### 3. Autonomous Coding Agent (`@CruxAI` · `Cmd+I`)
- **Multi-Step Reasoning:** Displays real-time chain-of-thought steps (Topology inspection → AST analysis → Speculative synthesis → Contract verification).
- **Interactive Diff Proposals:** Proposes structured code diffs with visual patch previews.
- **One-Click Patch Application:** Apply proposed diffs directly into the active buffer with tactile haptic confirmation.
- **One-Click Generator:** Optimize performance, inject defensive guard rails, or generate automated Vitest suites.

### 4. Multi-Session Virtual Terminal Suite
- **Multi-Instance Shells:** Spawn multiple isolated terminal sessions (`bash: 1`, `bash: 2`, `+ New Terminal`) with independent command histories and directories.
- **Built-in CLI Utilities:** `help`, `node <file>`, `run <file>`, `test` (Vitest runner), `cat`, `ls [-la]`, `cd`, `pwd`, `mkdir`, `touch`, `rm`, `echo`, `grep`, `git status`, `git commit`, `git log`, `git diff`, `haptics on/off`.
- **Node REPL:** In-memory interactive JavaScript REPL with live evaluation of workspace variables.
- **Daemon IPC Stream:** High-frequency event feed simulating local socket memory and hardware acceleration.

### 5. Tactile Haptic & Micro-Acoustic Engine
- **Web Haptics API:** Physical vibration pulses on supported trackpads and mobile devices.
- **Procedural Audio Synthesizer:** Real-time synthesized tactile micro-acoustics via the Web Audio API (mechanical switch clicks, keystroke ticks, run charging pulses, success chimes, and error thuds) with 0 external audio assets.
- **Quick Toggle:** Accessible via the top header button, status bar toggle, or `haptics on/off` shell command.

### 6. Design System & Typography
- **Typography:** **Hanken Grotesk** & **Space Grotesk** geometric display typography paired with crisp monospace code font.
- **Animations:** Smooth spring physics and transitions powered by **Framer Motion**.
- **Dark Precision Theme:** Flat surfaces with strict 1px hairline borders inspired by Linear and Vercel.

---

## ⌨️ Essential Keyboard Shortcuts

- `Cmd + Space`: Toggle between Zenith (IDE) and Nexus (Canvas)
- `Cmd + K`: Instant Command Palette & file switcher
- `Cmd + I`: Toggle CruxAI Autonomous Coding Agent
- `Cmd + Enter`: Run active file in sandboxed code runner
- `Cmd + S`: Save active file buffer to disk
- `Cmd + B`: Toggle File Explorer Sidebar
- `Cmd + J`: Toggle Terminal & Daemon Drawer
- `Space + Drag`: Pan infinite spatial canvas
- `Cmd / Ctrl + Wheel`: Smooth zoom in / out centered on cursor

---

## 🛠️ Tech Stack

- **Framework:** Next.js 14 (App Router)
- **UI & Animation:** React 18, TypeScript, Tailwind CSS, Framer Motion, Lucide Icons
- **Code Engine:** CodeMirror 6 (`@codemirror/view`, `@codemirror/state`, `@codemirror/language`)
- **State Management:** Zustand
- **Multiplayer & CRDTs:** Yjs, y-webrtc, y-websocket
- **File Utilities:** JSZip, Web File System Access API
- **Audio & Haptics:** Web Audio API procedural synthesis, Web Haptics API

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/hrgang-hrushi/collab-editor.git

# 2. Install dependencies
cd collab-editor
npm install

# 3. Start development server
npm run dev

# 4. Open in browser
http://localhost:3000
```
