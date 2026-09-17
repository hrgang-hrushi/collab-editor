# Collaborative IDE: Architecture & UI/UX Master Blueprint

**Role:** Principal Product Designer & Lead Full-Stack Engineer  
**Workspace:** `/Users/hrushikeshgangala/Downloads/collab-editor-main`  
**Target:** Production-Grade High-Performance Multiplayer Web IDE  

---

## 1. Executive Summary & Critical Engineering Decisions

| Dimension | Legacy / Naive Approach | Our Production Architecture | Rationale |
| :--- | :--- | :--- | :--- |
| **Editor Core** | Monaco Editor (VS Code core) | **CodeMirror 6 (CM6)** | Monaco consumes ~100MB+ per instance and thrashes the DOM in a zoomable canvas. CM6 is lightweight, functional, headless, and handles 30+ simultaneous editors at 60fps. |
| **CRDT Engine** | Automerge or manual OT | **Yjs (`Y.Doc`, `Y.Text`, `Y.Map`)** | Yjs benchmarks 10–20x faster in text manipulation, has atomic transactions, relative position encoding, and battle-tested WebSocket sync. |
| **Anchoring** | Line/Column numbers (`{line, col}`) | **`Y.RelativePosition`** | Raw line numbers break on concurrent edits. Relative positions attach to immutable CRDT character IDs and drift gracefully with mutations. |
| **Multiplayer Cursors** | 120Hz raw coordinate broadcast | **40Hz Quantized + Local Spring Lerp** | Prevents network packet congestion while guaranteeing butter-smooth 60–120 FPS cursor interpolation on client screens. |
| **Canvas Viewport** | Heavy WebGL or unvirtualized DOM | **CSS 3D Transforms + LOD Matrix** | Uses hardware-accelerated `translate3d` and dynamic 3-tier Level of Detail (LOD) to cull off-screen DOM nodes. |

---

## 2. System Architecture & CRDT Data Hierarchy

```
┌────────────────────────────────────────────────────────────────────────┐
│                              WORKSPACE Y.DOC                           │
│                                                                        │
│  ├── canvas (Y.Map)                                                    │
│  │    ├── nodes: Y.Map<CanvasNode>                                     │
│  │    ├── edges: Y.Array<CanvasEdge>                                   │
│  │    └── viewport: Y.Map<{ panX, panY, zoom }>                        │
│  │                                                                     │
│  ├── files (Y.Map)                                                     │
│  │    └── [fileId]: { id, path, content: Y.Text, language }            │
│  │                                                                     │
│  ├── suggestions (Y.Array<InlineSuggestion>)                           │
│  │    └── { id, fileId, author, anchorStart, anchorEnd, ... }          │
│  │                                                                     │
│  ├── comments (Y.Array<CommentThread>)                                 │
│  │    └── { id, fileId, authorId, anchor, messages: Y.Array }          │
│  │                                                                     │
│  └── awareness (Yjs Awareness Protocol)                                │
│       └── ephemeral state: { cursor: {x,y}, activeFile, userProfile }   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Mechanics Technical Specification

### 3.1 Spatial Multiplayer Cursors
- **Physics Formula:** Remote positions are updated as target vectors, rendered via `requestAnimationFrame` using damped harmonic oscillation:
  $$a = (x_{\text{target}} - x) \cdot k - v \cdot d$$
  $$v \leftarrow v + a \cdot \Delta t, \quad x \leftarrow x + v \cdot \Delta t$$
  *(Constants: $k = 320$, $d = 28$)*
- **Visuals:** SVG arrow caret with a dynamic linear gradient, soft glow drop shadow, and glassmorphic pill badge showing the user's name tag. Name tag auto-dims when hovering over the local user's active typing area.

### 3.2 Inline Suggestion Engine (Google Docs Style for Code)
- **Suggesting Mode Trigger:** Switched via top-bar badge or `Cmd+Option+X`.
- **Interception Pipeline:** A CodeMirror 6 `transactionFilter` traps insertions and deletions:
  - Deletions are transformed into `Decoration.mark` with a neon rose wash (`#fda4af` with strikethrough).
  - Additions are marked with a neon emerald wash (`#6ee7b7` with subtle underline).
- **Inline Action HUD:** A floating glassmorphic widget displays the author's avatar, timestamp, and inline **[Accept ✓]** / **[Reject ✕]** triggers (`Cmd+Shift+Y` / `Cmd+Shift+N`).
- **Atomic Commits:** Accepting dispatches an atomic `yDoc.transact()` replacing the original text range in the underlying `Y.Text` buffer.

### 3.3 Contextual Living Comment Threads
- **Anchoring:** Generated via `Y.createRelativePositionFromTypeIndex`. Moving code up or down automatically shifts the relative anchor.
- **Screen Projection:** Editor invokes `editorView.coordsAtPos(absIndex)` to place the glassmorphic comment card in the margin.
- **Vertical Relaxation Algorithm:** When adjacent lines have comments, a 1D repulsion pass prevents card overlaps, drawing flexed SVG bezier wires from the code line to the card.

### 3.4 Canvas Mode (Spatial Multi-File Navigation)
- **Zoom & Pan Controls:** Infinite spatial plane managed with `transform: translate3d(panX, panY, 0) scale(zoom)`.
- **Level of Detail (LOD):**
  - `zoom >= 0.7`: Fully interactive CodeMirror 6 editors.
  - `0.35 <= zoom < 0.7`: Read-only lightweight tokenized syntax previews.
  - `zoom < 0.35`: High-performance 2D canvas silhouettes with file icons and status badges.
- **Architectural Connectors:** Dynamic cubic Bezier arrows linking export symbols in File A to import statements in File B.

---

## 4. UI/UX Design System: Dark Glassmorphism

- **Typography:**
  - UI: `SF Pro Display` & `SF Pro Text` (`-apple-system`, letter-spacing: `-0.015em`).
  - Code Editor: `Commit Mono` or `Geist Mono` with circular dot-matrix zero styling (`zero`, `ss01`).
- **Glassmorphism Spec:**
  ```css
  background: rgba(15, 18, 25, 0.75);
  backdrop-filter: blur(20px) saturate(190%);
  border: 1px solid rgba(255, 255, 255, 0.08);
  box-shadow: 0 24px 48px -12px rgba(0, 0, 0, 0.75), inset 0 1px 0 0 rgba(255, 255, 255, 0.1);
  ```
- **Color Accents:** Deep void black background (`#060709`), editor surface (`#0D0F14`), collaborative neon cursors (Cyan `#00F0FF`, Magenta `#FF007A`, Emerald `#10B981`, Amber `#F59E0B`, Purple `#8B5CF6`).

---

## 5. Directory Structure & Technology Stack

- **Framework:** Next.js 15 (App Router), React 19, TypeScript
- **Styling:** Tailwind CSS v4, Framer Motion
- **Editor:** CodeMirror 6 (`@codemirror/view`, `@codemirror/state`, `@codemirror/language`)
- **CRDT & Sync:** `yjs`, `y-codemirror.next`, `y-websocket`, `y-webrtc`
- **State Management:** `zustand`, `jotai`
