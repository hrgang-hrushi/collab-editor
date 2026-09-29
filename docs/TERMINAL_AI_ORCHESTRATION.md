# Crux HyperTerminal & AI Coding Tool Orchestration Architecture

## 1. System Overview

Crux features a **Bare-Metal POSIX HyperTerminal** deeply integrated with an **Autonomous AI Coding Tool Discovery and Orchestration Subsystem**.

Rather than locking developers into a single proprietary assistant or an isolated web chat panel, Crux's terminal kernel automatically scans, identifies, scores, and orchestrates the AI coding tools and CLIs already configured on the user's host machine (such as **Google AntiGravity / AGY**, **Anthropic Claude Code**, **OpenAI Codex**, **OpenCode**, **Cursor**, and local **Ollama** models).

```
+---------------------------------------------------------------------------------------------------------+
|                                        CRUX HYPERTERMINAL SUBSYSTEM                                     |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|  [ TOP TOOLBAR & ORCHESTRATION HUD ]                                                                    |
|  +---------------------------------------------------------------------------------------------------+  |
|  | [AI ENGINE: ⚡ AUTO // AGY v1.2.12 ▼]  [● agy]  [● claude]  [● codex]  [● opencode]  [crux tools]  |  |
|  +---------------------------------------------------------------------------------------------------+  |
|                                                    |                                                    |
|                                                    v                                                    |
|  [ UNIFIED DISCOVERY & PROBE DAEMON ]                                                                    |
|  +---------------------------------------------------------------------------------------------------+  |
|  | Probes:                                                                                           |  |
|  | - Binaries: antigravity, agy, claude, codex, codec, opencode, cursor, gh, ollama, etc.            |  |
|  | - System paths: ~/.local/bin, ~/.npm-global/bin, ~/.bun/bin, /opt/homebrew/bin, etc.               |  |
|  | - User configurations: ~/.gemini, ~/.claude, ~/.codex, ~/.openclaw, ~/.cursor, etc.              |  |
|  | - Workspace contracts: GEMINI.md, CLAUDE.md, .cursorrules, .github/copilot-instructions           |  |
|  | - Local LLM daemons: Ollama (11434), OpenClaw (8000), LocalAI, vLLM                              |  |
|  | - Cloud SDKs & Env: AWS Bedrock chain, OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY           |  |
|  +---------------------------------------------------------------------------------------------------+  |
|                                                    |                                                    |
|                                                    v                                                    |
|  [ SMART AUTO-PICK & ORCHESTRATION ENGINE ]                                                             |
|  +---------------------------------------------------------------------------------------------------+  |
|  | Multi-Factor Affinity Scoring:                                                                    |  |
|  | 1. Verified Local Host Binary on PATH (+35 pts)                                                   |  |
|  | 2. 0ms Local Execution Latency (+15 pts)                                                          |  |
|  | 3. Workspace Contract Alignment (+45 pts for GEMINI.md/CLAUDE.md/.cursorrules)                     |  |
|  | 4. Autonomous Agent Capabilities (+15 pts)                                                        |  |
|  |                                                                                                   |  |
|  | Result: Primary Active Tool (Auto-Picked or User-Pinned Override)                                 |  |
|  +---------------------------------------------------------------------------------------------------+  |
|                                                    |                                                    |
|                                                    v                                                    |
|  [ EXECUTION & DISPATCH SUBSYSTEM ]                                                                      |
|  +---------------------------------------------------------------------------------------------------+  |
|  | 1. Shell Mode: Standard POSIX / zsh commands (git, npm, bun, python3, cargo, etc.)                |  |
|  | 2. Interactive Tool Shells: 'agy', 'claude', 'codex', 'opencode', 'cursor', 'ollama'                 |  |
|  |    -> Live bidirectional stdin/stdout streaming with signals (Ctrl+C, Ctrl+D)                     |  |
|  | 3. Natural Language Autonomous Routing:                                                            |  |
|  |    -> Prompts execute via active engine with workspace context & tool calling                     |  |
|  | 4. Crux Commands:                                                                                 |  |
|  |    -> 'crux tools' / 'crux agents': ASCII Hardware Brutalism matrix of all discovered tools       |  |
|  |    -> 'crux pick <tool>': Pin primary engine (e.g. crux pick claude, crux pick auto)              |  |
|  |    -> 'crux scan': Real-time deep probe of computer tools                                         |  |
|  |    -> 'crux doctor': Terminal diagnostics & environment validation                                 |  |
|  +---------------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------------+
```

---

## 2. Host Discovery & CLI Harvester Engine

Located in [`daemon/scanner.ts`](file:///Users/hrushikeshgangala/Projects/collab-editor-main/daemon/scanner.ts) (Web & Node) and [`src-tauri/src/cli_discovery.rs`](file:///Users/hrushikeshgangala/Projects/collab-editor-main/src-tauri/src/cli_discovery.rs) (Desktop Tauri), the harvester scans the host system:

### Target Probing Matrix:
1. **Google AntiGravity / AGY CLI**:
   - Probes: `~/.local/bin/antigravity`, `~/.local/bin/agy`, `~/.gemini/antigravity-cli/bin`, `/opt/homebrew/bin/agy`, `/usr/local/bin/agy`.
   - Runs `--version` to verify execution.
   - Probes user directory `~/.gemini` and workspace contract `GEMINI.md`.
2. **Anthropic Claude Code CLI**:
   - Probes: `~/.local/bin/claude`, `/opt/homebrew/bin/claude`, `/usr/local/bin/claude`.
   - Runs `--version`.
   - Probes user directory `~/.claude`, `~/.config/claude`, and workspace contract `CLAUDE.md`.
3. **OpenAI Codex / Sol 5.6 Medium**:
   - Probes: `~/.npm-global/bin/codex`, `/usr/local/bin/codex`, `~/.codex`.
   - Runs `--version`.
4. **OpenCode CLI**:
   - Probes: `~/.npm-global/bin/opencode`, `~/.npm-global/bin/open-code`, `~/.opencode`.
   - Runs `--version`.
5. **Cursor CLI & Composer**:
   - Probes: `/usr/local/bin/cursor`, `~/.cursor`, `~/Library/Application Support/Cursor`, `.cursorrules`.
   - Runs `--version`.
6. **Ollama Local LLM Engine**:
   - Probes: `/usr/local/bin/ollama`, `~/.ollama`.
   - Probes HTTP API `http://127.0.0.1:11434/api/tags` to list installed offline models.
7. **OpenClaw Agent Core**:
   - Probes: `~/.openclaw`, `~/.local/bin/openclaw`, and port `8000`.
8. **GitHub Copilot / CLI**:
   - Probes: `gh auth status` and Copilot keychain credentials.
9. **Cloud SDKs & Environment Variables**:
   - AWS Bedrock provider chain, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`.

---

## 3. The Intelligent Auto-Pick Scoring Engine

Located in [`lib/ai/toolOrchestrator.ts`](file:///Users/hrushikeshgangala/Projects/collab-editor-main/lib/ai/toolOrchestrator.ts):

### Scoring Algorithm:
$$\text{Score} = \text{BinaryVerified} (35) + \text{LocalLatency} (15) + \text{WorkspaceContractMatch} (45) + \text{Capabilities} (15)$$

- **Contract Alignment**:
  - `GEMINI.md` present in workspace $\to$ **AntiGravity AGY** receives $+45$ points.
  - `CLAUDE.md` present $\to$ **Claude Code** receives $+45$ points.
  - `.cursorrules` present $\to$ **Cursor** receives $+40$ points.
- **Auto-Pick Selection**:
  The tool with the highest score is automatically selected as the **Primary AI Engine** (`autoPickedTool`).
- **User Override**:
  Users can pin any tool via the HUD dropdown or terminal command `crux pick <tool>`. Running `crux pick auto` restores intelligent scoring.

---

## 4. HyperTerminal Commands & Capabilities

The terminal natively supports:

| Command | Action |
| :--- | :--- |
| `crux tools` / `crux agents` | Renders the Hardware Brutalism ASCII tools matrix with paths, versions, and scores |
| `crux pick auto` | Resets orchestration to intelligent Auto-Pick mode |
| `crux pick <tool>` | Pins primary AI engine (e.g. `crux pick claude`, `crux pick agy`) |
| `crux scan` | Forces a deep real-time sweep of all computer tools |
| `crux doctor` | Validates POSIX shell, PTY subsystem, search PATHs, and tool health |
| `crux status` | Inspects daemon status, IPC socket, and peer latency |
| `agy` / `antigravity` | Launches interactive AntiGravity AGY REPL |
| `claude` | Launches interactive Claude Code CLI REPL |
| `codex` | Launches interactive Codex REPL |
| `opencode` | Launches interactive OpenCode REPL |
| `cursor` | Launches interactive Cursor REPL |
| `ollama` | Launches interactive Ollama REPL |
| `<natural language>` | Auto-routes instructions (e.g. "fix auth.ts") to the active engine |
| `<shell commands>` | Live execution of POSIX commands (`git`, `npm`, `cargo`, `bun`, `python3`, etc.) |

---

## 5. UI/UX Hardware Brutalism HUD Specifications

Implemented in [`components/crux/zenith/ZenithTerminal.tsx`](file:///Users/hrushikeshgangala/Projects/collab-editor-main/components/crux/zenith/ZenithTerminal.tsx):
- **Universal 0px Border Radius**: Strict brutalist styling without rounded corners.
- **Monochrome Material Palette**: `#000000` (The Void), `#FFFFFF` (The Silk), `#111111` (Deep Silicon), `#222222` (The Grid).
- **AI Engine HUD & Dropdown**:
  - Live indicator displaying `[AI: ⚡ AUTO // AGY v1.2.12]` or `[AI: 📌 CLAUDE v2.1.91]`.
  - Dropdown listing all detected tools with latency and versions.
- **Dynamic Quick-Action Bar**:
  - Dynamic clickable pills for every discovered tool on the user's computer: `[⚡ AUTO]` `[● agy]` `[● claude]` `[● codex]` `[● opencode]` `[● cursor]` `[● ollama]` `[crux tools]` `[crux doctor]`.
- **Full Duplex Interactive Prompts**:
  - Supports `agy ❯ `, `claude ❯ `, `codex ❯ `, `opencode ❯ `, `cursor ❯ `, `ollama ❯ `, and `crux-sh:~$`.
  - Ctrl+C process interruption and signal handling.
  - Interactive stdin writing.
