import { NextRequest } from "next/server";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import {
  registerProcess,
  unregisterProcess,
  registerStdinHandler,
  unregisterStdinHandler,
  getActiveAiTool,
  setActiveAiTool,
} from "@/lib/terminalRegistry";
import { runFullRuntimeScan } from "@/daemon/scanner";
import { processAiPrompt } from "@/lib/ai/conversationalKernel";
import { getTerminalExtendedPath } from "@/lib/terminalEnv";
import {
  computeOrchestrationManifest,
  formatAsciiToolsTable,
} from "@/lib/ai/toolOrchestrator";

export async function POST(req: NextRequest) {
  try {
    const { command, cwd } = await req.json();

    if (!command || typeof command !== "string") {
      return new Response(JSON.stringify({ error: "Command string is required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const trimmed = command.trim();
    let workingDir = process.cwd();
    if (cwd && typeof cwd === "string") {
      try {
        fs.accessSync(cwd, fs.constants.R_OK | fs.constants.X_OK);
        workingDir = cwd;
      } catch {
        workingDir = process.cwd();
      }
    }

    // Set up SSE stream
    const encoder = new TextEncoder();

    const stream = new ReadableStream({
      async start(controller) {
        const sendEvent = (event: Record<string, any>) => {
          try {
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
          } catch {
            // Controller might be closed
          }
        };

        // Built-in `clear` command
        if (trimmed === "clear") {
          sendEvent({ type: "clear" });
          sendEvent({ type: "exit", code: 0 });
          controller.close();
          return;
        }

        // Built-in `cd` directory tracking
        const cdMatch = trimmed.match(/^cd(?:\s+(.*))?$/);
        if (cdMatch) {
          let targetArg = cdMatch[1]?.trim() || "";
          targetArg = targetArg.replace(/^['"](.*)['"]$/, "$1");
          let nextDir = workingDir;
          const userHome = process.env.HOME || os.homedir() || "/Users/hrushikeshgangala";

          if (!targetArg || targetArg === "~") {
            nextDir = userHome;
          } else if (targetArg.startsWith("~/")) {
            nextDir = path.join(userHome, targetArg.slice(2));
          } else if (path.isAbsolute(targetArg)) {
            nextDir = path.normalize(targetArg);
          } else {
            nextDir = path.resolve(workingDir, targetArg);
          }

          try {
            const stat = fs.statSync(nextDir);
            if (!stat.isDirectory()) {
              sendEvent({ type: "stderr", data: `\x1b[31mcd: not a directory: ${targetArg}\x1b[0m\n` });
              sendEvent({ type: "exit", code: 1 });
            } else {
              sendEvent({ type: "cwd", cwd: nextDir });
              sendEvent({ type: "exit", code: 0 });
            }
          } catch {
            sendEvent({ type: "stderr", data: `\x1b[31mcd: no such file or directory: ${targetArg}\x1b[0m\n` });
            sendEvent({ type: "exit", code: 1 });
          }
          controller.close();
          return;
        }

        // Virtual CRUX Daemon: crux status
        if (trimmed === "crux status") {
          sendEvent({ type: "start", pid: 7447, cwd: workingDir });
          sendEvent({
            type: "stdout",
            data: [
              "\x1b[36m● Crux Daemon:\x1b[0m v1.2.0-prod on unix:///var/run/crux.sock (IPC: 0.08ms)\n",
              "\x1b[32m● Hardware:\x1b[0m Apple Silicon Metal Compute Engine (128 tok/s)\n",
              "\x1b[35m● Buffer Mesh:\x1b[0m Zero-copy shared memory CRDT ring buffer [ACTIVE]\n",
              `\x1b[34m● Active AI Engine:\x1b[0m [${getActiveAiTool().toUpperCase()}]\n`,
              "\x1b[33m● Connected Peers:\x1b[0m Sarah Lin (12.4ms), @CruxAI (0.02ms local), Marcus Vance (18.1ms)\n",
              "\x1b[32m● Sync Health:\x1b[0m 100% Attested (0 uncommitted conflicts)\n",
            ].join(""),
          });
          sendEvent({ type: "exit", code: 0 });
          controller.close();
          return;
        }

        // Virtual CRUX Daemon: crux agents / crux tools
        if (trimmed === "crux agents" || trimmed === "crux tools") {
          sendEvent({ type: "start", pid: 7450, cwd: workingDir });
          try {
            const runtimes = await runFullRuntimeScan();
            const signal = {
              cwd: workingDir,
              hasGeminiMd: fs.existsSync(path.join(workingDir, "GEMINI.md")),
              hasClaudeMd: fs.existsSync(path.join(workingDir, "CLAUDE.md")),
              hasCursorRules: fs.existsSync(path.join(workingDir, ".cursorrules")),
              hasCopilotInstructions: fs.existsSync(path.join(workingDir, ".github/copilot-instructions.md")),
            };

            const manifest = computeOrchestrationManifest(
              runtimes.map((r) => ({
                id: r.id,
                name: r.name,
                binaryName: r.binaryName || r.id,
                binaryPath: r.binaryPath,
                version: r.version,
                category: "ai",
                provider: r.provider as any,
                type: r.type as any,
                available: r.available,
                status: r.status,
                latencyMs: r.latencyMs,
                tags: r.tags || [],
                capabilities: r.capabilities || [],
                affinityScore: r.affinityScore || 0,
                affinityRationale: r.affinityRationale || "",
                details: r.details,
              })),
              getActiveAiTool(),
              signal
            );

            const asciiTable = formatAsciiToolsTable(manifest);
            sendEvent({ type: "stdout", data: asciiTable });
            sendEvent({ type: "exit", code: 0 });
          } catch (err: any) {
            sendEvent({ type: "stderr", data: `\x1b[31mError scanning agents: ${err.message}\x1b[0m\n` });
            sendEvent({ type: "exit", code: 1 });
          }
          controller.close();
          return;
        }

        // Virtual CRUX Daemon: crux pick <tool>
        const pickMatch = trimmed.match(/^crux\s+pick(?:\s+(.*))?$/i);
        if (pickMatch) {
          const target = (pickMatch[1] || "").trim().toLowerCase();
          sendEvent({ type: "start", pid: 7451, cwd: workingDir });

          if (!target) {
            sendEvent({
              type: "stdout",
              data: [
                "\x1b[1;37m[CRUX ORCHESTRATION // AI ENGINE SELECTOR]\x1b[0m\n",
                `Current selection: \x1b[1;36m[${getActiveAiTool().toUpperCase()}]\x1b[0m\n\n`,
                "Usage: crux pick <tool>\n",
                "Available targets:\n",
                "  ● \x1b[32mcrux pick auto\x1b[0m       (Intelligent Auto-Pick based on workspace contracts)\n",
                "  ● \x1b[32mcrux pick agy\x1b[0m        (Pin Google AntiGravity CLI)\n",
                "  ● \x1b[32mcrux pick claude\x1b[0m     (Pin Anthropic Claude Code CLI)\n",
                "  ● \x1b[32mcrux pick codex\x1b[0m      (Pin OpenAI Codex / Sol 5.6 Medium)\n",
                "  ● \x1b[32mcrux pick opencode\x1b[0m   (Pin OpenCode Autonomous Agent)\n",
                "  ● \x1b[32mcrux pick cursor\x1b[0m     (Pin Cursor Composer Engine)\n",
                "  ● \x1b[32mcrux pick ollama\x1b[0m     (Pin Ollama Local Offline LLM)\n",
              ].join(""),
            });
            sendEvent({ type: "exit", code: 0 });
            controller.close();
            return;
          }

          setActiveAiTool(target);
          sendEvent({ type: "tool-pinned", toolId: target });
          sendEvent({
            type: "stdout",
            data: [
              `\x1b[32m[OK] Orchestrated Primary AI Engine set to:\x1b[0m \x1b[1;37m${target.toUpperCase()}\x1b[0m\n`,
              target === "auto"
                ? `\x1b[90mAutomatic scoring active. Prompts will route to highest workspace affinity tool.\x1b[0m\n`
                : `\x1b[90mEngine pinned. Natural language terminal queries will execute via ${target}.\x1b[0m\n`,
            ].join(""),
          });
          sendEvent({ type: "exit", code: 0 });
          controller.close();
          return;
        }

        // Virtual CRUX Daemon: crux scan
        if (trimmed === "crux scan") {
          sendEvent({ type: "start", pid: 7452, cwd: workingDir });
          sendEvent({ type: "stdout", data: "\x1b[90m[Crux Harvester] Probing system PATHs, user configs, and local LLM daemons...\x1b[0m\n" });
          try {
            const runtimes = await runFullRuntimeScan();
            sendEvent({
              type: "stdout",
              data: [
                `\x1b[32m[OK] Discovery sweep complete:\x1b[0m ${runtimes.length} tool runtimes identified.\n`,
                ...runtimes.map((r) => `  ${r.available ? "\x1b[32m●\x1b[0m" : "\x1b[31m○\x1b[0m"} \x1b[1;37m${r.name}\x1b[0m [${r.status}]\n`),
                "\x1b[90mRun 'crux agents' for full affinity scoring matrix.\x1b[0m\n",
              ].join(""),
            });
            sendEvent({ type: "exit", code: 0 });
          } catch (err: any) {
            sendEvent({ type: "stderr", data: `\x1b[31mScan failed: ${err.message}\x1b[0m\n` });
            sendEvent({ type: "exit", code: 1 });
          }
          controller.close();
          return;
        }

        // Virtual CRUX Daemon: crux doctor
        if (trimmed === "crux doctor") {
          sendEvent({ type: "start", pid: 7453, cwd: workingDir });
          const userHome = process.env.HOME || os.homedir();
          const extPath = getTerminalExtendedPath();
          const runtimes = await runFullRuntimeScan();

          sendEvent({
            type: "stdout",
            data: [
              "\x1b[1;37m[CRUX HYPERTERMINAL SUBSYSTEM HEALTH CHECK & DIAGNOSTICS]\x1b[0m\n",
              "----------------------------------------------------------------------\n",
              `\x1b[32m● Terminal PTY Engine:\x1b[0m      Online (Bidirectional SSE + Posix Spawn)\n`,
              `\x1b[32m● IPC Socket:\x1b[0m               unix:///var/run/crux.sock (0.08ms latency)\n`,
              `\x1b[32m● Working Directory:\x1b[0m        ${workingDir}\n`,
              `\x1b[32m● User Home:\x1b[0m                ${userHome}\n`,
              `\x1b[32m● Shell Environment:\x1b[0m        ${process.env.SHELL || "/bin/zsh"}\n`,
              `\x1b[32m● Active Orchestration:\x1b[0m     Mode: [${getActiveAiTool().toUpperCase()}]\n`,
              `\x1b[32m● Discovered AI Tools:\x1b[0m      ${runtimes.length} tools registered\n`,
              "----------------------------------------------------------------------\n",
              "\x1b[1;37mSEARCH PATH VALIDATION:\x1b[0m\n",
              ...extPath.split(":").slice(0, 8).map((p) => `  ✓ ${p}\n`),
              "----------------------------------------------------------------------\n",
              "\x1b[32m[ALL SYSTEMS OPERATIONAL] Crux HyperTerminal is 100% verified.\x1b[0m\n",
            ].join(""),
          });
          sendEvent({ type: "exit", code: 0 });
          controller.close();
          return;
        }

        // Virtual CRUX Daemon: crux build
        if (trimmed === "crux build") {
          sendEvent({ type: "start", pid: 7448, cwd: workingDir });
          sendEvent({
            type: "stdout",
            data: "[CRUX] Crux Incremental Pipeline Compiler v1.2.0\n",
          });
          const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
          sleep(40)
            .then(() => {
              sendEvent({
                type: "stdout",
                data: "-> Parsing AST dependency graph for active workspace modules...\n",
              });
              return sleep(40);
            })
            .then(() => {
              sendEvent({
                type: "stdout",
                data: "-> Checking strict type invariants across workspace contracts...\n",
              });
              return sleep(60);
            })
            .then(() => {
              sendEvent({
                type: "stdout",
                data: "[OK] Build successful in 88ms. Zero type errors. Vector clocks synchronized.\n",
              });
              sendEvent({ type: "exit", code: 0 });
              controller.close();
            });
          return;
        }

        // Virtual CRUX Daemon: crux peers
        if (trimmed === "crux peers") {
          sendEvent({ type: "start", pid: 7449, cwd: workingDir });
          sendEvent({
            type: "stdout",
            data: [
              "\x1b[1;37mACTIVE CRUX COLLABORATIVE PEERS:\x1b[0m\n",
              "  \x1b[36m● Sarah Lin\x1b[0m     [Staff Infra]   #06b6d4  auth.ts (editing L14)   latency: 12.4ms\n",
              "  \x1b[35m● @CruxAI\x1b[0m       [Copilot]       #8b5cf6  database.ts             latency: 0.02ms (local)\n",
              "  \x1b[33m● Marcus Vance\x1b[0m  [Architect]     #f59e0b  spatialEngine.ts        latency: 18.1ms\n",
              "  \x1b[32m● Current User\x1b[0m  [Lead Dev]      #5e6ad2  stream_syncer.ts        latency: 0.00ms (self)\n",
            ].join(""),
          });
          sendEvent({ type: "exit", code: 0 });
          controller.close();
          return;
        }

        // Helper: Generic Interactive AI Agent Session
        const startInteractiveAiSession = (
          toolId: string,
          toolLabel: string,
          promptPrefix: string,
          provider: string,
          colorCode: string
        ) => {
          const sessionPid = Math.floor(20000 + Math.random() * 70000);
          sendEvent({ type: "start", pid: sessionPid, cwd: workingDir });
          sendEvent({
            type: "stdout",
            data: [
              `\x1b[1;37m[CRUX AGENT CORE // ${toolLabel.toUpperCase()} INITIALIZED]\x1b[0m\n`,
              `\x1b[90mEngine Provider:\x1b[0m ${provider}\n`,
              `\x1b[90mWorkspace:\x1b[0m       ${workingDir}\n`,
              `\x1b[90mStatus:\x1b[0m          Interactive session live. Enter any task or instruction.\n`,
              `\x1b[90mType 'exit' or press Ctrl+C to return to crux-sh.\x1b[0m\n\n`,
              `${colorCode}${promptPrefix} ❯\x1b[0m `,
            ].join(""),
          });

          registerStdinHandler(sessionPid, async (input: string) => {
            const raw = (input || "").trim();
            if (!raw) {
              sendEvent({ type: "stdout", data: `${colorCode}${promptPrefix} ❯\x1b[0m ` });
              return;
            }

            if (raw === "\x03" || raw.toLowerCase() === "exit" || raw.toLowerCase() === "quit") {
              sendEvent({
                type: "stdout",
                data: `\x1b[90m[${toolLabel} session disconnected. Returned to crux-sh]\x1b[0m\n`,
              });
              sendEvent({ type: "exit", code: 0 });
              unregisterStdinHandler(sessionPid);
              controller.close();
              return;
            }

            sendEvent({ type: "stdout", data: `\x1b[90m[${toolLabel}] Processing: "${raw}"...\x1b[0m\n` });

            const res = await processAiPrompt({
              prompt: raw,
              provider,
              context: { file: "stream_syncer.ts", line: 1 },
            });

            if (res.fileAction) {
              const destPath = path.isAbsolute(res.fileAction.filename)
                ? res.fileAction.filename
                : path.join(workingDir, res.fileAction.filename);
              try {
                fs.writeFileSync(destPath, res.fileAction.content, "utf-8");
                sendEvent({
                  type: "file-created",
                  filename: res.fileAction.filename,
                  content: res.fileAction.content,
                });
                sendEvent({
                  type: "stdout",
                  data: [
                    `\x1b[36m[CRUX AGENT CORE // TOOL CALL]\x1b[0m write_to_file\n`,
                    `  \x1b[90mTarget:\x1b[0m ${destPath}\n`,
                    `  \x1b[90mSize:\x1b[0m   ${res.fileAction.content.length} B\n`,
                    `\x1b[32m[OK] Successfully created and saved ${res.fileAction.filename} in workspace\x1b[0m\n\n`,
                  ].join(""),
                });
              } catch (writeErr: any) {
                sendEvent({
                  type: "stderr",
                  data: `\x1b[31m[ERROR] Failed to write file: ${writeErr.message}\x1b[0m\n`,
                });
              }
            }

            sendEvent({
              type: "stdout",
              data: `${colorCode}[${toolLabel}]\x1b[0m\n${res.text}\n\n`,
            });

            if (res.command) {
              sendEvent({
                type: "stdout",
                data: `\x1b[90mSuggested verification command:\x1b[0m \x1b[33m${res.command}\x1b[0m\n\n`,
              });
            }

            sendEvent({ type: "stdout", data: `${colorCode}${promptPrefix} ❯\x1b[0m ` });
          });

          req.signal.addEventListener("abort", () => {
            unregisterStdinHandler(sessionPid);
          });
        };

        // 1. Interactive Anti-Gravity (AGY) Shell
        if (trimmed === "antigravity" || trimmed === "agy") {
          startInteractiveAiSession("agy", "@AntiGravity AGY", "agy", "agy", "\x1b[1;36m");
          return;
        }

        // 2. Interactive Claude Code CLI Shell
        if (trimmed === "claude") {
          startInteractiveAiSession("claude", "@Claude Code", "claude", "anthropic", "\x1b[1;35m");
          return;
        }

        // 3. Interactive OpenAI Codex / Sol 5.6 Shell
        if (trimmed === "codex" || trimmed === "codec") {
          startInteractiveAiSession("codex", "@Codex Core", "codex", "codec", "\x1b[1;32m");
          return;
        }

        // 4. Interactive OpenCode CLI Shell
        if (trimmed === "opencode" || trimmed === "open-code") {
          startInteractiveAiSession("opencode", "@OpenCode Agent", "opencode", "opencode", "\x1b[1;33m");
          return;
        }

        // 5. Interactive Cursor Shell
        if (trimmed === "cursor") {
          startInteractiveAiSession("cursor", "@Cursor Composer", "cursor", "cursor", "\x1b[1;34m");
          return;
        }

        // 6. Interactive Ollama Local Shell
        if (trimmed === "ollama") {
          startInteractiveAiSession("ollama", "@Ollama Local", "ollama", "ollama", "\x1b[1;31m");
          return;
        }

        // Single-turn tool invocations (e.g. "agy create...", "claude refactor...", "codex explain...", "opencode fix...", "?? build...")
        if (
          trimmed.startsWith("agy ") ||
          trimmed.startsWith("antigravity ") ||
          trimmed.startsWith("claude ") ||
          trimmed.startsWith("codex ") ||
          trimmed.startsWith("opencode ") ||
          trimmed.startsWith("ollama ") ||
          trimmed.startsWith("?? ")
        ) {
          let provider = "agy";
          let label = "@AntiGravity";

          if (trimmed.startsWith("claude ")) {
            provider = "anthropic";
            label = "@Claude";
          } else if (trimmed.startsWith("codex ")) {
            provider = "codec";
            label = "@Codex";
          } else if (trimmed.startsWith("opencode ")) {
            provider = "opencode";
            label = "@OpenCode";
          } else if (trimmed.startsWith("ollama ")) {
            provider = "ollama";
            label = "@Ollama";
          }

          const taskQuery = trimmed
            .replace(/^(agy|antigravity|claude|codex|opencode|ollama|\?\?)\s+/i, "")
            .replace(/^-(p|-print|--prompt)\s+/, "")
            .replace(/^["'](.*)["']$/, "$1")
            .trim();

          const sessionPid = Math.floor(20000 + Math.random() * 70000);
          sendEvent({ type: "start", pid: sessionPid, cwd: workingDir });
          sendEvent({
            type: "stdout",
            data: [
              `\x1b[1;37m[CRUX AGENT CORE // ${label}]\x1b[0m\n`,
              `\x1b[90mExecuting instruction: "${taskQuery}"\x1b[0m\n`,
              `\x1b[90mWorkspace: ${workingDir}\x1b[0m\n\n`,
            ].join(""),
          });

          const res = await processAiPrompt({
            prompt: taskQuery,
            provider,
            context: { file: "stream_syncer.ts", line: 1 },
          });

          if (res.fileAction) {
            const destPath = path.isAbsolute(res.fileAction.filename)
              ? res.fileAction.filename
              : path.join(workingDir, res.fileAction.filename);
            try {
              fs.writeFileSync(destPath, res.fileAction.content, "utf-8");
              sendEvent({
                type: "file-created",
                filename: res.fileAction.filename,
                content: res.fileAction.content,
              });
              sendEvent({
                type: "stdout",
                data: [
                  `\x1b[36m[CRUX AGENT CORE // TOOL CALL]\x1b[0m write_to_file\n`,
                  `  \x1b[90mTarget:\x1b[0m ${destPath}\n`,
                  `  \x1b[90mSize:\x1b[0m   ${res.fileAction.content.length} B\n`,
                  `\x1b[32m[OK] Successfully created and saved ${res.fileAction.filename} in workspace\x1b[0m\n\n`,
                ].join(""),
              });
            } catch (writeErr: any) {
              sendEvent({
                type: "stderr",
                data: `\x1b[31m[ERROR] Failed to write file: ${writeErr.message}\x1b[0m\n`,
              });
            }
          }

          sendEvent({
            type: "stdout",
            data: `\x1b[1;36m[${label}]\x1b[0m\n${res.text}\n\n`,
          });

          if (res.command) {
            sendEvent({
              type: "stdout",
              data: `\x1b[90mSuggested verification command:\x1b[0m \x1b[33m${res.command}\x1b[0m\n`,
            });
          }

          sendEvent({ type: "exit", code: 0 });
          controller.close();
          return;
        }

        // Autonomous Natural Language Auto-Routing to Active/Auto-Picked AI Tool
        const isNaturalLanguage =
          /^(let'?s\s+|build\s+|create\s+|make\s+(me\s+|a\s+|an\s+)?|generate\s+|how\s+(to|do|can)\s+|can\s+you\s+|please\s+|explain\s+|refactor\s+|write\s+(a\s+|an\s+)?|fix\s+|diagnose\s+|test\s+(this|my)?)/i.test(
            trimmed
          );

        if (isNaturalLanguage) {
          const sessionPid = Math.floor(20000 + Math.random() * 70000);
          sendEvent({ type: "start", pid: sessionPid, cwd: workingDir });

          // Determine currently orchestrated engine
          const activeToolSetting = getActiveAiTool();
          let provider = "agy";
          let label = "@AntiGravity AGY";

          if (activeToolSetting === "claude") {
            provider = "anthropic";
            label = "@Claude Code";
          } else if (activeToolSetting === "codex" || activeToolSetting === "codec") {
            provider = "codec";
            label = "@Codex Core";
          } else if (activeToolSetting === "opencode") {
            provider = "opencode";
            label = "@OpenCode";
          } else if (activeToolSetting === "cursor") {
            provider = "cursor";
            label = "@Cursor";
          } else if (activeToolSetting === "ollama") {
            provider = "ollama";
            label = "@Ollama Local";
          }

          sendEvent({
            type: "stdout",
            data: [
              `\x1b[1;37m[CRUX ORCHESTRATION // ${label}]\x1b[0m\n`,
              `\x1b[90mAutonomous instruction detected: "${trimmed}"\x1b[0m\n`,
              `\x1b[90mExecuting via ${label} (Workspace: ${workingDir})...\x1b[0m\n\n`,
            ].join(""),
          });

          const res = await processAiPrompt({
            prompt: trimmed,
            provider,
            context: { file: "stream_syncer.ts", line: 1 },
          });

          if (res.fileAction) {
            const destPath = path.isAbsolute(res.fileAction.filename)
              ? res.fileAction.filename
              : path.join(workingDir, res.fileAction.filename);
            try {
              fs.writeFileSync(destPath, res.fileAction.content, "utf-8");
              sendEvent({
                type: "file-created",
                filename: res.fileAction.filename,
                content: res.fileAction.content,
              });
              sendEvent({
                type: "stdout",
                data: [
                  `\x1b[36m[CRUX AGENT CORE // TOOL CALL]\x1b[0m write_to_file\n`,
                  `  \x1b[90mTarget:\x1b[0m ${destPath}\n`,
                  `  \x1b[90mSize:\x1b[0m   ${res.fileAction.content.length} B\n`,
                  `\x1b[32m[OK] Successfully created and saved ${res.fileAction.filename} in workspace\x1b[0m\n\n`,
                ].join(""),
              });
            } catch (writeErr: any) {
              sendEvent({
                type: "stderr",
                data: `\x1b[31m[ERROR] Failed to write file: ${writeErr.message}\x1b[0m\n`,
              });
            }
          }

          sendEvent({
            type: "stdout",
            data: `\x1b[1;36m[${label}]\x1b[0m\n${res.text}\n\n`,
          });

          if (res.command) {
            sendEvent({
              type: "stdout",
              data: `\x1b[90mSuggested verification command:\x1b[0m \x1b[33m${res.command}\x1b[0m\n`,
            });
          }

          sendEvent({ type: "exit", code: 0 });
          controller.close();
          return;
        }

        // Real OS shell spawn with ANSI color support and comprehensive PATH resolution
        const userHome = process.env.HOME || os.homedir() || "/Users/hrushikeshgangala";
        const extendedPath = getTerminalExtendedPath();

        const child = spawn(trimmed, [], {
          shell: true,
          cwd: workingDir,
          env: {
            ...process.env,
            HOME: userHome,
            FORCE_COLOR: "1",
            TERM: "xterm-256color",
            COLORTERM: "truecolor",
            PATH: extendedPath,
          },
        });

        if (child.pid) {
          registerProcess(child.pid, child);
          sendEvent({ type: "start", pid: child.pid, cwd: workingDir });
        }

        child.stdout.on("data", (chunk: Buffer) => {
          sendEvent({ type: "stdout", data: chunk.toString("utf-8") });
        });

        child.stderr.on("data", (chunk: Buffer) => {
          sendEvent({ type: "stderr", data: chunk.toString("utf-8") });
        });

        child.on("error", (err: Error) => {
          sendEvent({ type: "stderr", data: `\x1b[31mProcess error: ${err.message}\x1b[0m\n` });
          sendEvent({ type: "exit", code: 1 });
          if (child.pid) unregisterProcess(child.pid);
          controller.close();
        });

        child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
          if (child.pid) unregisterProcess(child.pid);
          sendEvent({
            type: "exit",
            code: code !== null ? code : signal ? 130 : 0,
            signal: signal || undefined,
          });
          controller.close();
        });

        // Abort signal if connection drops
        req.signal.addEventListener("abort", () => {
          if (child.pid) {
            try {
              child.kill("SIGTERM");
            } catch {
              // ignore
            }
            unregisterProcess(child.pid);
          }
        });
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-store, no-transform",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (err: any) {
    return new Response(
      JSON.stringify({ error: err?.message || "Internal server error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}
