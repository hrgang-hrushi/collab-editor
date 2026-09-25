import { NextRequest } from "next/server";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import {
  registerProcess,
  unregisterProcess,
  registerStdinHandler,
  unregisterStdinHandler,
} from "@/lib/terminalRegistry";
import { runFullRuntimeScan } from "@/daemon/scanner";
import { processAiPrompt } from "@/lib/ai/conversationalKernel";

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
      start(controller) {
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
          const userHome = process.env.HOME || "/Users/hrushikeshgangala";

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

        // Virtual CRUX Daemon commands
        if (trimmed === "crux status") {
          sendEvent({ type: "start", pid: 7447, cwd: workingDir });
          sendEvent({
            type: "stdout",
            data: [
              "\x1b[36m● Crux Daemon:\x1b[0m v1.2.0-prod on unix:///var/run/crux.sock (IPC: 0.08ms)\n",
              "\x1b[32m● Hardware:\x1b[0m Apple Silicon Metal Compute Engine (128 tok/s)\n",
              "\x1b[35m● Buffer Mesh:\x1b[0m Zero-copy shared memory CRDT ring buffer [ACTIVE]\n",
              "\x1b[33m● Connected Peers:\x1b[0m Sarah Lin (12.4ms), @CruxAI (0.02ms local), Marcus Vance (18.1ms)\n",
              "\x1b[32m● Sync Health:\x1b[0m 100% Attested (0 uncommitted conflicts)\n",
            ].join(""),
          });
          sendEvent({ type: "exit", code: 0 });
          controller.close();
          return;
        }

        if (trimmed === "crux agents") {
          sendEvent({ type: "start", pid: 7450, cwd: workingDir });
          runFullRuntimeScan()
            .then((runtimes) => {
              const lines = [
                "\x1b[1;37m[CRUX DISCOVERED AI AGENTS & COMPUTE RUNTIMES]\x1b[0m\n",
                "----------------------------------------------------------------------\n",
              ];
              if (!runtimes || runtimes.length === 0) {
                lines.push("  \x1b[33mNo external AI runtimes detected. Defaulting to @CruxAI (Built-in).\x1b[0m\n");
              } else {
                runtimes.forEach((r) => {
                  const statusDot = r.available ? "\x1b[32m● ONLINE \x1b[0m" : "\x1b[31m○ OFFLINE\x1b[0m";
                  const configTag = r.details?.hasGeminiMd ? " \x1b[35m[GEMINI.md]\x1b[0m" : r.details?.hasCursorRules ? " \x1b[35m[.cursorrules]\x1b[0m" : r.details?.hasClaudeMd ? " \x1b[35m[CLAUDE.md]\x1b[0m" : "";
                  lines.push(
                    `  ${statusDot} \x1b[1;36m${r.name.padEnd(36)}\x1b[0m [${r.provider.toUpperCase().padEnd(9)}] ${configTag}\n`
                  );
                });
              }
              lines.push("----------------------------------------------------------------------\n");
              lines.push("\x1b[90mExecute in shell: 'antigravity', 'claude', 'npm test', 'git status'\x1b[0m\n");
              sendEvent({ type: "stdout", data: lines.join("") });
              sendEvent({ type: "exit", code: 0 });
              controller.close();
            })
            .catch((err) => {
              sendEvent({ type: "stderr", data: `\x1b[31mError scanning agents: ${err.message}\x1b[0m\n` });
              sendEvent({ type: "exit", code: 1 });
              controller.close();
            });
          return;
        }

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
                data: "-> Parsing AST dependency graph for 5 active modules...\n",
              });
              return sleep(40);
            })
            .then(() => {
              sendEvent({
                type: "stdout",
                data: "-> Checking strict type invariants across stream_syncer.ts <-> auth.ts...\n",
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

        // Interactive Anti-Gravity (AGY) Agent Core Terminal Shell
        if (trimmed === "antigravity" || trimmed === "agy") {
          const sessionPid = Math.floor(20000 + Math.random() * 70000);
          sendEvent({ type: "start", pid: sessionPid, cwd: workingDir });
          sendEvent({
            type: "stdout",
            data: [
              "\x1b[1;37m[CRUX AGENT CORE // ANTIGRAVITY AGY v1.2.9 INITIALIZED]\x1b[0m\n",
              "\x1b[90mHost Binary: /Users/hrushikeshgangala/.local/bin/antigravity\x1b[0m\n",
              "\x1b[90mEngine: Local IPC Socket unix:///var/run/crux.sock (0.08ms)\x1b[0m\n",
              "\x1b[90mSkills: crux-design-system, code-review-and-quality, modern-web-guidance\x1b[0m\n",
              "----------------------------------------------------------------------\n",
              "\x1b[1;36m[@AntiGravity]\x1b[0m Ready. Enter any task, query, or type 'exit' to return to shell.\n\n",
            ].join(""),
          });

          registerStdinHandler(sessionPid, async (input: string) => {
            const raw = (input || "").trim();
            if (!raw) return;

            if (raw === "\x03" || raw.toLowerCase() === "exit" || raw.toLowerCase() === "quit") {
              sendEvent({
                type: "stdout",
                data: "\x1b[90m[Anti-Gravity interactive session disconnected. Returned to crux-sh]\x1b[0m\n",
              });
              sendEvent({ type: "exit", code: 0 });
              unregisterStdinHandler(sessionPid);
              controller.close();
              return;
            }

            sendEvent({ type: "stdout", data: "\x1b[90m[@AntiGravity] Processing task...\x1b[0m\n" });

            const res = await processAiPrompt({
              prompt: raw,
              provider: "agy",
              context: { file: "stream_syncer.ts", line: 1 },
            });

            sendEvent({
              type: "stdout",
              data: `\x1b[1;36m[@AntiGravity]\x1b[0m\n${res.text}\n\n`,
            });
          });

          req.signal.addEventListener("abort", () => {
            unregisterStdinHandler(sessionPid);
          });
          return;
        }

        // Interactive Claude Code CLI Shell
        if (trimmed === "claude") {
          const sessionPid = Math.floor(20000 + Math.random() * 70000);
          sendEvent({ type: "start", pid: sessionPid, cwd: workingDir });
          sendEvent({
            type: "stdout",
            data: [
              "\x1b[1;37m[CLAUDE CODE CLI // ANTHROPIC SONNET 3.5 INITIALIZED]\x1b[0m\n",
              "\x1b[90mBinary: /Users/hrushikeshgangala/.local/bin/claude\x1b[0m\n",
              "\x1b[90mType any instruction for Claude, or 'exit' / Ctrl+C to return to shell.\x1b[0m\n\n",
            ].join(""),
          });

          registerStdinHandler(sessionPid, async (input: string) => {
            const raw = (input || "").trim();
            if (!raw) return;

            if (raw === "\x03" || raw.toLowerCase() === "exit" || raw.toLowerCase() === "quit") {
              sendEvent({
                type: "stdout",
                data: "\x1b[90m[Claude session terminated. Returned to crux-sh]\x1b[0m\n",
              });
              sendEvent({ type: "exit", code: 0 });
              unregisterStdinHandler(sessionPid);
              controller.close();
              return;
            }

            sendEvent({ type: "stdout", data: "\x1b[90m[@Claude] Processing task...\x1b[0m\n" });

            const res = await processAiPrompt({
              prompt: raw,
              provider: "anthropic",
              context: { file: "auth.ts", line: 1 },
            });

            sendEvent({
              type: "stdout",
              data: `\x1b[1;35m[@Claude]\x1b[0m\n${res.text}\n\n`,
            });
          });

          req.signal.addEventListener("abort", () => {
            unregisterStdinHandler(sessionPid);
          });
          return;
        }

        // Real OS shell spawn with ANSI color support and comprehensive PATH resolution
        const userHome = process.env.HOME || "/Users/hrushikeshgangala";
        const extendedPath = [
          `${userHome}/.local/bin`,
          `${userHome}/.cargo/bin`,
          `${userHome}/.gemini/antigravity-cli/bin`,
          `/opt/homebrew/bin`,
          `/opt/homebrew/sbin`,
          `/usr/local/bin`,
          process.env.PATH || "",
          `/usr/bin`,
          `/bin`,
          `/usr/sbin`,
          `/sbin`,
        ].filter(Boolean).join(":");

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
