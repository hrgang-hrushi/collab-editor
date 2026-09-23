import { NextRequest } from "next/server";
import { spawn } from "child_process";
import fs from "fs";
import { registerProcess, unregisterProcess } from "@/lib/terminalRegistry";

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

        if (trimmed === "crux build") {
          sendEvent({ type: "start", pid: 7448, cwd: workingDir });
          sendEvent({
            type: "stdout",
            data: "\x1b[1;36m⚡ Crux Incremental Pipeline Compiler v1.2.0\x1b[0m\n",
          });
          const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
          // Drive all stages as chained promises so the stream stays alive
          sleep(40)
            .then(() => {
              sendEvent({
                type: "stdout",
                data: "→ Parsing AST dependency graph for 5 active modules...\n",
              });
              return sleep(40);
            })
            .then(() => {
              sendEvent({
                type: "stdout",
                data: "→ Checking strict type invariants across stream_syncer.ts ↔ auth.ts...\n",
              });
              return sleep(60);
            })
            .then(() => {
              sendEvent({
                type: "stdout",
                data: "\x1b[32m✓ Build successful in 88ms. Zero type errors. Vector clocks synchronized.\x1b[0m\n",
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

        // Real OS shell spawn with ANSI color support
        const child = spawn(trimmed, [], {
          shell: true,
          cwd: workingDir,
          env: {
            ...process.env,
            FORCE_COLOR: "1",
            TERM: "xterm-256color",
            COLORTERM: "truecolor",
            PATH: `/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:${process.env.PATH || "/usr/bin:/bin:/usr/sbin:/sbin"}`,
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
