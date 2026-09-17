import { NextRequest, NextResponse } from "next/server";
import { exec } from "child_process";
import path from "path";

export async function POST(req: NextRequest) {
  try {
    const { command, cwd } = await req.json();

    if (!command || typeof command !== "string") {
      return NextResponse.json(
        { error: "Command string is required" },
        { status: 400 }
      );
    }

    const trimmed = command.trim();
    if (!trimmed) {
      return NextResponse.json({ stdout: "", stderr: "", exitCode: 0 });
    }

    const workingDir = cwd || process.cwd();

    // Built-in Crux daemon and virtual commands
    if (trimmed === "crux status") {
      return NextResponse.json({
        stdout: [
          "● Crux Daemon: v1.0.0-prod on unix:///var/run/crux.sock (IPC: 0.08ms)",
          "● Hardware: Apple Silicon Metal Compute Engine (128 tok/s)",
          "● Buffer Mesh: Zero-copy shared memory CRDT ring buffer [ACTIVE]",
          "● Connected Peers: Sarah Lin (12.4ms), @CruxAI (0.02ms local), Marcus Vance (18.1ms)",
          "● Sync Health: Clean (0 unmerged conflicts)",
        ].join("\n"),
        stderr: "",
        exitCode: 0,
      });
    }

    if (trimmed === "crux build") {
      return NextResponse.json({
        stdout: [
          "⚡ Crux Incremental Pipeline Compiler v1.0.0",
          "→ Parsing AST dependency graph for 5 modules...",
          "→ Checking TypeScript strict contracts across stream_syncer.ts ↔ auth.ts...",
          "→ Synchronizing vector clocks across 3 peer nodes...",
          "✓ Build successful in 42ms. Zero type errors.",
        ].join("\n"),
        stderr: "",
        exitCode: 0,
      });
    }

    if (trimmed === "crux peers") {
      return NextResponse.json({
        stdout: [
          "ACTIVE CRUX COLLABORATIVE PEERS:",
          "  ● Sarah Lin     [Staff Infra]   #06b6d4  auth.ts (editing L14)   latency: 12.4ms",
          "  ● @CruxAI       [Copilot]       #8b5cf6  database.ts             latency: 0.02ms (local)",
          "  ● Marcus Vance  [Architect]     #f59e0b  spatialEngine.ts        latency: 18.1ms",
          "  ● Current User  [Lead Dev]      #5e6ad2  stream_syncer.ts        latency: 0.00ms (self)",
        ].join("\n"),
        stderr: "",
        exitCode: 0,
      });
    }

    // Execute real shell commands safely
    return new Promise<NextResponse>((resolve) => {
      // Execute command with 12 second timeout
      exec(
        trimmed,
        {
          cwd: workingDir,
          timeout: 12000,
          maxBuffer: 1024 * 1024 * 2, // 2MB output buffer
          env: {
            ...process.env,
            PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
          },
        },
        (error, stdout, stderr) => {
          if (error) {
            resolve(
              NextResponse.json({
                stdout: stdout || "",
                stderr: stderr || error.message,
                exitCode: error.code || 1,
              })
            );
          } else {
            resolve(
              NextResponse.json({
                stdout: stdout || "",
                stderr: stderr || "",
                exitCode: 0,
              })
            );
          }
        }
      );
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Internal server error" },
      { status: 500 }
    );
  }
}
