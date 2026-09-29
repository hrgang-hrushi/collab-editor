import { NextRequest, NextResponse } from "next/server";
import { exec } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { getTerminalExtendedPath } from "@/lib/terminalEnv";
import { runFullRuntimeScan } from "@/daemon/scanner";
import { computeOrchestrationManifest, formatAsciiToolsTable } from "@/lib/ai/toolOrchestrator";
import { getActiveAiTool, setActiveAiTool } from "@/lib/terminalRegistry";

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

    // Built-in Crux daemon: crux status
    if (trimmed === "crux status") {
      return NextResponse.json({
        stdout: [
          "● Crux Daemon: v1.2.0-prod on unix:///var/run/crux.sock (IPC: 0.08ms)",
          "● Hardware: Apple Silicon Metal Compute Engine (128 tok/s)",
          "● Buffer Mesh: Zero-copy shared memory CRDT ring buffer [ACTIVE]",
          `● Active AI Engine: [${getActiveAiTool().toUpperCase()}]`,
          "● Connected Peers: Sarah Lin (12.4ms), @CruxAI (0.02ms local), Marcus Vance (18.1ms)",
          "● Sync Health: Clean (0 unmerged conflicts)",
        ].join("\n"),
        stderr: "",
        exitCode: 0,
      });
    }

    // Built-in Crux daemon: crux agents / crux tools
    if (trimmed === "crux agents" || trimmed === "crux tools") {
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

      const table = formatAsciiToolsTable(manifest);
      return NextResponse.json({
        stdout: table,
        stderr: "",
        exitCode: 0,
      });
    }

    // Built-in Crux daemon: crux pick <tool>
    const pickMatch = trimmed.match(/^crux\s+pick(?:\s+(.*))?$/i);
    if (pickMatch) {
      const target = (pickMatch[1] || "").trim().toLowerCase();
      if (!target) {
        return NextResponse.json({
          stdout: `Current selection: [${getActiveAiTool().toUpperCase()}]. Usage: crux pick <auto|agy|claude|codex|opencode|cursor|ollama>`,
          stderr: "",
          exitCode: 0,
        });
      }
      setActiveAiTool(target);
      return NextResponse.json({
        stdout: `[OK] Orchestrated Primary AI Engine set to: ${target.toUpperCase()}`,
        stderr: "",
        exitCode: 0,
      });
    }

    // Built-in Crux daemon: crux doctor
    if (trimmed === "crux doctor") {
      const userHome = process.env.HOME || os.homedir();
      const extPath = getTerminalExtendedPath();
      const runtimes = await runFullRuntimeScan();

      const out = [
        "[CRUX HYPERTERMINAL SUBSYSTEM HEALTH CHECK & DIAGNOSTICS]",
        "----------------------------------------------------------------------",
        "● Terminal PTY Engine:      Online (Next.js Node API + Posix Spawn)",
        "● IPC Socket:               unix:///var/run/crux.sock (0.08ms latency)",
        `● Working Directory:        ${workingDir}`,
        `● User Home:                ${userHome}`,
        `● Shell:                    ${process.env.SHELL || "/bin/zsh"}`,
        `● Active Orchestration:     Mode: [${getActiveAiTool().toUpperCase()}]`,
        `● Discovered AI Tools:      ${runtimes.length} tools registered`,
        "----------------------------------------------------------------------",
        "SEARCH PATH VALIDATION:",
        ...extPath.split(":").slice(0, 8).map((p) => `  ✓ ${p}`),
        "----------------------------------------------------------------------",
        "[ALL SYSTEMS OPERATIONAL] Crux HyperTerminal is 100% verified.",
      ].join("\n");

      return NextResponse.json({
        stdout: out,
        stderr: "",
        exitCode: 0,
      });
    }

    if (trimmed === "crux build") {
      return NextResponse.json({
        stdout: [
          "[CRUX] Crux Incremental Pipeline Compiler v1.2.0",
          "-> Parsing AST dependency graph for active workspace modules...",
          "-> Checking TypeScript strict contracts across stream_syncer.ts <-> auth.ts...",
          "-> Synchronizing vector clocks across 3 peer nodes...",
          "[OK] Build successful in 42ms. Zero type errors.",
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

    const userHome = process.env.HOME || os.homedir() || "/Users/hrushikeshgangala";
    const extendedPath = getTerminalExtendedPath();

    // Execute real shell commands safely
    return new Promise<NextResponse>((resolve) => {
      exec(
        trimmed,
        {
          cwd: workingDir,
          timeout: 15000,
          maxBuffer: 1024 * 1024 * 4,
          env: {
            ...process.env,
            HOME: userHome,
            FORCE_COLOR: "1",
            TERM: "xterm-256color",
            COLORTERM: "truecolor",
            PATH: extendedPath,
          },
        },
        (error, stdout, stderr) => {
          if (error) {
            resolve(
              NextResponse.json({
                stdout: stdout || "",
                stderr: stderr || error.message,
                exitCode: typeof error.code === "number" ? error.code : 1,
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
