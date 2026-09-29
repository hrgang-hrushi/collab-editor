import { NextRequest, NextResponse } from "next/server";
import { runFullRuntimeScan } from "@/daemon/scanner";
import { importAllWorkspaceConfigurations } from "@/daemon/importer";
import { DiscoveryReport } from "@/daemon/types";
import { computeOrchestrationManifest } from "@/lib/ai/toolOrchestrator";
import fs from "fs";
import path from "path";

export const dynamic = "auto";

/**
 * GET /api/discovery
 * Supports standard JSON response or Server-Sent Events (SSE) stream:
 * If Accept header includes 'text/event-stream', streams discovery updates live.
 */
export async function GET(req: NextRequest) {
  const isEventStream = req.headers.get("accept")?.includes("text/event-stream");
  const cwd = process.cwd();
  const signal = {
    cwd,
    hasGeminiMd: fs.existsSync(path.join(cwd, "GEMINI.md")),
    hasClaudeMd: fs.existsSync(path.join(cwd, "CLAUDE.md")),
    hasCursorRules: fs.existsSync(path.join(cwd, ".cursorrules")),
    hasCopilotInstructions: fs.existsSync(path.join(cwd, ".github/copilot-instructions.md")),
  };

  if (isEventStream) {
    const encoder = new TextEncoder();

    const stream = new ReadableStream({
      async start(controller) {
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify({ type: "init", status: "DISCOVERY_DAEMON_ATTACHED" })}\n\n`)
        );

        try {
          // 1. Run local compute & SDK detection
          const runtimes = await runFullRuntimeScan();
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify({ type: "runtimes", runtimes })}\n\n`)
          );

          // 2. Import workspace profiles
          const { profiles, detectedSdk } = await importAllWorkspaceConfigurations(cwd);
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify({ type: "profiles", profiles, detectedSdk })}\n\n`)
          );

          // 3. Compute orchestration manifest
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
              affinityBreakdown: r.affinityBreakdown,
              details: r.details,
            })),
            null,
            signal
          );

          const report: DiscoveryReport = {
            timestamp: Date.now(),
            runtimes,
            profiles,
            detectedSdk,
            orchestration: {
              selectionMode: manifest.selectionMode,
              activeToolId: manifest.activeToolId,
              autoPickedId: manifest.autoPickedTool.id,
              autoPickedName: manifest.autoPickedTool.name,
              rationale: manifest.rationale,
              totalDetected: manifest.totalDetected,
            },
          };

          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify({ type: "discovery", ...report })}\n\n`)
          );
        } catch (err: any) {
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify({ type: "error", message: err?.message })}\n\n`)
          );
        } finally {
          controller.close();
        }
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
      },
    });
  }

  // Standard JSON response
  try {
    const [runtimes, { profiles, detectedSdk }] = await Promise.all([
      runFullRuntimeScan(),
      importAllWorkspaceConfigurations(cwd),
    ]);

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
        affinityBreakdown: r.affinityBreakdown,
        details: r.details,
      })),
      null,
      signal
    );

    const report: DiscoveryReport = {
      timestamp: Date.now(),
      runtimes,
      profiles,
      detectedSdk,
      orchestration: {
        selectionMode: manifest.selectionMode,
        activeToolId: manifest.activeToolId,
        autoPickedId: manifest.autoPickedTool.id,
        autoPickedName: manifest.autoPickedTool.name,
        rationale: manifest.rationale,
        totalDetected: manifest.totalDetected,
      },
    };

    return NextResponse.json(report);
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Discovery scan failed" },
      { status: 500 }
    );
  }
}
