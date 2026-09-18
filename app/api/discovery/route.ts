import { NextRequest, NextResponse } from "next/server";
import { runFullRuntimeScan } from "@/daemon/scanner";
import { importAllWorkspaceConfigurations } from "@/daemon/importer";
import { DiscoveryReport } from "@/daemon/types";

export const dynamic = "force-dynamic";

/**
 * GET /api/discovery
 * Supports standard JSON response or Server-Sent Events (SSE) stream:
 * If Accept header includes 'text/event-stream', streams discovery updates live.
 */
export async function GET(req: NextRequest) {
  const isEventStream = req.headers.get("accept")?.includes("text/event-stream");

  if (isEventStream) {
    const encoder = new TextEncoder();

    const stream = new ReadableStream({
      async start(controller) {
        // Send initial heartbeat
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
          const { profiles, detectedSdk } = await importAllWorkspaceConfigurations(process.cwd());
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify({ type: "profiles", profiles, detectedSdk })}\n\n`)
          );

          // 3. Complete packet
          const report: DiscoveryReport = {
            timestamp: Date.now(),
            runtimes,
            profiles,
            detectedSdk,
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
      importAllWorkspaceConfigurations(process.cwd()),
    ]);

    const report: DiscoveryReport = {
      timestamp: Date.now(),
      runtimes,
      profiles,
      detectedSdk,
    };

    return NextResponse.json(report);
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Discovery scan failed" },
      { status: 500 }
    );
  }
}
