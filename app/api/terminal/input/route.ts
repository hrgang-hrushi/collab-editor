import { NextRequest } from "next/server";
import {
  writeToProcessStdin,
  terminalProcesses,
  terminalStdinHandlers,
} from "@/lib/terminalRegistry";

export async function POST(req: NextRequest) {
  try {
    const { pid, input } = await req.json();
    if (input === undefined) {
      return new Response(JSON.stringify({ error: "input is required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    let targetPid = pid ? Number(pid) : null;
    const hasTarget =
      targetPid &&
      (terminalProcesses.has(targetPid) || terminalStdinHandlers.has(targetPid));

    if (!hasTarget) {
      // Fallback to the latest active process or interactive handler
      const activePids = [
        ...Array.from(terminalProcesses.keys()),
        ...Array.from(terminalStdinHandlers.keys()),
      ];
      if (activePids.length > 0) {
        targetPid = activePids[activePids.length - 1];
      }
    }

    if (!targetPid) {
      return new Response(JSON.stringify({ error: "No running process or session found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    const success = writeToProcessStdin(targetPid, String(input));
    return new Response(JSON.stringify({ success, pid: targetPid }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
