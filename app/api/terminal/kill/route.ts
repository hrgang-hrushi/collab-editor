import { NextRequest, NextResponse } from "next/server";
import { killProcess } from "@/lib/terminalRegistry";

export async function POST(req: NextRequest) {
  try {
    const { pid, signal = "SIGINT" } = await req.json();

    if (typeof pid !== "number") {
      return NextResponse.json(
        { error: "Process PID number is required" },
        { status: 400 }
      );
    }

    const killed = killProcess(pid, signal as NodeJS.Signals);

    return NextResponse.json({
      success: killed,
      pid,
      signal,
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Failed to terminate process" },
      { status: 500 }
    );
  }
}
