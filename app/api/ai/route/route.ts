import { NextRequest, NextResponse } from "next/server";
import { processAiPrompt } from "@/lib/ai/conversationalKernel";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const result = await processAiPrompt(body);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Failed to process AI prompt" },
      { status: 500 }
    );
  }
}
