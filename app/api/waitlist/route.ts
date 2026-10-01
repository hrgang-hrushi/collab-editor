import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";
const productionEndpoint = "https://codecrux.us/api/waitlist";

async function forward(method: "GET" | "POST", body?: string) {
  try {
    const response = await fetch(productionEndpoint, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body,
      cache: "no-store",
    });
    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch {
    return NextResponse.json({ error: "Waitlist is temporarily unavailable" }, { status: 503 });
  }
}

export async function GET() {
  return forward("GET");
}

export async function POST(request: NextRequest) {
  return forward("POST", await request.text());
}
