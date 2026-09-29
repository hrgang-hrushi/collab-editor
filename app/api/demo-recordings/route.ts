import { NextRequest, NextResponse } from "next/server";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  const origin = request.headers.get("origin");
  const host = request.nextUrl.hostname;
  if (process.env.NODE_ENV !== "development" || !["localhost", "127.0.0.1"].includes(host) || !origin || !["localhost", "127.0.0.1"].includes(new URL(origin).hostname)) {
    return NextResponse.json({ error: "Local development capture only" }, { status: 403 });
  }
  const contentType = request.headers.get("content-type");
  if (contentType !== "video/webm" && contentType !== "video/mp4") {
    return NextResponse.json({ error: "Expected WebM or MP4 video" }, { status: 415 });
  }
  const declaredSize = Number(request.headers.get("content-length") || 0);
  if (declaredSize > 200 * 1024 * 1024) {
    return NextResponse.json({ error: "Recording exceeds 200 MB" }, { status: 413 });
  }
  const bytes = Buffer.from(await request.arrayBuffer());
  if (bytes.length < 1024 || bytes.length > 200 * 1024 * 1024) {
    return NextResponse.json({ error: "Recording size is invalid" }, { status: 400 });
  }
  const shot = (request.nextUrl.searchParams.get("shot") || "demo")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "demo";
  const directory = path.join(process.cwd(), "output", "demos");
  await mkdir(directory, { recursive: true });
  const extension = contentType === "video/mp4" ? "mp4" : "webm";
  const name = `${shot}-${new Date().toISOString().replace(/[:.]/g, "-")}.${extension}`;
  const filePath = path.join(directory, name);
  await writeFile(filePath, bytes);
  return NextResponse.json({ path: filePath, bytes: bytes.length });
}
