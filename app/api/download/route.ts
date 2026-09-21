import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  // Release artifact candidate paths
  const candidatePaths = [
    path.join(process.cwd(), "src-tauri/target/release/bundle/dmg/crux_0.1.0_universal.dmg"),
    path.join(process.cwd(), "src-tauri/target/release/bundle/dmg/crux_0.1.0_aarch64.dmg"),
    path.join(process.cwd(), "src-tauri/target/release/bundle/dmg/crux_0.1.0_x64.dmg"),
    path.join(process.cwd(), "src-tauri/target/release/bundle/dmg/Crex_0.1.0_universal.dmg"),
    path.join(process.cwd(), "src-tauri/target/release/bundle/dmg/Crex_0.1.0_aarch64.dmg"),
    path.join(process.cwd(), "public/downloads/crux_0.1.0_universal.dmg"),
  ];

  // 1. Check if an actual local DMG build artifact exists on disk
  for (const filePath of candidatePaths) {
    if (fs.existsSync(filePath)) {
      try {
        const stat = fs.statSync(filePath);
        const fileStream = fs.createReadStream(filePath);
        const filename = path.basename(filePath);

        return new NextResponse(fileStream as any, {
          headers: {
            "Content-Disposition": `attachment; filename="${filename}"`,
            "Content-Type": "application/x-apple-diskimage",
            "Content-Length": stat.size.toString(),
          },
        });
      } catch (err) {
        console.error("Error streaming local DMG:", err);
      }
    }
  }

  // 2. Check GitHub Release asset URL
  const githubReleaseUrl =
    "https://github.com/hrgang-hrushi/collab-editor/releases/latest/download/crux_0.1.0_universal.dmg";

  // Check if caller requests JSON or direct download redirect
  const acceptHeader = request.headers.get("accept") || "";
  if (acceptHeader.includes("application/json")) {
    return NextResponse.json({
      downloadUrl: githubReleaseUrl,
      version: "0.1.0",
      architecture: "universal",
      platform: "macOS 12.0+",
      fileName: "crux_0.1.0_universal.dmg",
    });
  }

  // Redirect to GitHub Release DMG download
  return NextResponse.redirect(githubReleaseUrl, 302);
}
