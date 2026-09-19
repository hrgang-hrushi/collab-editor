import { NextRequest, NextResponse } from "next/server";
import { exec } from "child_process";

function sh(cmd: string, cwd: string): Promise<string> {
  return new Promise((resolve) => {
    exec(cmd, { cwd, timeout: 3000 }, (err, stdout, stderr) => {
      resolve(err ? "" : stdout.trim());
    });
  });
}

export async function POST(req: NextRequest) {
  try {
    const { action } = await req.json();
    const cwd = process.cwd();

    if (action === "branch" || action === "status") {
      const [branch, statusOut] = await Promise.all([
        sh("git rev-parse --abbrev-ref HEAD", cwd),
        sh("git status --short", cwd),
      ]);

      const changedFiles = statusOut
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);

      return NextResponse.json({
        branch: branch || "main",
        isDirty: changedFiles.length > 0,
        changedFiles,
      });
    }

    if (action === "log") {
      const logOut = await sh("git log --oneline -7", cwd);
      const commits = logOut
        .split("\n")
        .filter(Boolean)
        .map((line) => {
          const spaceIdx = line.indexOf(" ");
          return {
            hash: line.slice(0, spaceIdx),
            message: line.slice(spaceIdx + 1),
          };
        });
      return NextResponse.json({ commits });
    }

    return NextResponse.json({ error: "Unknown action" }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Git API error" },
      { status: 500 }
    );
  }
}
