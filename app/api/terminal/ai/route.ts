import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { action, prompt, command, stderr, exitCode, activeFileName } = body;

    if (action === "generate-command") {
      const q = (prompt || "").trim().toLowerCase();

      let generatedCommand = "crux status";
      let explanation = "Displays Crux daemon status, buffer mesh health, and connected peer latencies.";

      if (q.includes("build") || q.includes("compile")) {
        generatedCommand = "crux build";
        explanation = "Runs Crux incremental compiler pipeline across active AST modules.";
      } else if (q.includes("peer") || q.includes("collaborat") || q.includes("who")) {
        generatedCommand = "crux peers";
        explanation = "Lists all connected collaborative peers and their cryptographic attestations.";
      } else if (q.includes("git status") || (q.includes("git") && q.includes("change"))) {
        generatedCommand = "git status --short";
        explanation = "Shows short status of modified, staged, and untracked files.";
      } else if (q.includes("git commit") || q.includes("commit")) {
        generatedCommand = 'git commit -m "update: sync collaborative buffer changes"';
        explanation = "Creates a git commit with a standard synchronization message.";
      } else if (q.includes("git branch") || q.includes("branch")) {
        generatedCommand = "git branch -a";
        explanation = "Lists all local and remote branches in the repository.";
      } else if (q.includes("find") || q.includes("list ts") || q.includes("search file")) {
        generatedCommand = "find . -maxdepth 3 -name '*.ts' -o -name '*.tsx'";
        explanation = "Finds all TypeScript source files within the workspace hierarchy.";
      } else if (q.includes("port") || q.includes("3000") || q.includes("listening")) {
        generatedCommand = "lsof -i :3000";
        explanation = "Checks which process is currently bound to port 3000.";
      } else if (q.includes("install") || q.includes("add package")) {
        const pkg = prompt.split("add package")[1] || prompt.split("install")[1] || "lodash";
        generatedCommand = `npm install ${pkg.trim()}`;
        explanation = `Installs package '${pkg.trim()}' into local node_modules.`;
      } else if (q.includes("run") || q.includes("test")) {
        const target = activeFileName || "stream_syncer.ts";
        generatedCommand = `node ${target}`;
        explanation = `Executes ${target} in the sandboxed V8 runtime.`;
      } else if (q.includes("clean") || q.includes("cache")) {
        generatedCommand = "rm -rf .next/cache";
        explanation = "Flushes Next.js build and compiler cache.";
      } else {
        generatedCommand = `echo "Query: ${prompt}" && crux status`;
        explanation = "Executes command query with Crux daemon telemetry context.";
      }

      return NextResponse.json({
        command: generatedCommand,
        explanation,
        confidence: 0.96,
      });
    }

    if (action === "diagnose-error") {
      const err = stderr || "";
      let summary = "Process exited with an error";
      let rootCause = "Uncaught runtime or shell failure.";
      let suggestedCommand: string | undefined = undefined;
      let suggestedDiff: string | undefined = undefined;

      if (err.includes("SyntaxError: Unexpected token")) {
        summary = "SyntaxError: Incomplete statement or dangling operator";
        rootCause = "A dangling dot, incomplete expression, or invalid token interrupted compilation.";
        suggestedCommand = `node ${activeFileName || "stream_syncer.ts"}`;
        suggestedDiff = "// Complete the expression before calling the daemon method";
      } else if (err.includes("Cannot find module") || err.includes("MODULE_NOT_FOUND")) {
        const match = err.match(/Cannot find module '([^']+)'/);
        const modName = match ? match[1] : "dependency";
        summary = `ModuleNotFound: '${modName}' is not installed in node_modules`;
        rootCause = `The import '${modName}' could not be resolved from local node_modules.`;
        suggestedCommand = `npm install ${modName}`;
      } else if (err.includes("EADDRINUSE") || err.includes("address already in use")) {
        summary = "Port Conflict: Address already in use";
        rootCause = "Another background process is bound to the requested port.";
        suggestedCommand = "lsof -ti :3000 | xargs kill -9";
      } else if (err.includes("Permission denied") || err.includes("EACCES")) {
        summary = "Permission Denied: Insufficient filesystem privileges";
        rootCause = "The process attempted to write to a restricted path or socket.";
        suggestedCommand = "chmod +x " + (command?.split(" ")[0] || "script.sh");
      } else if (err.includes("SIGINT") || exitCode === 130) {
        summary = "Process aborted by user (SIGINT)";
        rootCause = "The running command was interrupted via Ctrl+C / kill signal.";
      } else {
        summary = `Process exited with code ${exitCode || 1}`;
        rootCause = err.split("\n")[0] || "Command failed with non-zero exit status.";
        suggestedCommand = "crux status";
      }

      return NextResponse.json({
        summary,
        rootCause,
        suggestedCommand,
        suggestedDiff,
      });
    }

    return NextResponse.json({ error: "Invalid action" }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Failed to process AI terminal request" },
      { status: 500 }
    );
  }
}
