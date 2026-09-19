import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const {
      action,
      prompt,
      command,
      stderr,
      exitCode,
      activeFileName = "stream_syncer.ts",
      activeFileContent = "",
      cursorLine = 1,
    } = body;

    if (action === "generate-command") {
      const q = (prompt || "").trim().toLowerCase();
      const currentFile = activeFileName || "stream_syncer.ts";
      const baseName = currentFile.replace(/\.[^/.]+$/, "");

      let generatedCommand = "crux status";
      let explanation = "Displays Crux daemon status, buffer mesh health, and connected peer latencies.";

      // 11.1 Context-Aware command synthesis
      if (q.includes("test") && (q.includes("this") || q.includes("file"))) {
        generatedCommand = `npx jest src/${baseName}.test.ts`;
        explanation = `Runs automated test suite specifically for active buffer ${currentFile}`;
      } else if (q.includes("run") && (q.includes("this") || q.includes("file") || q.includes("buffer"))) {
        generatedCommand = `node ${currentFile}`;
        explanation = `Executes active buffer ${currentFile} in V8 sandbox runtime`;
      } else if (q.includes("lint") || q.includes("typecheck")) {
        generatedCommand = `npx tsc --noEmit ${currentFile}`;
        explanation = `Validates strict TypeScript types for ${currentFile}`;
      } else if (q.includes("git log") || (q.includes("history") && q.includes("this"))) {
        generatedCommand = `git log -n 5 --oneline -- ${currentFile}`;
        explanation = `Inspects recent commit history for active buffer ${currentFile}`;
      } else if (q.includes("count") || q.includes("lines")) {
        generatedCommand = `wc -l ${currentFile}`;
        explanation = `Counts lines of code in active buffer ${currentFile}`;
      } else if (q.includes("build") || q.includes("compile")) {
        generatedCommand = "crux build";
        explanation = "Runs Crux incremental compiler pipeline across active AST modules.";
      } else if (q.includes("peer") || q.includes("collaborat") || q.includes("who")) {
        generatedCommand = "crux peers";
        explanation = "Lists all connected collaborative peers and their cryptographic attestations.";
      } else if (q.includes("git status") || (q.includes("git") && q.includes("change"))) {
        generatedCommand = "git status --short";
        explanation = "Shows short status of modified, staged, and untracked files.";
      } else if (q.includes("git commit") || q.includes("commit")) {
        generatedCommand = `git commit -m "update(${baseName}): sync collaborative buffer changes"`;
        explanation = `Creates a scoped git commit for ${currentFile}.`;
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
      } else if (q.includes("clean") || q.includes("cache")) {
        generatedCommand = "rm -rf .next/cache";
        explanation = "Flushes Next.js build and compiler cache.";
      } else {
        generatedCommand = `echo "Context [${currentFile}:${cursorLine}]" && crux status`;
        explanation = `Executes query with active buffer ${currentFile} context.`;
      }

      return NextResponse.json({
        command: generatedCommand,
        explanation,
        confidence: 0.98,
        contextSummary: `${currentFile}:${cursorLine}`,
      });
    }

    if (action === "diagnose-error" || action === "auto-heal") {
      const err = stderr || "";
      const targetFile = activeFileName || "stream_syncer.ts";
      let summary = "Process exited with an error";
      let rootCause = "Uncaught runtime or shell failure.";
      let suggestedCommand: string | undefined = undefined;
      let fixProposedIn = `${targetFile}:${cursorLine || 14}`;
      let suggestedDiff: {
        originalText: string;
        suggestedText: string;
        description: string;
        line: number;
      } | null = null;

      if (err.includes("SyntaxError: Unexpected token") || err.includes("SyntaxError")) {
        summary = "SyntaxError: Incomplete statement or invalid token syntax";
        rootCause = "A trailing dot or unclosed punctuation interrupted AST transpilation.";
        suggestedCommand = `node ${targetFile}`;
        fixProposedIn = `${targetFile}:8`;
        suggestedDiff = {
          line: 8,
          originalText: "await this.daemon.",
          suggestedText: "const ticket = await this.daemon.acquireLock('stream-mesh-primary');",
          description: "@CruxAI Auto-Healing: Resolved trailing operator with acquireLock call",
        };
      } else if (err.includes("Cannot find module") || err.includes("MODULE_NOT_FOUND")) {
        const match = err.match(/Cannot find module '([^']+)'/);
        const modName = match ? match[1] : "dependency";
        summary = `ModuleNotFound: '${modName}' is not installed in node_modules`;
        rootCause = `The import '${modName}' could not be resolved from local node_modules.`;
        suggestedCommand = `npm install ${modName}`;
        fixProposedIn = `${targetFile}:1`;
        suggestedDiff = {
          line: 1,
          originalText: `import { ... } from "${modName}";`,
          suggestedText: `// Auto-Healed dependency fallback\nimport { ${modName}Mock } from "./types";`,
          description: `@CruxAI Auto-Healing: Injected local mock fallback for uninstalled '${modName}'`,
        };
      } else if (err.includes("EADDRINUSE") || err.includes("address already in use")) {
        summary = "Port Conflict: Address already in use (EADDRINUSE)";
        rootCause = "Another background process is bound to the requested port.";
        suggestedCommand = "lsof -ti :3000 | xargs kill -9";
        fixProposedIn = "next.config.js:1";
      } else if (err.includes("Permission denied") || err.includes("EACCES")) {
        summary = "Permission Denied: Insufficient filesystem privileges";
        rootCause = "The process attempted to write to a restricted path or socket.";
        suggestedCommand = "chmod +x " + (command?.split(" ")[0] || "script.sh");
        fixProposedIn = "workspace:0";
      } else if (err.includes("SIGINT") || exitCode === 130) {
        summary = "Process aborted by user (SIGINT)";
        rootCause = "The running command was interrupted via Ctrl+C / kill signal.";
      } else {
        summary = `Process exited with code ${exitCode || 1}`;
        rootCause = err.split("\n")[0] || "Command failed with non-zero exit status.";
        suggestedCommand = `node ${targetFile}`;
        fixProposedIn = `${targetFile}:14`;
        suggestedDiff = {
          line: 14,
          originalText: "// Pending verification pass",
          suggestedText: "// Auto-healed: Injected verification guard\nif (!token) return false;",
          description: "@CruxAI Auto-Healing: Injected null guard for peer signature token",
        };
      }

      return NextResponse.json({
        summary,
        rootCause,
        suggestedCommand,
        fixProposedIn,
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
