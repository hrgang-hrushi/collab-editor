import { ExecutionResult, FileNode } from "./types";

/**
 * Executes code using the Next.js sandboxed runner API
 * with automatic fallback to client-side evaluation if offline.
 */
export async function executeCode(
  code: string,
  language: string,
  filename: string,
  files: FileNode[]
): Promise<ExecutionResult> {
  const startTime = Date.now();

  try {
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        language,
        filename,
        files: files.map((f) => ({ path: f.path, name: f.name, content: f.content })),
      }),
    });

    if (response.ok) {
      const data: ExecutionResult = await response.json();
      return data;
    }
  } catch (apiErr) {
    console.warn("Server runner unavailable, falling back to client eval:", apiErr);
  }

  // Check if non-JS language in offline client fallback
  if (filename.endsWith(".java") || language === "java") {
    return {
      stdout: [],
      stderr: [
        "[Crux Runner] Java execution requires a server-side runtime with JDK installed.",
        "Unable to evaluate Java in browser-only client fallback.",
      ],
      durationMs: Date.now() - startTime,
      success: false,
      timestamp: Date.now(),
      fileName: filename,
    };
  }

  // Client-side fallback for simple JavaScript execution
  const stdout: string[] = [];
  const stderr: string[] = [];

  try {
    const origLog = console.log;
    const origErr = console.error;

    console.log = (...args: any[]) => {
      stdout.push(args.map((a) => (typeof a === "object" ? JSON.stringify(a) : String(a))).join(" "));
      origLog(...args);
    };
    console.error = (...args: any[]) => {
      stderr.push(args.map((a) => (typeof a === "object" ? JSON.stringify(a) : String(a))).join(" "));
      origErr(...args);
    };

    // Strip basic TypeScript interfaces/types for client-side eval
    let sanitizedCode = code
      .replace(/:\s*(string|number|boolean|any|void|Record<[^>]+>|Array<[^>]+>|Promise<[^>]+>|[A-Z][a-zA-Z0-9<>]*)/g, "")
      .replace(/interface\s+[A-Za-z0-9_]+\s*\{[^}]*\}/g, "")
      .replace(/type\s+[A-Za-z0-9_]+\s*=[^;]+;/g, "");

    // Run using Function constructor
    const runFn = new Function(sanitizedCode);
    const retVal = runFn();

    console.log = origLog;
    console.error = origErr;

    return {
      stdout,
      stderr,
      returnValue: retVal !== undefined ? String(retVal) : undefined,
      durationMs: Date.now() - startTime,
      success: stderr.length === 0,
      timestamp: Date.now(),
      fileName: filename,
    };
  } catch (evalErr: any) {
    stderr.push(evalErr?.message || String(evalErr));
    return {
      stdout,
      stderr,
      durationMs: Date.now() - startTime,
      success: false,
      timestamp: Date.now(),
      fileName: filename,
    };
  }
}
