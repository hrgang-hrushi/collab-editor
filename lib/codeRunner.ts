import { invoke } from "@tauri-apps/api/core";
import { ExecutionResult, FileNode } from "./types";

interface TauriExecutionResult {
  stdout: string;
  stderr: string;
  exit_code: number;
  execution_time_ms: number;
}

/**
 * Executes code using native Tauri IPC (when in desktop app), or the backend /api/terminal
 * execution engine (when in web app), with browser V8 fallback.
 */
export async function executeCode(
  code: string,
  language: string,
  filename: string,
  _files: FileNode[] = []
): Promise<ExecutionResult> {
  const startTime = Date.now();
  let currentLang = (language || "").toLowerCase();
  const editorContent = code;

  // Smart language inference: if filename or code structure indicates another language
  if (
    filename.endsWith(".java") ||
    editorContent.includes("import java.") ||
    editorContent.includes("public class ") ||
    editorContent.includes("System.out.") ||
    editorContent.includes("Scanner ")
  ) {
    currentLang = "java";
  } else if (filename.endsWith(".py") || (currentLang === "plaintext" && editorContent.includes("def ") && editorContent.includes("print("))) {
    currentLang = "python";
  } else if (filename.endsWith(".rs") || (currentLang === "plaintext" && editorContent.includes("fn main()"))) {
    currentLang = "rust";
  } else if (filename.endsWith(".cpp") || filename.endsWith(".cc") || editorContent.includes("#include <iostream>")) {
    currentLang = "cpp";
  } else if (filename.endsWith(".c") || editorContent.includes("#include <stdio.h>")) {
    currentLang = "c";
  } else if (filename.endsWith(".swift") || editorContent.includes("import Foundation")) {
    currentLang = "swift";
  } else if (!currentLang || currentLang === "plaintext") {
    currentLang = "typescript";
  }

  // 1. Primary execution route: Native Tauri Rust IPC subprocess (when in desktop shell)
  const isTauri = typeof window !== "undefined" && Boolean((window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__);
  if (isTauri) {
    try {
      const raw = await invoke<TauriExecutionResult>("execute_code", {
        language: currentLang,
        sourceCode: editorContent,
      });

      const stdoutLines = raw.stdout
        ? raw.stdout.split("\n").filter((l, i, arr) => i < arr.length - 1 || l.trim() !== "")
        : [];
      const stderrLines = raw.stderr
        ? raw.stderr.split("\n").filter((l, i, arr) => i < arr.length - 1 || l.trim() !== "")
        : [];

      return {
        stdout: stdoutLines,
        stderr: stderrLines,
        durationMs: Number(raw.execution_time_ms) || (Date.now() - startTime),
        success: raw.exit_code === 0,
        timestamp: Date.now(),
        fileName: filename,
      };
    } catch (ipcErr: any) {
      console.warn("[Crux IPC] Tauri command execution failed, trying server API runner:", ipcErr?.message || ipcErr);
    }
  }

  // 2. Server-side API execution (works for web app and server-backed desktop)
  try {
    // Save file to disk first
    await fetch("/api/fs/write", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fileName: filename,
        filePath: filename,
        content: editorContent,
      }),
    });

    let runCmd = "";
    if (filename.endsWith(".java") || currentLang === "java") {
      const clsMatch =
        editorContent.match(/public\s+class\s+([A-Za-z0-9_]+)/) ||
        editorContent.match(/class\s+([A-Za-z0-9_]+)/);
      const cls = clsMatch ? clsMatch[1] : (filename.replace(/\.java$/, "") || "Main");
      runCmd = `javac ${filename} && java ${cls}`;
    } else if (filename.endsWith(".py") || currentLang === "python") {
      runCmd = `python3 ${filename}`;
    } else if (filename.endsWith(".rs") || currentLang === "rust") {
      const binName = filename.replace(/\.rs$/, "");
      runCmd = `rustc ${filename} && ./${binName}`;
    } else if (filename.endsWith(".cpp") || currentLang === "cpp") {
      runCmd = `clang++ ${filename} -o crux_cpp_bin && ./crux_cpp_bin`;
    } else if (filename.endsWith(".c") || currentLang === "c") {
      runCmd = `clang ${filename} -o crux_c_bin && ./crux_c_bin`;
    } else if (filename.endsWith(".swift") || currentLang === "swift") {
      runCmd = `swiftc ${filename} -o crux_swift_bin && ./crux_swift_bin`;
    } else if (filename.endsWith(".ts") || filename.endsWith(".tsx") || currentLang === "typescript") {
      runCmd = `bun run ${filename}`;
    } else {
      runCmd = `node ${filename}`;
    }

    const termRes = await fetch("/api/terminal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: runCmd }),
    });

    if (termRes.ok) {
      const data = await termRes.json();
      const stdoutLines = data.stdout
        ? data.stdout.split("\n").filter((l: string, i: number, arr: string[]) => i < arr.length - 1 || l.trim() !== "")
        : [];
      const stderrLines = data.stderr
        ? data.stderr.split("\n").filter((l: string, i: number, arr: string[]) => i < arr.length - 1 || l.trim() !== "")
        : [];

      return {
        stdout: stdoutLines,
        stderr: stderrLines,
        durationMs: Date.now() - startTime,
        success: data.exitCode === 0,
        timestamp: Date.now(),
        fileName: filename,
      };
    }
  } catch (serverErr) {
    console.warn("[Crux Runner] Server API execution failed, falling back to client evaluation:", serverErr);
  }

  // 3. Client-side fallback for simple JavaScript execution in pure browser
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

    const sanitizedCode = code
      .replace(/:\s*(string|number|boolean|any|void|Record<[^>]+>|Array<[^>]+>|Promise<[^>]+>|[A-Z][a-zA-Z0-9<>]*)/g, "")
      .replace(/interface\s+[A-Za-z0-9_]+\s*\{[^}]*\}/g, "")
      .replace(/type\s+[A-Za-z0-9_]+\s*=[^;]+;/g, "");

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
