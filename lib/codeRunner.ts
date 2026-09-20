import { invoke } from "@tauri-apps/api/core";
import { ExecutionResult, FileNode } from "./types";

interface TauriExecutionResult {
  stdout: string;
  stderr: string;
  exit_code: number;
  execution_time_ms: number;
}

/**
 * Executes code using native Tauri IPC to spawn native OS subprocesses in Rust.
 */
export async function executeCode(
  code: string,
  language: string,
  filename: string,
  _files: FileNode[] = []
): Promise<ExecutionResult> {
  const startTime = Date.now();
  const currentLang = language.toLowerCase();
  const editorContent = code;

  // 1. Primary execution route: Native Tauri Rust IPC subprocess
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
    const errMsg = ipcErr?.message || String(ipcErr);
    // If not in Tauri desktop shell (e.g. browser environment), fall back gracefully
    if (
      errMsg.includes("__TAURI_INTERNALS__") ||
      errMsg.includes("window.__TAURI__") ||
      errMsg.includes("IPC") ||
      typeof window === "undefined" ||
      !(window as any).__TAURI_INTERNALS__
    ) {
      console.warn("[Crux IPC] Tauri runtime unavailable in browser context, using client fallback:", errMsg);
    } else {
      console.error("[Crux IPC] Tauri command execution failed:", errMsg);
      return {
        stdout: [],
        stderr: [`[Crux Rust IPC Error] ${errMsg}`],
        durationMs: Date.now() - startTime,
        success: false,
        timestamp: Date.now(),
        fileName: filename,
      };
    }
  }

  // Non-JS fallback when outside Tauri runtime
  if (filename.endsWith(".java") || currentLang === "java") {
    return {
      stdout: [],
      stderr: [
        "[Crux Desktop Runner] Native Java execution requires the Crex Tauri desktop app.",
        "Please run inside the Tauri desktop shell to invoke native javac / java subprocesses.",
      ],
      durationMs: Date.now() - startTime,
      success: false,
      timestamp: Date.now(),
      fileName: filename,
    };
  }

  if (filename.endsWith(".py") || currentLang === "python") {
    return {
      stdout: [],
      stderr: [
        "[Crux Desktop Runner] Native Python execution requires the Crex Tauri desktop app.",
        "Please run inside the Tauri desktop shell to invoke native python3 subprocesses.",
      ],
      durationMs: Date.now() - startTime,
      success: false,
      timestamp: Date.now(),
      fileName: filename,
    };
  }

  // Client-side fallback for simple JavaScript execution in pure browser
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
