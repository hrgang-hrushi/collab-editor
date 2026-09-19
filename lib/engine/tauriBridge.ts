/**
 * Crux Multi-Language Execution Bridge
 * Connects directly to Tauri IPC execute_code daemon in desktop mode,
 * with seamless fallback to Next.js API runner in browser mode.
 */

export interface ExecutionResult {
  stdout: string;
  stderr: string;
  exit_code: number;
  duration_ms: number;
}

export async function executeMultiLanguageCode(
  language: string,
  sourceCode: string
): Promise<ExecutionResult> {
  const startTime = Date.now();

  // 1. Check if running inside Tauri Desktop shell
  if (typeof window !== "undefined" && (window as any).__TAURI__) {
    try {
      const { invoke } = (window as any).__TAURI__;
      const result = await invoke("execute_code", {
        language,
        sourceCode,
      });
      return result as ExecutionResult;
    } catch (err: any) {
      return {
        stdout: "",
        stderr: `[TAURI IPC ERROR] ${err?.message || err}`,
        exit_code: 1,
        duration_ms: Date.now() - startTime,
      };
    }
  }

  // 2. Fallback to API runner
  try {
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: sourceCode,
        language,
      }),
    });

    const data = await response.json();
    return {
      stdout: Array.isArray(data.stdout) ? data.stdout.join("\n") : (data.stdout || ""),
      stderr: Array.isArray(data.stderr) ? data.stderr.join("\n") : (data.stderr || data.error || ""),
      exit_code: data.exitCode !== undefined ? data.exitCode : (data.error ? 1 : 0),
      duration_ms: data.executionTimeMs || (Date.now() - startTime),
    };
  } catch (err: any) {
    return {
      stdout: "",
      stderr: `[DAEMON ERROR] ${err?.message || "Execution request failed"}`,
      exit_code: 1,
      duration_ms: Date.now() - startTime,
    };
  }
}
