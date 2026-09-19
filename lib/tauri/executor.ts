/**
 * Crex Multi-Language Tauri IPC Bridge
 * Executes code across Python, Rust, C, Java, Swift, Node, and Bun
 * via the host OS daemon in src-tauri.
 */

export interface ExecutionResult {
  stdout: string;
  stderr: string;
  exit_code: number;
  execution_time_ms: number;
}

export async function executeLocalCode(
  language: string,
  sourceCode: string
): Promise<ExecutionResult> {
  // Check if running in Tauri desktop environment
  if (typeof window !== "undefined" && ("__TAURI_INTERNALS__" in window || "__TAURI__" in window)) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const result = await invoke<ExecutionResult>("execute_code", {
        language,
        sourceCode,
      });
      return result;
    } catch (err: any) {
      return {
        stdout: "",
        stderr: `[CREX_DAEMON_ERROR]: ${err?.message || err}`,
        exit_code: 1,
        execution_time_ms: 0,
      };
    }
  }

  // Fallback for browser testing when not inside native Tauri window
  const startTime = performance.now();
  await new Promise((r) => setTimeout(r, 65));
  const elapsed = Math.round(performance.now() - startTime);

  return {
    stdout: `[CREX_DESKTOP_DAEMON_OFFLINE]\nRunning in Web Browser mode.\nHost OS compiler bridge (${language}) requires the Crex Tauri Desktop shell.\n\nCode length: ${sourceCode.length} bytes.\nTarget runtime: ${language.toUpperCase()}`,
    stderr: "",
    exit_code: 0,
    execution_time_ms: elapsed,
  };
}
