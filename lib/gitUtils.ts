/**
 * Git Utilities: Native Tauri IPC or HTTP fallback
 */
export async function getGitBranchInfo(): Promise<{ branch: string; isDirty: boolean }> {
  const isTauri =
    typeof window !== "undefined" &&
    Boolean((window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__);

  if (isTauri) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const res = await invoke<{ branch: string; isDirty: boolean }>("git_command", {
        action: "branch",
      });
      if (res && res.branch) {
        return { branch: res.branch, isDirty: Boolean(res.isDirty) };
      }
    } catch {
      // fallback
    }
  }

  try {
    const res = await fetch("/api/git", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "branch" }),
    });
    if (res.ok) {
      const data = await res.json();
      return { branch: data.branch || "main", isDirty: Boolean(data.isDirty) };
    }
  } catch {
    // ignore
  }

  return { branch: "main", isDirty: false };
}
