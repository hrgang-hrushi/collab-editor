import { INITIAL_FILES } from "@/lib/defaultData";
import { FileNode } from "@/lib/types";
import checkpoints from "./cleanCheckpoints.json";

const restoreMarker = "crux_clean_checkpoints_restored_20260929";
const previousFilesKey = "crux_workspace_files_before_clean_restore_20260929";

const starterFiles = [
  ["file-stream-syncer", "stream_syncer.ts"],
  ["file-database", "database.ts"],
  ["file-auth", "auth.ts"],
  ["file-types", "types.ts"],
  ["file-spatial", "spatialEngine.ts"],
] as const;

/** Restore the checkpoints chosen for this workspace once per browser/WebView. */
export function restoreCleanCheckpoints(): void {
  if (typeof window === "undefined" || localStorage.getItem(restoreMarker)) return;

  const previous = localStorage.getItem("crux_workspace_files");
  const parsed = previous ? JSON.parse(previous) : INITIAL_FILES;
  if (!Array.isArray(parsed)) throw new Error("Saved workspace is not a file list");

  // Keep every unrelated/imported file and its metadata intact.
  const files: FileNode[] = parsed.map((file: FileNode) => ({ ...file }));
  for (const [id, name] of starterFiles) {
    const content = checkpoints[name];
    const index = files.findIndex((file) => file.id === id);
    if (index >= 0) files[index] = { ...files[index], content, isDirty: false, status: "clean" };
    else {
      const starter = INITIAL_FILES.find((file) => file.id === id);
      if (starter) files.push({ ...starter, content });
    }
  }

  const practiceIndex = files.findIndex((file) => file.path === "src/Practice.java");
  const practice: FileNode = {
    id: "file-practice-checkpoint",
    name: "Practice.java",
    path: "src/Practice.java",
    language: "java",
    content: checkpoints["Practice.java"],
    x: 60,
    y: 1120,
    width: 560,
    height: 460,
    zIndex: 8,
    status: "clean",
    isDirty: false,
  };
  if (practiceIndex >= 0) files[practiceIndex] = { ...files[practiceIndex], ...practice };
  else files.push(practice);

  if (previous !== null) localStorage.setItem(previousFilesKey, previous);
  localStorage.setItem("crux_workspace_files", JSON.stringify(files));
  localStorage.setItem(restoreMarker, new Date().toISOString());
}
