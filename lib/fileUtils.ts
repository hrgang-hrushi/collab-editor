import { FileNode } from "./types";
import JSZip from "jszip";

export interface TreeItem {
  id: string; // File ID if file, or full path if folder
  name: string;
  path: string;
  isFolder: boolean;
  children?: TreeItem[];
  file?: FileNode;
}

/**
 * Detect language based on file extension
 */
export function detectLanguage(filename: string): FileNode["language"] {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".java")) return "java";
  if (lower.endsWith(".rs")) return "rust";
  if (lower.endsWith(".cpp") || lower.endsWith(".cc") || lower.endsWith(".cxx") || lower.endsWith(".hpp")) return "cpp";
  if (lower.endsWith(".c") || lower.endsWith(".h")) return "c";
  if (lower.endsWith(".swift")) return "swift";
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".d.ts")) return "typescript";
  if (lower.endsWith(".js") || lower.endsWith(".jsx") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return "javascript";
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".css") || lower.endsWith(".scss") || lower.endsWith(".sass") || lower.endsWith(".less")) return "css";
  if (lower.endsWith(".html") || lower.endsWith(".htm")) return "html";
  if (lower.endsWith(".json") || lower.endsWith(".jsonc")) return "json";
  if (lower.endsWith(".md") || lower.endsWith(".markdown") || lower.endsWith(".mdx")) return "markdown";
  return "plaintext";
}

/**
 * Transforms flat array of FileNodes with relative paths into a nested tree structure
 */
export function buildFileTree(files: FileNode[], folderPaths: string[] = []): TreeItem[] {
  const rootItems: TreeItem[] = [];
  const folderMap = new Map<string, TreeItem>();

  const ensureFolder = (path: string): TreeItem | null => {
    const parts = path.split("/").filter(Boolean);
    let currentPath = "";
    let parentFolder: TreeItem | null = null;
    for (const folderName of parts) {
      currentPath = currentPath ? `${currentPath}/${folderName}` : folderName;
      let folder = folderMap.get(currentPath);
      if (!folder) {
        folder = {
          id: `folder-${currentPath}`,
          name: folderName,
          path: currentPath,
          isFolder: true,
          children: [],
        };
        folderMap.set(currentPath, folder);
        if (parentFolder) parentFolder.children!.push(folder);
        else rootItems.push(folder);
      }
      parentFolder = folder;
    }
    return parentFolder;
  };

  for (const folderPath of folderPaths) ensureFolder(folderPath);

  // Sort files alphabetically by path
  const sortedFiles = [...files].sort((a, b) => a.path.localeCompare(b.path));

  for (const file of sortedFiles) {
    const parts = file.path.split("/").filter(Boolean);

    // If file is at root
    if (parts.length <= 1) {
      rootItems.push({
        id: file.id,
        name: file.name,
        path: file.path,
        isFolder: false,
        file,
      });
      continue;
    }

    const parentFolder = ensureFolder(parts.slice(0, -1).join("/"));

    // Add the file into the deepest parent folder
    if (parentFolder) {
      parentFolder.children!.push({
        id: file.id,
        name: file.name,
        path: file.path,
        isFolder: false,
        file,
      });
    }
  }

  // Sort children: folders first, then files alphabetically
  const sortTree = (items: TreeItem[]) => {
    items.sort((a, b) => {
      if (a.isFolder === b.isFolder) {
        return a.name.localeCompare(b.name);
      }
      return a.isFolder ? -1 : 1;
    });

    for (const item of items) {
      if (item.isFolder && item.children) {
        sortTree(item.children);
      }
    }
  };

  sortTree(rootItems);
  return rootItems;
}

/**
 * Ignored patterns when importing directories
 */
const IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  ".next",
  "dist",
  "build",
  ".turbo",
  ".vercel",
  ".cache",
  ".idea",
  ".vscode",
]);

/**
 * Binary file extensions to preserve as assets instead of decoding as text
 */
const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "ico", "webp", "pdf", "zip", "tar", "gz", "exe", "dmg", "iso", "mp4", "mp3", "woff", "woff2", "ttf", "eot"
]);

const MAX_IMPORT_BYTES = 10 * 1024 * 1024;

async function readBrowserFile(file: File, path: string): Promise<ImportedWorkspace["files"][number] | null> {
  if (file.size > MAX_IMPORT_BYTES) return null;
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const ext = file.name.split(".").pop()?.toLowerCase() || "";
    if (!BINARY_EXTENSIONS.has(ext)) {
      try {
        return { name: file.name, path, content: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
      } catch {
        // Preserve unknown binary formats too.
      }
    }
    let binary = "";
    for (let i = 0; i < bytes.length; i += 32768) {
      binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
    }
    return { name: file.name, path, content: "Binary file — preview unavailable", binaryBase64: btoa(binary) };
  } catch {
    return null;
  }
}

/**
 * Recursively read directory using File System Access API
 */
export async function readDirectoryHandle(
  dirHandle: any,
  currentPath = ""
): Promise<Array<{ name: string; path: string; content: string; handle?: any }>> {
  const results: Array<{ name: string; path: string; content: string; handle?: any }> = [];

  for await (const entry of dirHandle.values()) {
    if (entry.kind === "directory") {
      if (IGNORED_DIRS.has(entry.name)) continue;
      const subPath = currentPath ? `${currentPath}/${entry.name}` : entry.name;
      const subResults = await readDirectoryHandle(entry, subPath);
      results.push(...subResults);
    } else if (entry.kind === "file") {
      const ext = entry.name.split(".").pop()?.toLowerCase() || "";
      if (BINARY_EXTENSIONS.has(ext)) continue;

      try {
        const fileData = await entry.getFile();
        // Skip files larger than 1MB for smooth browser performance
        if (fileData.size > 1024 * 1024) continue;

        const content = await fileData.text();
        const filePath = currentPath ? `${currentPath}/${entry.name}` : entry.name;
        results.push({
          name: entry.name,
          path: filePath,
          content,
          handle: entry,
        });
      } catch (err) {
        console.warn(`Could not read file ${entry.name}:`, err);
      }
    }
  }

  return results;
}

/**
 * Read files from standard webkitdirectory HTML file input fallback
 */
export async function readFileList(
  fileList: FileList
): Promise<ImportedWorkspace["files"]> {
  const results: ImportedWorkspace["files"] = [];

  for (let i = 0; i < fileList.length; i++) {
    const file = fileList[i];
    // webkitRelativePath gives e.g. "my-project/src/index.js"
    const fullPath = file.webkitRelativePath || file.name;
    const pathParts = fullPath.split("/");

    // Check if any directory in path is ignored
    const isIgnored = pathParts.slice(1, -1).some((p) => IGNORED_DIRS.has(p));
    if (isIgnored) continue;

    const imported = await readBrowserFile(file, fullPath);
    if (imported) results.push(imported);
  }

  return results;
}

/**
 * Open a native folder picker in the desktop app and import its text files.
 */
export interface ImportedWorkspace {
  files: Array<{ name: string; path: string; content: string; binaryBase64?: string }>;
  folders: string[];
  skipped: number;
}

export async function readNativeDirectory(): Promise<ImportedWorkspace | null> {
  const { open } = await import("@tauri-apps/plugin-dialog");
  const selectedPath = await open({ directory: true, multiple: false });
  if (!selectedPath) return null;
  return readNativePaths([selectedPath]);
}

export async function readNativePaths(paths: string[]): Promise<ImportedWorkspace> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<ImportedWorkspace>("import_paths_from_disk", { paths });
}

export function isTauriDesktop(): boolean {
  return typeof window !== "undefined" && Boolean(
    (window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__
  );
}

/** Read files and folders dropped from the host file manager in a browser. */
export async function readDroppedItems(items: DataTransferItemList): Promise<ImportedWorkspace> {
  const result: ImportedWorkspace = { files: [], folders: [], skipped: 0 };
  // Capture entries before awaiting; the browser clears DataTransfer after the drop event.
  const entries = Array.from(items)
    .filter((item) => item.kind === "file")
    .map((item) => ({ entry: (item as any).webkitGetAsEntry?.(), file: item.getAsFile() }));

  const readFile = async (file: File, path: string) => {
    const imported = await readBrowserFile(file, path);
    if (imported) result.files.push(imported);
    else result.skipped++;
  };

  const visit = async (entry: any, prefix = ""): Promise<void> => {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory) {
      if (IGNORED_DIRS.has(entry.name)) return;
      result.folders.push(path);
      const reader = entry.createReader();
      while (true) {
        const batch: any[] = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
        if (batch.length === 0) break;
        for (const child of batch) await visit(child, path);
      }
    } else if (entry.isFile) {
      const file: File = await new Promise((resolve, reject) => entry.file(resolve, reject));
      await readFile(file, path);
    }
  };

  for (const { entry, file } of entries) {
    try {
      if (entry) await visit(entry);
      else if (file) await readFile(file, file.name);
    } catch {
      result.skipped++;
    }
  }
  return result;
}

/**
 * Save file directly back to disk (via Tauri native IPC or FileSystemFileHandle)
 */
export async function saveFileToDisk(file: FileNode): Promise<boolean> {
  if (file.binaryBase64 !== undefined) return false;
  let saved = false;

  // 1. Server-side filesystem write via API (ensures terminal shell process has the file in process.cwd())
  try {
    const res = await fetch("/api/fs/write", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fileName: file.name,
        filePath: file.path,
        content: file.content,
      }),
    });
    if (res.ok) {
      saved = true;
    }
  } catch (err) {
    // ignore
  }

  // 2. Native Tauri IPC if running in desktop environment
  if (
    typeof window !== "undefined" &&
    Boolean((window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__)
  ) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const targetPath = file.path;
      if (targetPath) {
        await invoke<{ success: boolean }>("write_file_to_disk", {
          filePath: targetPath,
          content: file.content,
        });
      }
    } catch (tauriErr) {
      console.warn("[Crux FS] Tauri native file write fallback:", tauriErr);
    }
  }

  // 3. Web File System Access API handle
  if (file.handle) {
    try {
      const writable = await file.handle.createWritable();
      await writable.write(file.content);
      await writable.close();
      saved = true;
    } catch (err) {
      console.error(`Failed to save file ${file.name} to disk:`, err);
    }
  }

  return saved;
}

/**
 * Export all workspace files into a downloadable ZIP
 */
export async function exportWorkspaceAsZip(
  files: FileNode[],
  projectName = "crux-project",
  folders: string[] = []
): Promise<void> {
  const zip = new JSZip();

  for (const folder of folders) zip.folder(folder);

  for (const file of files) {
    zip.file(file.path, file.binaryBase64 !== undefined ? file.binaryBase64 : file.content, file.binaryBase64 !== undefined ? { base64: true } : undefined);
  }

  const blob = await zip.generateAsync({ type: "blob" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${projectName}.zip`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
