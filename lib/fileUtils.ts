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
export function buildFileTree(files: FileNode[]): TreeItem[] {
  const rootItems: TreeItem[] = [];
  const folderMap = new Map<string, TreeItem>();

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

    // Handle nested directories
    let currentPath = "";
    let parentFolder: TreeItem | null = null;

    for (let i = 0; i < parts.length - 1; i++) {
      const folderName = parts[i];
      currentPath = currentPath ? `${currentPath}/${folderName}` : folderName;

      if (!folderMap.has(currentPath)) {
        const newFolder: TreeItem = {
          id: `folder-${currentPath}`,
          name: folderName,
          path: currentPath,
          isFolder: true,
          children: [],
        };
        folderMap.set(currentPath, newFolder);

        if (parentFolder) {
          parentFolder.children!.push(newFolder);
        } else {
          rootItems.push(newFolder);
        }
      }

      parentFolder = folderMap.get(currentPath)!;
    }

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
 * Binary file extensions to skip text reading
 */
const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "ico", "webp", "pdf", "zip", "tar", "gz", "exe", "dmg", "iso", "mp4", "mp3", "woff", "woff2", "ttf", "eot"
]);

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
): Promise<Array<{ name: string; path: string; content: string }>> {
  const results: Array<{ name: string; path: string; content: string }> = [];

  for (let i = 0; i < fileList.length; i++) {
    const file = fileList[i];
    // webkitRelativePath gives e.g. "my-project/src/index.js"
    const fullPath = file.webkitRelativePath || file.name;
    const pathParts = fullPath.split("/");

    // Skip root folder name if present
    const relativePath = pathParts.length > 1 ? pathParts.slice(1).join("/") : fullPath;

    // Check if any directory in path is ignored
    const isIgnored = pathParts.some((p) => IGNORED_DIRS.has(p));
    if (isIgnored) continue;

    const ext = file.name.split(".").pop()?.toLowerCase() || "";
    if (BINARY_EXTENSIONS.has(ext)) continue;

    if (file.size > 1024 * 1024) continue;

    try {
      const content = await file.text();
      results.push({
        name: file.name,
        path: relativePath,
        content,
      });
    } catch (err) {
      console.warn(`Could not read file ${file.name}:`, err);
    }
  }

  return results;
}

/**
 * Save file directly back to disk (via Tauri native IPC or FileSystemFileHandle)
 */
export async function saveFileToDisk(file: FileNode): Promise<boolean> {
  // 1. Try native Tauri IPC if running in desktop environment
  if (
    typeof window !== "undefined" &&
    Boolean((window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__)
  ) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const targetPath = file.path;
      if (targetPath) {
        const res = await invoke<{ success: boolean }>("write_file_to_disk", {
          filePath: targetPath,
          content: file.content,
        });
        if (res?.success) {
          return true;
        }
      }
    } catch (tauriErr) {
      console.warn("[Crux FS] Tauri native file write failed, falling back to Web File API:", tauriErr);
    }
  }

  // 2. Web File System Access API handle
  if (file.handle) {
    try {
      const writable = await file.handle.createWritable();
      await writable.write(file.content);
      await writable.close();
      return true;
    } catch (err) {
      console.error(`Failed to save file ${file.name} to disk:`, err);
      return false;
    }
  }

  return false;
}

/**
 * Export all workspace files into a downloadable ZIP
 */
export async function exportWorkspaceAsZip(
  files: FileNode[],
  projectName = "crux-project"
): Promise<void> {
  const zip = new JSZip();

  for (const file of files) {
    zip.file(file.path, file.content);
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
