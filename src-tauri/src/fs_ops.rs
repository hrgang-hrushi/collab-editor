use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiskFileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReadFileResult {
    pub success: bool,
    pub path: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WriteFileResult {
    pub success: bool,
    pub path: String,
    pub bytes_written: usize,
}

/// Recursively list files in a directory up to max_depth (skipping node_modules, .git, etc.)
#[tauri::command]
pub fn list_directory_tree(dir_path: String, max_depth: Option<usize>) -> Result<Vec<DiskFileEntry>, String> {
    let root = Path::new(&dir_path);
    if !root.exists() {
        return Err(format!("Path does not exist: {}", dir_path));
    }
    if !root.is_dir() {
        return Err(format!("Path is not a directory: {}", dir_path));
    }

    let limit = max_depth.unwrap_or(6);
    let mut entries = Vec::new();
    walk_dir_recursive(root, root, 0, limit, &mut entries)?;

    Ok(entries)
}

fn walk_dir_recursive(
    root: &Path,
    current: &Path,
    depth: usize,
    max_depth: usize,
    results: &mut Vec<DiskFileEntry>,
) -> Result<(), String> {
    if depth > max_depth {
        return Ok(());
    }

    let read_dir = fs::read_dir(current).map_err(|e| e.to_string())?;

    for entry in read_dir.flatten() {
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();

        // Skip ignored directories
        if file_name.starts_with('.')
            || file_name == "node_modules"
            || file_name == "target"
            || file_name == ".next"
            || file_name == "dist"
            || file_name == "build"
        {
            continue;
        }

        let is_dir = path.is_dir();
        let rel_path = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| file_name.clone());

        let size_bytes = if is_dir {
            0
        } else {
            entry.metadata().map(|m| m.len()).unwrap_or(0)
        };

        results.push(DiskFileEntry {
            name: file_name,
            path: rel_path,
            is_dir,
            size_bytes,
        });

        if is_dir {
            walk_dir_recursive(root, &path, depth + 1, max_depth, results)?;
        }
    }

    Ok(())
}

/// Read text file directly from host filesystem
#[tauri::command]
pub fn read_file_from_disk(file_path: String) -> Result<ReadFileResult, String> {
    let path = Path::new(&file_path);
    if !path.exists() {
        return Err(format!("File does not exist: {}", file_path));
    }
    let content = fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;

    Ok(ReadFileResult {
        success: true,
        path: file_path,
        content,
    })
}

/// Write text file directly to host filesystem
#[tauri::command]
pub fn write_file_to_disk(file_path: String, content: String) -> Result<WriteFileResult, String> {
    let path = Path::new(&file_path);
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create parent dirs: {}", e))?;
        }
    }

    let bytes = content.as_bytes();
    fs::write(path, bytes).map_err(|e| format!("Failed to write to file: {}", e))?;

    Ok(WriteFileResult {
        success: true,
        path: file_path,
        bytes_written: bytes.len(),
    })
}
