use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use base64::Engine;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImportedFile {
    pub name: String,
    pub path: String,
    pub content: String,
    #[serde(rename = "binaryBase64", skip_serializing_if = "Option::is_none")]
    pub binary_base64: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImportResult {
    pub files: Vec<ImportedFile>,
    pub folders: Vec<String>,
    pub skipped: usize,
}

/// Read code files from a folder selected by the native directory picker.
#[tauri::command]
pub fn import_directory_from_disk(dir_path: String) -> Result<ImportResult, String> {
    import_paths_from_disk(vec![dir_path])
}

/// Import files and folders dragged in from the host operating system.
#[tauri::command]
pub fn import_paths_from_disk(paths: Vec<String>) -> Result<ImportResult, String> {
    let mut result = ImportResult {
        files: Vec::new(),
        folders: Vec::new(),
        skipped: 0,
    };
    for selected in paths {
        let path = Path::new(&selected);
        let name = path.file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "project".to_string());
        if path.is_dir() {
            import_directory_recursive(path, path, &name, &mut result)?;
        } else if path.is_file() {
            import_file(path, &name, &mut result);
        } else {
            result.skipped += 1;
        }
    }
    Ok(result)
}

fn import_directory_recursive(
    root: &Path,
    current: &Path,
    folder_name: &str,
    result: &mut ImportResult,
) -> Result<(), String> {
    const IGNORED_DIRS: &[&str] = &[
        ".git", "node_modules", ".next", "dist", "build", ".turbo",
        ".vercel", ".cache", ".idea", ".vscode", "target",
    ];
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(error) if current == root => return Err(error.to_string()),
        Err(_) => {
            result.skipped += 1;
            return Ok(());
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };

        // Do not follow symlinks outside the selected directory.
        if file_type.is_symlink() {
            result.skipped += 1;
            continue;
        }
        if file_type.is_dir() {
            if !IGNORED_DIRS.contains(&name.as_str()) {
                import_directory_recursive(root, &path, folder_name, result)?;
            }
            continue;
        }
        if !file_type.is_file() {
            result.skipped += 1;
            continue;
        }
        let relative = match path.strip_prefix(root) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        import_file(&path, &format!("{}/{}", folder_name, relative.to_string_lossy().replace('\\', "/")), result);
    }

    let relative = current.strip_prefix(root).map_err(|e| e.to_string())?;
    let folder_path = if relative.as_os_str().is_empty() {
        folder_name.to_string()
    } else {
        format!("{}/{}", folder_name, relative.to_string_lossy().replace('\\', "/"))
    };
    result.folders.push(folder_path);

    Ok(())
}

fn import_file(path: &Path, display_path: &str, result: &mut ImportResult) {
    const BINARY_EXTENSIONS: &[&str] = &[
        "png", "jpg", "jpeg", "gif", "ico", "webp", "pdf", "zip", "tar",
        "gz", "exe", "dmg", "iso", "mp4", "mp3", "woff", "woff2", "ttf", "eot",
    ];
    let extension = path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let bytes = match fs::metadata(path) {
        Ok(metadata) if metadata.len() <= 10 * 1024 * 1024 => fs::read(path),
        _ => {
            result.skipped += 1;
            return;
        }
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(_) => {
            result.skipped += 1;
            return;
        }
    };
    let (content, binary_base64) = if BINARY_EXTENSIONS.contains(&extension.as_str()) {
        ("Binary file — preview unavailable".to_string(), Some(base64::engine::general_purpose::STANDARD.encode(&bytes)))
    } else {
        match String::from_utf8(bytes) {
            Ok(content) => (content, None),
            Err(error) => ("Binary file — preview unavailable".to_string(), Some(base64::engine::general_purpose::STANDARD.encode(error.into_bytes()))),
        }
    };
    result.files.push(ImportedFile {
        name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        path: display_path.to_string(),
        content,
        binary_base64,
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_nested_and_empty_folders_with_file_paths() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::write(root.join("src/main.ts"), "export const ready = true;").unwrap();
        fs::write(root.join("logo.png"), [0_u8, 1, 2]).unwrap();

        let result = import_paths_from_disk(vec![root.to_string_lossy().to_string()]).unwrap();
        assert!(result.folders.contains(&"project".to_string()));
        assert!(result.folders.contains(&"project/src".to_string()));
        assert!(result.folders.contains(&"project/empty".to_string()));
        assert_eq!(result.files.len(), 2);
        assert!(result.files.iter().any(|file| file.path == "project/src/main.ts" && file.content == "export const ready = true;"));
        assert!(result.files.iter().any(|file| file.path == "project/logo.png" && file.binary_base64.is_some()));
        assert_eq!(result.skipped, 0);
    }
}
