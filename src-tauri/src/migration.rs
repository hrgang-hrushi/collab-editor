use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DetectedIde {
    pub id: String,
    pub name: String,
    pub config_path: String,
    pub has_settings: bool,
    pub has_keybindings: bool,
    pub has_snippets: bool,
    pub has_cursorrules: bool,
    pub settings_json: Option<Value>,
    pub keybindings_json: Option<Value>,
    pub cursorrules: Option<String>,
    pub active_theme: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExtensionSummary {
    pub id: String,
    pub name: String,
    pub version: String,
    pub themes: Vec<String>,
    pub has_grammars: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdeScanManifest {
    pub success: bool,
    pub timestamp: u64,
    pub ides: Vec<DetectedIde>,
    pub extensions: Vec<ExtensionSummary>,
    pub rules_files: Vec<String>,
    pub total_settings_count: usize,
    pub total_keybindings_count: usize,
    pub saved_config_path: Option<String>,
    pub active_theme: Option<String>,
    pub cursorrules_content: Option<String>,
    pub message: String,
}

/// Strips comments and trailing commas from JSON/JSONC string
fn clean_json_comments(input: &str) -> String {
    let mut output = String::new();
    let mut in_string = false;
    let mut in_single_comment = false;
    let mut in_multi_comment = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if in_single_comment {
            if c == '\n' || c == '\r' {
                in_single_comment = false;
                output.push(c);
            }
            continue;
        }

        if in_multi_comment {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_multi_comment = false;
            }
            continue;
        }

        if in_string {
            output.push(c);
            if c == '\\' {
                if let Some(next_c) = chars.next() {
                    output.push(next_c);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        if c == '"' {
            in_string = true;
            output.push(c);
            continue;
        }

        if c == '/' {
            if chars.peek() == Some(&'/') {
                chars.next();
                in_single_comment = true;
                continue;
            } else if chars.peek() == Some(&'*') {
                chars.next();
                in_multi_comment = true;
                continue;
            }
        }

        output.push(c);
    }

    // Clean trailing commas before '}' or ']'
    let mut cleaned = String::with_capacity(output.len());
    let mut last_char = ' ';
    for c in output.chars() {
        if (c == '}' || c == ']') && last_char == ',' {
            cleaned.pop(); // Remove the trailing comma
            // Also remove any whitespace before comma
            while let Some(ch) = cleaned.chars().last() {
                if ch.is_whitespace() {
                    cleaned.pop();
                } else {
                    break;
                }
            }
        }
        if !c.is_whitespace() {
            last_char = c;
        }
        cleaned.push(c);
    }

    cleaned
}

/// Safely read and parse relaxed JSON (supports JSON with comments)
fn read_relaxed_json(path: &Path) -> Option<Value> {
    if !path.exists() || !path.is_file() {
        return None;
    }
    match fs::read_to_string(path) {
        Ok(raw) => {
            let cleaned = clean_json_comments(&raw);
            serde_json::from_str(&cleaned).ok()
        }
        Err(_) => None,
    }
}

/// Discovers installed extensions in ~/.vscode/extensions or ~/.cursor/extensions
fn scan_extensions(home: &Path) -> Vec<ExtensionSummary> {
    let mut summaries = Vec::new();
    let extension_roots = [
        home.join(".vscode/extensions"),
        home.join(".cursor/extensions"),
    ];

    for root in &extension_roots {
        if !root.exists() || !root.is_dir() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let pkg_json = path.join("package.json");
                    if pkg_json.exists() {
                        if let Ok(content) = fs::read_to_string(&pkg_json) {
                            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                                let id = val.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let display_name = val
                                    .get("displayName")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&id)
                                    .to_string();
                                let version = val.get("version").and_then(|v| v.as_str()).unwrap_or("1.0.0").to_string();

                                let mut themes = Vec::new();
                                let mut has_grammars = false;

                                if let Some(contributes) = val.get("contributes") {
                                    if let Some(t_array) = contributes.get("themes").and_then(|v| v.as_array()) {
                                        for t in t_array {
                                            if let Some(label) = t.get("label").and_then(|v| v.as_str()) {
                                                themes.push(label.to_string());
                                            }
                                        }
                                    }
                                    if let Some(g_array) = contributes.get("grammars").and_then(|v| v.as_array()) {
                                        has_grammars = !g_array.is_empty();
                                    }
                                }

                                if !id.is_empty() {
                                    summaries.push(ExtensionSummary {
                                        id,
                                        name: display_name,
                                        version,
                                        themes,
                                        has_grammars,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    summaries.dedup_by(|a, b| a.id == b.id);
    summaries
}

/// 1. Path Discovery & 2. JSON Parsing & Translation Logic
/// Scans host filesystem for VS Code, Cursor, and Windsurf configurations,
/// extracts settings, keybindings, themes, and saves translated config to ~/.crux/config.json.
#[tauri::command]
pub fn scan_existing_ides() -> Result<IdeScanManifest, String> {
    let home = dirs::home_dir().ok_or_else(|| "Failed to determine user home directory".to_string())?;

    // Check common IDE configuration candidate directories
    let ide_candidates: Vec<(&'static str, &'static str, PathBuf)> = vec![
        (
            "vscode",
            "Visual Studio Code",
            home.join("Library/Application Support/Code/User"),
        ),
        (
            "vscode",
            "Visual Studio Code",
            home.join(".config/Code/User"),
        ),
        (
            "cursor",
            "Cursor",
            home.join("Library/Application Support/Cursor/User"),
        ),
        (
            "cursor",
            "Cursor",
            home.join(".config/Cursor/User"),
        ),
        (
            "windsurf",
            "Windsurf",
            home.join("Library/Application Support/Windsurf/User"),
        ),
        (
            "windsurf",
            "Windsurf",
            home.join(".config/Windsurf/User"),
        ),
    ];

    let mut detected_ides = Vec::new();
    let mut total_settings = 0;
    let mut total_keybindings = 0;
    let mut primary_theme: Option<String> = None;
    let mut primary_cursorrules: Option<String> = None;

    for (ide_id, ide_name, config_dir) in ide_candidates {
        if !config_dir.exists() || !config_dir.is_dir() {
            continue;
        }

        // Avoid adding duplicate IDE IDs if multiple path styles exist
        if detected_ides.iter().any(|d: &DetectedIde| d.id == ide_id) {
            continue;
        }

        // Target paths:
        // macOS VS Code Settings: dirs::home_dir().map(|h| h.join("Library/Application Support/Code/User/settings.json"))
        // macOS VS Code Keybindings: .../Code/User/keybindings.json
        let settings_path = config_dir.join("settings.json");
        let keybindings_path = config_dir.join("keybindings.json");
        let snippets_dir = config_dir.join("snippets");

        let settings_val = read_relaxed_json(&settings_path);
        let keybindings_val = read_relaxed_json(&keybindings_path);

        let has_settings = settings_val.is_some();
        let has_keybindings = keybindings_val.is_some();
        let has_snippets = snippets_dir.exists() && snippets_dir.is_dir();

        let active_theme = settings_val.as_ref().and_then(|val| {
            val.get("workbench.colorTheme")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
        });

        if primary_theme.is_none() && active_theme.is_some() {
            primary_theme = active_theme.clone();
        }

        if let Some(val) = &settings_val {
            if let Some(obj) = val.as_object() {
                total_settings += obj.len();
            }
        }

        if let Some(val) = &keybindings_val {
            if let Some(arr) = val.as_array() {
                total_keybindings += arr.len();
            }
        }

        // Check for workspace / home .cursorrules
        let cursorrules_path = home.join(".cursorrules");
        let cwd_cursorrules = Path::new(".cursorrules");
        let cursorrules_content = if cwd_cursorrules.exists() && cwd_cursorrules.is_file() {
            fs::read_to_string(cwd_cursorrules).ok()
        } else if cursorrules_path.exists() && cursorrules_path.is_file() {
            fs::read_to_string(&cursorrules_path).ok()
        } else {
            None
        };

        if primary_cursorrules.is_none() && cursorrules_content.is_some() {
            primary_cursorrules = cursorrules_content.clone();
        }

        detected_ides.push(DetectedIde {
            id: ide_id.to_string(),
            name: ide_name.to_string(),
            config_path: config_dir.to_string_lossy().to_string(),
            has_settings,
            has_keybindings,
            has_snippets,
            has_cursorrules: cursorrules_content.is_some(),
            settings_json: settings_val,
            keybindings_json: keybindings_val,
            cursorrules: cursorrules_content,
            active_theme,
        });
    }

    // Catalog extensions and grammars
    let extensions = scan_extensions(&home);

    let mut rules_files = Vec::new();
    let rules_candidates = [
        home.join(".cursorrules"),
        home.join(".windsurfrules"),
        PathBuf::from(".cursorrules"),
        PathBuf::from(".windsurfrules"),
    ];
    for r in &rules_candidates {
        if r.exists() && r.is_file() {
            rules_files.push(r.to_string_lossy().to_string());
        }
    }

    // 2. Save translated configuration into Crux's local directory: ~/.crux/config.json
    let crux_dir = home.join(".crux");
    let mut saved_config_path: Option<String> = None;

    if fs::create_dir_all(&crux_dir).is_ok() {
        let config_file = crux_dir.join("config.json");

        // Select the richest IDE configuration (prefer Cursor if present, else VS Code, else first)
        let selected_ide = detected_ides
            .iter()
            .find(|i| i.id == "cursor")
            .or_else(|| detected_ides.iter().find(|i| i.id == "vscode"))
            .or_else(|| detected_ides.first());

        let translated_config = json!({
            "version": "1.0.0",
            "imported_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "source_ide": selected_ide.map(|i| i.name.clone()).unwrap_or_else(|| "None".to_string()),
            "active_theme": primary_theme.clone().unwrap_or_else(|| "Cursor Dark Midnight".to_string()),
            "settings": selected_ide.and_then(|i| i.settings_json.clone()).unwrap_or(json!({})),
            "keybindings": selected_ide.and_then(|i| i.keybindings_json.clone()).unwrap_or(json!([])),
            "cursorrules": primary_cursorrules.clone(),
            "ai_assistant": {
                "foundational_model": "Sol 5.6 medium / Codex",
                "backend": "codec",
                "auto_injection": true,
                "context_window": 128000
            },
            "detected_ides_count": detected_ides.len(),
            "installed_extensions_count": extensions.len()
        });

        if let Ok(formatted) = serde_json::to_string_pretty(&translated_config) {
            if fs::write(&config_file, formatted).is_ok() {
                saved_config_path = Some(config_file.to_string_lossy().to_string());
            }
        }
    }

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let ide_names = detected_ides
        .iter()
        .map(|i| i.name.as_str())
        .collect::<Vec<&str>>()
        .join(" & ");

    let message = if detected_ides.is_empty() {
        "No legacy IDE configuration directories detected on host".to_string()
    } else {
        format!(
            "Successfully scanned {} ({} settings, {} keybindings, {} extensions)",
            ide_names, total_settings, total_keybindings, extensions.len()
        )
    };

    Ok(IdeScanManifest {
        success: true,
        timestamp: now_ts,
        ides: detected_ides,
        extensions,
        rules_files,
        total_settings_count: total_settings,
        total_keybindings_count: total_keybindings,
        saved_config_path,
        active_theme: primary_theme,
        cursorrules_content: primary_cursorrules,
        message,
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MigrationAssetResult {
    pub success: bool,
    pub source_ide: String,
    pub saved_config_path: Option<String>,
    pub cursorrules_content: Option<String>,
    pub settings_count: usize,
    pub keybindings_count: usize,
    pub active_theme: Option<String>,
    pub message: String,
}

/// Executes migration of assets for a selected IDE (or best match),
/// saving the configuration to ~/.crux/config.json and returning migrated properties.
#[tauri::command]
pub fn migrate_ide_assets(
    selected_ide_id: Option<String>,
    permission_granted: Option<bool>,
) -> Result<MigrationAssetResult, String> {
    if let Some(granted) = permission_granted {
        if !granted {
            return Err("User permission not granted for migration".to_string());
        }
    }

    let manifest = scan_existing_ides()?;
    let selected_id = selected_ide_id.unwrap_or_else(|| "cursor".to_string());
    let ide = manifest
        .ides
        .iter()
        .find(|i| i.id == selected_id)
        .or_else(|| manifest.ides.iter().find(|i| i.id == "cursor"))
        .or_else(|| manifest.ides.first())
        .cloned();

    let (name, settings_count, keybindings_count, active_theme, cursorrules) = match ide {
        Some(i) => {
            let s_count = i.settings_json.as_ref().and_then(|v| v.as_object()).map(|o| o.len()).unwrap_or(0);
            let k_count = i.keybindings_json.as_ref().and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
            (i.name, s_count, k_count, i.active_theme, i.cursorrules)
        }
        None => (
            "Default / Cursor".to_string(),
            manifest.total_settings_count,
            manifest.total_keybindings_count,
            manifest.active_theme.clone(),
            manifest.cursorrules_content.clone(),
        ),
    };

    Ok(MigrationAssetResult {
        success: true,
        source_ide: name.clone(),
        saved_config_path: manifest.saved_config_path,
        cursorrules_content: cursorrules.or(manifest.cursorrules_content),
        settings_count,
        keybindings_count,
        active_theme,
        message: format!("Successfully migrated configuration and assets from {}", name),
    })
}

