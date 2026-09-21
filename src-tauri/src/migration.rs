use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DetectedIde {
    pub id: String,
    pub name: String,
    pub config_path: String,
    pub has_settings: bool,
    pub has_keybindings: bool,
    pub has_snippets: bool,
    pub has_cursorrules: bool,
    pub settings_json: Option<serde_json::Value>,
    pub keybindings_json: Option<serde_json::Value>,
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
pub struct DiscoveredAgentSkill {
    pub name: String,
    pub path: String,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdeScanManifest {
    pub timestamp: u64,
    pub permission_granted: bool,
    pub ides: Vec<DetectedIde>,
    pub extensions: Vec<ExtensionSummary>,
    pub rules_files: Vec<String>,
    pub custom_skills: Vec<DiscoveredAgentSkill>,
    pub total_settings_count: usize,
    pub total_keybindings_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MigrationResult {
    pub success: bool,
    pub permission_granted: bool,
    pub imported_settings_count: usize,
    pub imported_keybindings_count: usize,
    pub imported_theme: Option<String>,
    pub imported_rules_count: usize,
    pub message: String,
    pub cursorrules_content: Option<String>,
}

/// Strips single-line and multi-line comments from JSON string
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

    output
}

fn read_relaxed_json(path: &Path) -> Option<serde_json::Value> {
    if !path.exists() {
        return None;
    }
    let raw = fs::read_to_string(path).ok()?;
    let cleaned = clean_json_comments(&raw);
    serde_json::from_str(&cleaned).ok()
}

fn get_home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)
}

fn get_ide_candidate_paths(home: &Path) -> Vec<(&'static str, &'static str, PathBuf)> {
    vec![
        // VS Code
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
        // Cursor
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
        // Windsurf
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
    ]
}

fn scan_extensions(home: &Path) -> Vec<ExtensionSummary> {
    let mut summaries = Vec::new();
    let extension_roots = [
        home.join(".vscode/extensions"),
        home.join(".cursor/extensions"),
    ];

    for root in &extension_roots {
        if !root.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let pkg_json = path.join("package.json");
                    if pkg_json.exists() {
                        if let Ok(content) = fs::read_to_string(&pkg_json) {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                                let id = val.get("name").and_string_or_default();
                                let display_name = val.get("displayName")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&id)
                                    .to_string();
                                let version = val.get("version").and_string_or_default();

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

fn scan_agent_skills(home: &Path) -> Vec<DiscoveredAgentSkill> {
    let mut skills = Vec::new();
    let skill_roots = [
        home.join(".cursor/skills-cursor"),
        home.join(".cursor/agents"),
        home.join(".gemini/antigravity-cli/skills"),
    ];

    for root in &skill_roots {
        if !root.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if path.is_dir() {
                    let desc = path.join("SKILL.md")
                        .exists()
                        .then(|| "Standard Agent Skill definition".to_string());
                    skills.push(DiscoveredAgentSkill {
                        name,
                        path: path.to_string_lossy().to_string(),
                        description: desc,
                    });
                }
            }
        }
    }

    skills
}

trait JsonStringHelper {
    fn and_string_or_default(&self) -> String;
}

impl JsonStringHelper for Option<&serde_json::Value> {
    fn and_string_or_default(&self) -> String {
        self.and_then(|v| v.as_str()).unwrap_or("").to_string()
    }
}

#[tauri::command]
pub fn scan_existing_ides(permission_granted: Option<bool>) -> Result<IdeScanManifest, String> {
    // Explicit permission validation check
    let granted = permission_granted.unwrap_or(true);
    if !granted {
        return Err("Permission denied: user consent required to scan local IDE configuration directories".to_string());
    }

    let home = get_home_dir().ok_or_else(|| "Could not determine user HOME directory".to_string())?;

    let candidates = get_ide_candidate_paths(&home);
    let mut detected_ides = Vec::new();
    let mut total_settings = 0;
    let mut total_keybindings = 0;

    for (ide_id, ide_name, config_dir) in candidates {
        if !config_dir.exists() {
            continue;
        }

        // Avoid adding duplicate IDs if both paths exist
        if detected_ides.iter().any(|d: &DetectedIde| d.id == ide_id) {
            continue;
        }

        let settings_path = config_dir.join("settings.json");
        let keybindings_path = config_dir.join("keybindings.json");
        let snippets_dir = config_dir.join("snippets");

        let settings_val = read_relaxed_json(&settings_path);
        let keybindings_val = read_relaxed_json(&keybindings_path);

        let has_settings = settings_val.is_some();
        let has_keybindings = keybindings_val.is_some();
        let has_snippets = snippets_dir.exists();

        let active_theme = settings_val.as_ref().and_then(|val| {
            val.get("workbench.colorTheme")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
        });

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
        let cursorrules_content = if cwd_cursorrules.exists() {
            fs::read_to_string(cwd_cursorrules).ok()
        } else if cursorrules_path.exists() {
            fs::read_to_string(&cursorrules_path).ok()
        } else {
            None
        };

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

    let extensions = scan_extensions(&home);
    let custom_skills = scan_agent_skills(&home);

    let mut rules_files = Vec::new();
    let rules_candidates = [
        home.join(".cursorrules"),
        home.join(".windsurfrules"),
        PathBuf::from(".cursorrules"),
        PathBuf::from(".windsurfrules"),
    ];
    for r in &rules_candidates {
        if r.exists() {
            rules_files.push(r.to_string_lossy().to_string());
        }
    }

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(IdeScanManifest {
        timestamp: now_ts,
        permission_granted: true,
        ides: detected_ides,
        extensions,
        rules_files,
        custom_skills,
        total_settings_count: total_settings,
        total_keybindings_count: total_keybindings,
    })
}

#[tauri::command]
pub fn migrate_ide_assets(selected_ide_id: String, permission_granted: Option<bool>) -> Result<MigrationResult, String> {
    let granted = permission_granted.unwrap_or(true);
    if !granted {
        return Err("Permission denied: user consent required to migrate configurations".to_string());
    }

    let manifest = scan_existing_ides(Some(true))?;
    let selected = manifest
        .ides
        .iter()
        .find(|i| i.id == selected_ide_id)
        .or_else(|| manifest.ides.first())
        .ok_or_else(|| format!("No configuration found for IDE '{}'", selected_ide_id))?;

    let mut imported_settings = 0;
    if let Some(s) = &selected.settings_json {
        if let Some(obj) = s.as_object() {
            imported_settings = obj.len();
        }
    }

    let mut imported_keybindings = 0;
    if let Some(k) = &selected.keybindings_json {
        if let Some(arr) = k.as_array() {
            imported_keybindings = arr.len();
        }
    }

    let imported_rules = if selected.has_cursorrules { 1 } else { 0 } + manifest.rules_files.len();

    // 1. Write ~/.crux/ settings, keybindings, and snapshot
    if let Some(home) = get_home_dir() {
        let crux_dir = home.join(".crux");
        let _ = fs::create_dir_all(&crux_dir);
        
        if let Some(s) = &selected.settings_json {
            let _ = fs::write(crux_dir.join("settings.json"), serde_json::to_string_pretty(s).unwrap_or_default());
        }
        if let Some(k) = &selected.keybindings_json {
            let _ = fs::write(crux_dir.join("keybindings.json"), serde_json::to_string_pretty(k).unwrap_or_default());
        }

        let config_target = crux_dir.join("migrated_config.json");
        let snapshot = serde_json::json!({
            "source_ide": selected.name,
            "migrated_at": manifest.timestamp,
            "settings": selected.settings_json,
            "keybindings": selected.keybindings_json,
            "active_theme": selected.active_theme,
            "rules": selected.cursorrules,
        });
        let _ = fs::write(config_target, serde_json::to_string_pretty(&snapshot).unwrap_or_default());
    }

    // 2. If .cursorrules was detected and not in local project root, write it to .cursorrules
    let cursorrules_content = selected.cursorrules.clone();
    if let Some(rules) = &cursorrules_content {
        let project_cursorrules = Path::new(".cursorrules");
        if !project_cursorrules.exists() {
            let _ = fs::write(project_cursorrules, rules);
        }
    }

    Ok(MigrationResult {
        success: true,
        permission_granted: true,
        imported_settings_count: imported_settings,
        imported_keybindings_count: imported_keybindings,
        imported_theme: selected.active_theme.clone(),
        imported_rules_count: imported_rules,
        message: format!("Successfully migrated {} assets from {}", imported_settings + imported_keybindings, selected.name),
        cursorrules_content,
    })
}
