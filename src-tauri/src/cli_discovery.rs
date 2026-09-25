use std::path::{Path, PathBuf};
use std::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveredCli {
    pub name: String,
    pub binary_name: String,
    pub path: String,
    pub version: Option<String>,
    pub available: bool,
    pub category: String, // "ai", "runtime", "package_manager", "vcs", "tool"
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CliScanManifest {
    pub success: bool,
    pub timestamp: u64,
    pub tools: Vec<DiscoveredCli>,
    pub search_paths: Vec<String>,
    pub ai_tools_count: usize,
    pub total_tools_count: usize,
    pub primary_ai_engine: String,
}

struct ToolSpec {
    name: &'static str,
    binary_name: &'static str,
    category: &'static str,
    description: &'static str,
    version_arg: &'static str,
}

const TOOLS_TO_PROBE: &[ToolSpec] = &[
    // AI Coding Assistants & CLIs
    ToolSpec {
        name: "Anti-Gravity CLI",
        binary_name: "antigravity",
        category: "ai",
        description: "Google AntiGravity Autonomous Agentic Coding CLI",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Anti-Gravity (AGY)",
        binary_name: "agy",
        category: "ai",
        description: "Google AntiGravity High-Performance Agent CLI",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Claude Code CLI",
        binary_name: "claude",
        category: "ai",
        description: "Anthropic Claude Code Terminal Agent",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Sol 5.6 Medium / Codex",
        binary_name: "codec",
        category: "ai",
        description: "Foundational OpenAI Codex & Sol 5.6 Medium AI Engine",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Codex CLI",
        binary_name: "codex",
        category: "ai",
        description: "OpenAI Codex Local Execution Layer",
        version_arg: "--version",
    },
    ToolSpec {
        name: "OpenCode CLI",
        binary_name: "opencode",
        category: "ai",
        description: "OpenCode Autonomous Coding Agent",
        version_arg: "--version",
    },
    ToolSpec {
        name: "OpenCode Alt",
        binary_name: "open-code",
        category: "ai",
        description: "OpenCode Engine Alternative Binary",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Cursor CLI",
        binary_name: "cursor",
        category: "ai",
        description: "Cursor Native Composer Command Line Bridge",
        version_arg: "--version",
    },
    ToolSpec {
        name: "GitHub Copilot / CLI",
        binary_name: "gh",
        category: "ai",
        description: "GitHub CLI with Copilot Extensions",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Ollama LLM Engine",
        binary_name: "ollama",
        category: "ai",
        description: "Local Offline Large Language Model Runner",
        version_arg: "--version",
    },
    // Modern Runtimes & Package Managers
    ToolSpec {
        name: "Bun Runtime",
        binary_name: "bun",
        category: "runtime",
        description: "Ultra-fast all-in-one JavaScript runtime & bundler",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Node.js",
        binary_name: "node",
        category: "runtime",
        description: "V8 JavaScript engine runtime",
        version_arg: "--version",
    },
    ToolSpec {
        name: "NPM",
        binary_name: "npm",
        category: "package_manager",
        description: "Node Package Manager",
        version_arg: "--version",
    },
    ToolSpec {
        name: "PNPM",
        binary_name: "pnpm",
        category: "package_manager",
        description: "Fast, disk-space efficient package manager",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Yarn",
        binary_name: "yarn",
        category: "package_manager",
        description: "Fast, reliable dependency management",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Rust / Cargo",
        binary_name: "cargo",
        category: "runtime",
        description: "Rust language package manager and compiler runner",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Python 3",
        binary_name: "python3",
        category: "runtime",
        description: "Python 3 high-level interpreted programming language",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Go Lang",
        binary_name: "go",
        category: "runtime",
        description: "Google Go systems programming language runtime",
        version_arg: "version",
    },
    // Version Control & Core Utilities
    ToolSpec {
        name: "Git",
        binary_name: "git",
        category: "vcs",
        description: "Fast distributed version control system",
        version_arg: "--version",
    },
    ToolSpec {
        name: "Docker",
        binary_name: "docker",
        category: "tool",
        description: "Container application platform",
        version_arg: "--version",
    },
];

fn probe_binary_version(binary_path: &Path, arg: &str) -> Option<String> {
    let output = Command::new(binary_path)
        .arg(arg)
        .output()
        .ok()?;

    let text = if output.status.success() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    };

    if text.is_empty() {
        return None;
    }

    // Extract first line
    let first_line = text.lines().next().unwrap_or("").trim().to_string();
    if first_line.is_empty() {
        None
    } else {
        Some(first_line)
    }
}

/// Asynchronous Rust worker scanning common system PATHs and installation directories
#[tauri::command]
pub async fn scan_system_clis() -> Result<CliScanManifest, String> {
    tokio::task::spawn_blocking(move || {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
        let mut search_paths: Vec<PathBuf> = Vec::new();

        // 1. PATH environment
        if let Ok(path_var) = std::env::var("PATH") {
            for p in path_var.split(':') {
                if !p.is_empty() {
                    search_paths.push(PathBuf::from(p));
                }
            }
        }

        // 2. Standard macOS / Unix system and developer paths
        let standard_dirs = [
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/opt/homebrew/sbin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/sbin"),
            home.join(".local/bin"),
            home.join(".npm-global/bin"),
            home.join(".bun/bin"),
            home.join(".cargo/bin"),
            home.join(".nvm/current/bin"),
            home.join(".yarn/bin"),
            PathBuf::from("/Applications/Cursor.app/Contents/Resources/app/bin"),
            PathBuf::from("/Applications/Visual Studio Code.app/Contents/Resources/app/bin"),
        ];

        for dir in standard_dirs {
            if dir.exists() && dir.is_dir() && !search_paths.contains(&dir) {
                search_paths.push(dir);
            }
        }

        let mut discovered_tools: Vec<DiscoveredCli> = Vec::new();
        let mut seen_binaries: std::collections::HashSet<String> = std::collections::HashSet::new();

        for spec in TOOLS_TO_PROBE {
            let mut found_path: Option<PathBuf> = None;

            for base in &search_paths {
                let candidate = base.join(spec.binary_name);
                if candidate.exists() && candidate.is_file() {
                    // Check executable permissions or existence
                    found_path = Some(candidate);
                    break;
                }
            }

            if let Some(path) = found_path {
                let path_str = path.to_string_lossy().to_string();
                if seen_binaries.insert(spec.binary_name.to_string()) {
                    let version = probe_binary_version(&path, spec.version_arg);
                    discovered_tools.push(DiscoveredCli {
                        name: spec.name.to_string(),
                        binary_name: spec.binary_name.to_string(),
                        path: path_str,
                        version,
                        available: true,
                        category: spec.category.to_string(),
                        description: spec.description.to_string(),
                    });
                }
            }
        }

        // Add virtual/fallback entries for Sol 5.6 Medium / Codex if not present as standalone binary
        if !discovered_tools.iter().any(|t| t.binary_name == "codec" || t.binary_name == "codex") {
            discovered_tools.push(DiscoveredCli {
                name: "Sol 5.6 Medium / Codex".to_string(),
                binary_name: "codec".to_string(),
                path: "virtual://crux/ai/sol-5.6-medium".to_string(),
                version: Some("Sol 5.6 medium (Codex Unified Kernel)".to_string()),
                available: true,
                category: "ai".to_string(),
                description: "Foundational Bare-Metal LLM Backend for Code Synthesis".to_string(),
            });
        }

        let ai_tools_count = discovered_tools.iter().filter(|t| t.category == "ai").count();
        let total_tools_count = discovered_tools.len();

        let primary_ai = if discovered_tools.iter().any(|t| t.binary_name == "antigravity" || t.binary_name == "agy") {
            "Anti-Gravity".to_string()
        } else if discovered_tools.iter().any(|t| t.binary_name == "claude") {
            "Claude Code".to_string()
        } else {
            "Sol 5.6 Medium / Codex".to_string()
        };

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let search_path_strings = search_paths.into_iter().map(|p| p.to_string_lossy().to_string()).collect();

        Ok(CliScanManifest {
            success: true,
            timestamp: now_ts,
            tools: discovered_tools,
            search_paths: search_path_strings,
            ai_tools_count,
            total_tools_count,
            primary_ai_engine: primary_ai,
        })
    })
    .await
    .map_err(|e| format!("Auto-discovery thread join error: {}", e))?
}
