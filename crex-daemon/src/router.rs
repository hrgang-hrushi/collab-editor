//! Agnostic AI Router for Crex Native Daemon
//! Connects to OpenAI, Anthropic (Claude), AGY, OpenCode, and local Ollama.
//! Keys and endpoints established strictly via environment variables,
//! OS keychain sweeps, or terminal-style Omnibar command `> route add [provider]`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    OpenAi,
    Anthropic,
    Agy,
    OpenCode,
    Ollama,
}

impl ProviderKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "openai" | "gpt" => Some(ProviderKind::OpenAi),
            "anthropic" | "claude" => Some(ProviderKind::Anthropic),
            "agy" | "antigravity" => Some(ProviderKind::Agy),
            "opencode" => Some(ProviderKind::OpenCode),
            "ollama" | "local" => Some(ProviderKind::Ollama),
            _ => None,
        }
    }

    pub fn default_endpoint(&self) -> &'static str {
        match self {
            ProviderKind::OpenAi => "https://api.openai.com/v1/chat/completions",
            ProviderKind::Anthropic => "https://api.anthropic.com/v1/messages",
            ProviderKind::Agy => "https://api.antigravity.ai/v1/completions",
            ProviderKind::OpenCode => "https://api.opencode.ai/v1/chat",
            ProviderKind::Ollama => "http://127.0.0.1:11434/api/generate",
        }
    }

    pub fn default_model(&self) -> &'static str {
        match self {
            ProviderKind::OpenAi => "gpt-4o",
            ProviderKind::Anthropic => "claude-3-5-sonnet-20241022",
            ProviderKind::Agy => "agy-kernel-v1",
            ProviderKind::OpenCode => "opencode-deepseek-33b",
            ProviderKind::Ollama => "codellama",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteEntry {
    pub provider: ProviderKind,
    pub endpoint: String,
    pub auth_token: Option<String>,
    pub model: String,
    pub is_active: bool,
    pub source: String, // "env", "keychain", "omnibar", "file"
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptRequest {
    pub provider: Option<String>,
    pub prompt: String,
    pub system: Option<String>,
    pub stream: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptResponse {
    pub provider: String,
    pub model: String,
    pub content: String,
    pub latency_ms: u64,
}

pub struct AiRouter {
    pub routes: HashMap<String, RouteEntry>,
    pub active_provider: String,
}

impl AiRouter {
    pub fn new() -> Self {
        let mut router = Self {
            routes: HashMap::new(),
            active_provider: "ollama".to_string(),
        };

        // 1. Discover via Environment Variables
        router.sweep_env_vars();

        // 2. Discover via macOS Keychain
        router.sweep_keychain();

        // 3. Discover via persistent config file (~/.crex/routes.json)
        router.load_persisted_routes();

        // Ensure at least default Ollama exists if nothing active
        if router.routes.is_empty() || !router.routes.contains_key(&router.active_provider) {
            let ollama_entry = RouteEntry {
                provider: ProviderKind::Ollama,
                endpoint: ProviderKind::Ollama.default_endpoint().to_string(),
                auth_token: None,
                model: ProviderKind::Ollama.default_model().to_string(),
                is_active: true,
                source: "default".to_string(),
            };
            router.routes.insert("ollama".to_string(), ollama_entry);
            router.active_provider = "ollama".to_string();
        }

        router
    }

    fn config_dir() -> PathBuf {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".crex")
    }

    fn config_path() -> PathBuf {
        Self::config_dir().join("routes.json")
    }

    /// Read credentials from environment variables
    pub fn sweep_env_vars(&mut self) {
        // OpenAI
        if let Ok(key) = env::var("OPENAI_API_KEY") {
            if !key.trim().is_empty() {
                self.routes.insert(
                    "openai".to_string(),
                    RouteEntry {
                        provider: ProviderKind::OpenAi,
                        endpoint: env::var("OPENAI_ENDPOINT").unwrap_or_else(|_| ProviderKind::OpenAi.default_endpoint().to_string()),
                        auth_token: Some(key),
                        model: env::var("OPENAI_MODEL").unwrap_or_else(|_| ProviderKind::OpenAi.default_model().to_string()),
                        is_active: false,
                        source: "env:OPENAI_API_KEY".to_string(),
                    },
                );
                self.active_provider = "openai".to_string();
            }
        }

        // Anthropic
        if let Ok(key) = env::var("ANTHROPIC_API_KEY") {
            if !key.trim().is_empty() {
                self.routes.insert(
                    "anthropic".to_string(),
                    RouteEntry {
                        provider: ProviderKind::Anthropic,
                        endpoint: env::var("ANTHROPIC_ENDPOINT").unwrap_or_else(|_| ProviderKind::Anthropic.default_endpoint().to_string()),
                        auth_token: Some(key),
                        model: env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| ProviderKind::Anthropic.default_model().to_string()),
                        is_active: false,
                        source: "env:ANTHROPIC_API_KEY".to_string(),
                    },
                );
                self.active_provider = "anthropic".to_string();
            }
        }

        // AGY
        if let Ok(key) = env::var("AGY_API_KEY").or_else(|_| env::var("ANTIGRAVITY_API_KEY")) {
            if !key.trim().is_empty() {
                self.routes.insert(
                    "agy".to_string(),
                    RouteEntry {
                        provider: ProviderKind::Agy,
                        endpoint: env::var("AGY_ENDPOINT").unwrap_or_else(|_| ProviderKind::Agy.default_endpoint().to_string()),
                        auth_token: Some(key),
                        model: ProviderKind::Agy.default_model().to_string(),
                        is_active: false,
                        source: "env:AGY_API_KEY".to_string(),
                    },
                );
                self.active_provider = "agy".to_string();
            }
        }

        // OpenCode
        if let Ok(key) = env::var("OPENCODE_API_KEY") {
            if !key.trim().is_empty() {
                self.routes.insert(
                    "opencode".to_string(),
                    RouteEntry {
                        provider: ProviderKind::OpenCode,
                        endpoint: env::var("OPENCODE_ENDPOINT").unwrap_or_else(|_| ProviderKind::OpenCode.default_endpoint().to_string()),
                        auth_token: Some(key),
                        model: ProviderKind::OpenCode.default_model().to_string(),
                        is_active: false,
                        source: "env:OPENCODE_API_KEY".to_string(),
                    },
                );
            }
        }

        // Ollama local endpoint override
        let ollama_host = env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());
        self.routes.insert(
            "ollama".to_string(),
            RouteEntry {
                provider: ProviderKind::Ollama,
                endpoint: format!("{}/api/generate", ollama_host.trim_end_matches('/')),
                auth_token: None,
                model: env::var("OLLAMA_MODEL").unwrap_or_else(|_| ProviderKind::Ollama.default_model().to_string()),
                is_active: false,
                source: "env:OLLAMA_HOST".to_string(),
            },
        );
    }

    /// Read credentials from macOS Keychain via security binary
    pub fn sweep_keychain(&mut self) {
        if cfg!(target_os = "macos") {
            let targets = ["openai", "anthropic", "agy", "opencode"];
            for provider_name in targets {
                if self.routes.get(provider_name).and_then(|r| r.auth_token.as_ref()).is_some() {
                    continue; // already set via env
                }

                let service_name = format!("crex-ai-{}", provider_name);
                if let Ok(output) = Command::new("security")
                    .args(["find-generic-password", "-s", &service_name, "-w"])
                    .output()
                {
                    if output.status.success() {
                        let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if !token.is_empty() {
                            if let Some(kind) = ProviderKind::parse(provider_name) {
                                self.routes.insert(
                                    provider_name.to_string(),
                                    RouteEntry {
                                        endpoint: kind.default_endpoint().to_string(),
                                        model: kind.default_model().to_string(),
                                        provider: kind,
                                        auth_token: Some(token),
                                        is_active: false,
                                        source: "keychain".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn load_persisted_routes(&mut self) {
        let path = Self::config_path();
        if path.exists() {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(entries) = serde_json::from_str::<HashMap<String, RouteEntry>>(&data) {
                    for (k, v) in entries {
                        if v.is_active {
                            self.active_provider = k.clone();
                        }
                        self.routes.insert(k, v);
                    }
                }
            }
        }
    }

    pub fn save_routes(&self) -> Result<(), String> {
        let dir = Self::config_dir();
        if !dir.exists() {
            let _ = fs::create_dir_all(&dir);
        }
        let json = serde_json::to_string_pretty(&self.routes).map_err(|e| e.to_string())?;
        fs::write(Self::config_path(), json).map_err(|e| e.to_string())
    }

    /// Process terminal-style Omnibar command: `> route add [provider] [token/endpoint]`
    pub fn handle_omnibar_command(&mut self, cmd: &str) -> String {
        let clean = cmd.trim();
        let clean = clean.strip_prefix('>').unwrap_or(clean).trim();

        let parts: Vec<&str> = clean.split_whitespace().collect();
        if parts.is_empty() || parts[0] != "route" {
            return "Usage: > route add [provider] [token/endpoint] | > route list | > route set [provider]".to_string();
        }

        if parts.len() == 1 || parts[1] == "list" {
            let mut out = String::from("ACTIVE AI ROUTES:\n");
            for (name, entry) in &self.routes {
                let mark = if name == &self.active_provider { " [*ACTIVE*]" } else { "" };
                let token_hint = entry.auth_token.as_ref().map(|t| {
                    if t.len() > 6 { format!("{}...{}", &t[..3], &t[t.len()-3..]) } else { "***".to_string() }
                }).unwrap_or_else(|| "none (local/open)".to_string());
                out.push_str(&format!("  - {:10} -> {:35} (model: {}) [src: {}] [token: {}]{}\n", 
                    name, entry.endpoint, entry.model, entry.source, token_hint, mark));
            }
            return out;
        }

        if parts[1] == "set" && parts.len() >= 3 {
            let prov = parts[2].to_lowercase();
            if self.routes.contains_key(&prov) {
                self.active_provider = prov.clone();
                for (k, v) in self.routes.iter_mut() {
                    v.is_active = k == &prov;
                }
                let _ = self.save_routes();
                return format!("[AiRouter] Active provider switched to: {}", prov);
            } else {
                return format!("[AiRouter] Provider '{}' not registered. Run '> route add {} [token]'", prov, prov);
            }
        }

        if parts[1] == "add" && parts.len() >= 3 {
            let prov_name = parts[2].to_lowercase();
            let kind = match ProviderKind::parse(&prov_name) {
                Some(k) => k,
                None => return format!("[AiRouter] Unknown provider '{}'. Supported: openai, anthropic, agy, opencode, ollama", prov_name),
            };

            let token_or_url = parts.get(3).copied();
            let mut endpoint = kind.default_endpoint().to_string();
            let mut auth_token = None;

            if let Some(val) = token_or_url {
                if val.starts_with("http://") || val.starts_with("https://") {
                    endpoint = val.to_string();
                } else {
                    auth_token = Some(val.to_string());
                }
            }

            let entry = RouteEntry {
                provider: kind.clone(),
                endpoint,
                auth_token,
                model: kind.default_model().to_string(),
                is_active: true,
                source: "omnibar".to_string(),
            };

            self.routes.insert(prov_name.clone(), entry);
            self.active_provider = prov_name.clone();
            let _ = self.save_routes();

            return format!("[AiRouter] Successfully configured route: {} (default model: {})", prov_name, kind.default_model());
        }

        if parts[1] == "remove" && parts.len() >= 3 {
            let prov_name = parts[2].to_lowercase();
            self.routes.remove(&prov_name);
            let _ = self.save_routes();
            return format!("[AiRouter] Removed route: {}", prov_name);
        }

        "Unknown route command. Use '> route add [provider] [token]', '> route list', or '> route set [provider]'".to_string()
    }
}
