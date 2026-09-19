pub mod router;

use router::{AiRouter, RouteEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelServiceInfo {
    pub name: String,
    pub port: u16,
    pub active: bool,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceTask {
    pub label: String,
    pub command: String,
    pub task_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareState {
    pub os: String,
    pub arch: String,
    pub logical_cores: usize,
    pub services: Vec<ModelServiceInfo>,
    pub workspace_tasks: Vec<WorkspaceTask>,
    pub ai_routes: HashMap<String, RouteEntry>,
    pub active_ai_provider: String,
}

fn check_port(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok()
}

fn discover_model_services() -> Vec<ModelServiceInfo> {
    let targets = [
        ("Ollama", 11434, "http://127.0.0.1:11434/api/tags"),
        ("LM Studio", 1234, "http://127.0.0.1:1234/v1/models"),
        ("OpenClaw / LocalAI", 8080, "http://127.0.0.1:8080/v1/models"),
        ("vLLM Engine", 8000, "http://127.0.0.1:8000/v1/models"),
    ];

    targets
        .iter()
        .map(|(name, port, endpoint)| {
            let active = check_port(*port);
            ModelServiceInfo {
                name: name.to_string(),
                port: *port,
                active,
                endpoint: endpoint.to_string(),
            }
        })
        .collect()
}

fn parse_vscode_tasks(root: &Path) -> Vec<WorkspaceTask> {
    let mut tasks = Vec::new();
    let tasks_path = root.join(".vscode").join("tasks.json");
    if let Ok(content) = fs::read_to_string(tasks_path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(task_list) = val.get("tasks").and_then(|t| t.as_array()) {
                for t in task_list {
                    let label = t.get("label").and_then(|l| l.as_str()).unwrap_or("unnamed");
                    let command = t.get("command").and_then(|c| c.as_str()).unwrap_or("");
                    let task_type = t.get("type").and_then(|tp| tp.as_str()).unwrap_or("shell");

                    tasks.push(WorkspaceTask {
                        label: label.to_string(),
                        command: command.to_string(),
                        task_type: task_type.to_string(),
                    });
                }
            }
        }
    }
    tasks
}

fn parse_idea_configurations(root: &Path) -> Vec<WorkspaceTask> {
    let mut tasks = Vec::new();
    let run_configs = root.join(".idea").join("runConfigurations");
    if let Ok(entries) = fs::read_dir(run_configs) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("xml") {
                if let Ok(content) = fs::read_to_string(&path) {
                    let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("task");
                    tasks.push(WorkspaceTask {
                        label: file_stem.to_string(),
                        command: if content.contains("Application") { "java/run" } else { "exec" }.to_string(),
                        task_type: "idea_run".to_string(),
                    });
                }
            }
        }
    }
    tasks
}

fn main() {
    let mut ai_router = AiRouter::new();

    // Check if invoked with a route command e.g. `crex-daemon --route "> route add openai sk-..."`
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--route" {
        let cmd = args[2..].join(" ");
        let result = ai_router.handle_omnibar_command(&cmd);
        println!("{}", result);
        return;
    }

    let current_dir = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    let services = discover_model_services();

    let mut workspace_tasks = parse_vscode_tasks(&current_dir);
    workspace_tasks.extend(parse_idea_configurations(&current_dir));

    let state = HardwareState {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        logical_cores: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
        services,
        workspace_tasks,
        ai_routes: ai_router.routes,
        active_ai_provider: ai_router.active_provider,
    };

    let json = serde_json::to_string_pretty(&state).unwrap_or_else(|_| "{}".to_string());
    println!("{}", json);
}
