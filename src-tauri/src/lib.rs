use std::fs;
use std::process::Command;
use std::time::Instant;
use tempfile::tempdir;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub execution_time_ms: u128,
}

fn prepare_command(program: &str, dir_path: &std::path::Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.current_dir(dir_path);
    let home = std::env::var("HOME").unwrap_or_default();
    let current_path = std::env::var("PATH").unwrap_or_default();
    let extended_path = format!(
        "{}/.bun/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:{}",
        home, current_path
    );
    cmd.env("PATH", extended_path);
    cmd
}

pub mod commands {
    use super::*;

    #[tauri::command]
    pub fn execute_code(language: String, source_code: String) -> Result<ExecutionResult, String> {
        let start_time = Instant::now();
        let dir = tempdir().map_err(|e| format!("Failed to create temporary sandbox directory: {}", e))?;
        let dir_path = dir.path();

        let lang = language.to_lowercase();
        let (compile_cmd, run_cmd) = match lang.as_str() {
            "python" | "py" => {
                let file_path = dir_path.join("script.py");
                fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;
                let mut cmd = prepare_command("python3", dir_path);
                cmd.arg(file_path);
                (None, Some(cmd))
            }
            "rust" | "rs" => {
                let src_path = dir_path.join("main.rs");
                let bin_path = dir_path.join("app_bin");
                fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;
                let mut comp = prepare_command("rustc", dir_path);
                comp.arg(&src_path).arg("-o").arg(&bin_path);
                let run = prepare_command(bin_path.to_str().unwrap_or("app_bin"), dir_path);
                (Some(comp), Some(run))
            }
            "c" => {
                let src_path = dir_path.join("main.c");
                let bin_path = dir_path.join("app_bin");
                fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;
                let mut comp = prepare_command("gcc", dir_path);
                comp.arg(&src_path).arg("-o").arg(&bin_path);
                let run = prepare_command(bin_path.to_str().unwrap_or("app_bin"), dir_path);
                (Some(comp), Some(run))
            }
            "cpp" | "c++" => {
                let src_path = dir_path.join("main.cpp");
                let bin_path = dir_path.join("app_bin");
                fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;
                let mut comp = prepare_command("g++", dir_path);
                comp.arg(&src_path).arg("-o").arg(&bin_path);
                let run = prepare_command(bin_path.to_str().unwrap_or("app_bin"), dir_path);
                (Some(comp), Some(run))
            }
            "java" => {
                // Extract public class or class name if present, default to "Main"
                let class_name = source_code
                    .lines()
                    .find_map(|line| {
                        let trimmed = line.trim();
                        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                            return None;
                        }
                        if let Some(pos) = trimmed.find("class ") {
                            let after = &trimmed[pos + 6..];
                            let name = after
                                .split_whitespace()
                                .next()
                                .unwrap_or("")
                                .trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                            if !name.is_empty() {
                                return Some(name.to_string());
                            }
                        }
                        None
                    })
                    .unwrap_or_else(|| "Main".to_string());

                let file_name = format!("{}.java", class_name);
                let src_path = dir_path.join(&file_name);
                fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;

                let mut comp = prepare_command("javac", dir_path);
                comp.arg(&src_path);

                let mut run = prepare_command("java", dir_path);
                run.arg(&class_name);

                (Some(comp), Some(run))
            }
            "swift" => {
                let src_path = dir_path.join("main.swift");
                let bin_path = dir_path.join("app_bin");
                fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;
                let mut comp = prepare_command("swiftc", dir_path);
                comp.arg(&src_path).arg("-o").arg(&bin_path);
                let run = prepare_command(bin_path.to_str().unwrap_or("app_bin"), dir_path);
                (Some(comp), Some(run))
            }
            "javascript" | "js" | "node" => {
                let file_path = dir_path.join("script.js");
                fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;
                let mut cmd = prepare_command("node", dir_path);
                cmd.arg(file_path);
                (None, Some(cmd))
            }
            "typescript" | "ts" => {
                let file_path = dir_path.join("script.ts");
                fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;
                let mut cmd = prepare_command("bun", dir_path);
                cmd.arg("run").arg(file_path);
                (None, Some(cmd))
            }
            _ => {
                return Err(format!("Unsupported bare-metal language execution target: {}", language));
            }
        };

        if let Some(mut comp) = compile_cmd {
            let comp_output = comp.output().map_err(|e| format!("Compilation process failed: {}", e))?;
            if !comp_output.status.success() {
                let execution_time_ms = start_time.elapsed().as_millis();
                return Ok(ExecutionResult {
                    stdout: String::from_utf8_lossy(&comp_output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&comp_output.stderr).to_string(),
                    exit_code: comp_output.status.code().unwrap_or(1),
                    execution_time_ms,
                });
            }
        }

        if let Some(mut run) = run_cmd {
            let run_output = run.output().map_err(|e| format!("Binary execution failed: {}", e))?;
            let execution_time_ms = start_time.elapsed().as_millis();
            Ok(ExecutionResult {
                stdout: String::from_utf8_lossy(&run_output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&run_output.stderr).to_string(),
                exit_code: run_output.status.code().unwrap_or(0),
                execution_time_ms,
            })
        } else {
            Err("No executable command configured for target".to_string())
        }
    }
}

pub use commands::execute_code;
pub mod migration;
pub use migration::{scan_existing_ides, migrate_ide_assets};
pub mod fs_ops;
pub mod terminal;
pub use terminal::{pty_spawn, pty_write, pty_resize, pty_kill, terminal_spawn, terminal_input, terminal_kill, git_command};
pub mod cli_discovery;
pub use cli_discovery::scan_system_clis;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::execute_code,
            migration::scan_existing_ides,
            migration::migrate_ide_assets,
            cli_discovery::scan_system_clis,
            fs_ops::list_directory_tree,
            fs_ops::read_file_from_disk,
            fs_ops::write_file_to_disk,
            fs_ops::import_directory_from_disk,
            fs_ops::import_paths_from_disk,
            terminal::pty_spawn,
            terminal::pty_write,
            terminal::pty_resize,
            terminal::pty_kill,
            terminal::terminal_spawn,
            terminal::terminal_input,
            terminal::terminal_kill,
            terminal::git_command
        ])
        .run(tauri::generate_context!())
        .expect("error while running Crux desktop application");
}
