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

mod commands {
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
            let mut cmd = Command::new("python3");
            cmd.arg(file_path).current_dir(dir_path);
            (None, Some(cmd))
        }
        "rust" | "rs" => {
            let src_path = dir_path.join("main.rs");
            let bin_path = dir_path.join("app_bin");
            fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;
            let mut comp = Command::new("rustc");
            comp.arg(&src_path).arg("-o").arg(&bin_path).current_dir(dir_path);
            let mut run = Command::new(bin_path);
            run.current_dir(dir_path);
            (Some(comp), Some(run))
        }
        "c" => {
            let src_path = dir_path.join("main.c");
            let bin_path = dir_path.join("app_bin");
            fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;
            let mut comp = Command::new("gcc");
            comp.arg(&src_path).arg("-o").arg(&bin_path).current_dir(dir_path);
            let mut run = Command::new(bin_path);
            run.current_dir(dir_path);
            (Some(comp), Some(run))
        }
        "cpp" | "c++" => {
            let src_path = dir_path.join("main.cpp");
            let bin_path = dir_path.join("app_bin");
            fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;
            let mut comp = Command::new("g++");
            comp.arg(&src_path).arg("-o").arg(&bin_path).current_dir(dir_path);
            let mut run = Command::new(bin_path);
            run.current_dir(dir_path);
            (Some(comp), Some(run))
        }
        "java" => {
            let src_path = dir_path.join("Main.java");
            fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;
            let mut comp = Command::new("javac");
            comp.arg(&src_path).current_dir(dir_path);
            let mut run = Command::new("java");
            run.arg("Main").current_dir(dir_path);
            (Some(comp), Some(run))
        }
        "swift" => {
            let src_path = dir_path.join("main.swift");
            let bin_path = dir_path.join("app_bin");
            fs::write(&src_path, &source_code).map_err(|e| e.to_string())?;
            let mut comp = Command::new("swiftc");
            comp.arg(&src_path).arg("-o").arg(&bin_path).current_dir(dir_path);
            let mut run = Command::new(bin_path);
            run.current_dir(dir_path);
            (Some(comp), Some(run))
        }
        "javascript" | "js" | "node" => {
            let file_path = dir_path.join("script.js");
            fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;
            let mut cmd = Command::new("node");
            cmd.arg(file_path).current_dir(dir_path);
            (None, Some(cmd))
        }
        "typescript" | "ts" => {
            let file_path = dir_path.join("script.ts");
            fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;
            let mut cmd = Command::new("bun");
            cmd.arg("run").arg(file_path).current_dir(dir_path);
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

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().build())
        .invoke_handler(tauri::generate_handler![commands::execute_code])
        .run(tauri::generate_context!())
        .expect("error while running Crex desktop application");
}
