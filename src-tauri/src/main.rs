#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
}

#[tauri::command]
async fn execute_code(language: String, source_code: String) -> Result<ExecutionResult, String> {
    let start_time = Instant::now();
    let temp_dir = tempfile::tempdir().map_err(|e| format!("Failed to create tempdir: {}", e))?;
    let dir_path: PathBuf = temp_dir.path().to_path_buf();

    let lang = language.to_lowercase();
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = 0;

    match lang.as_str() {
        "python" | "py" => {
            let file_path = dir_path.join("temp.py");
            fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;

            let output = Command::new("python3")
                .arg(&file_path)
                .current_dir(&dir_path)
                .output()
                .map_err(|e| format!("Failed to execute python3: {}", e))?;

            stdout = String::from_utf8_lossy(&output.stdout).to_string();
            stderr = String::from_utf8_lossy(&output.stderr).to_string();
            exit_code = output.status.code().unwrap_or(-1);
        }
        "rust" | "rs" => {
            let file_path = dir_path.join("temp.rs");
            let bin_path = dir_path.join("temp");
            fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;

            let compile_output = Command::new("rustc")
                .arg(&file_path)
                .arg("-o")
                .arg(&bin_path)
                .current_dir(&dir_path)
                .output()
                .map_err(|e| format!("Failed to execute rustc: {}", e))?;

            if !compile_output.status.success() {
                stderr = String::from_utf8_lossy(&compile_output.stderr).to_string();
                exit_code = compile_output.status.code().unwrap_or(-1);
            } else {
                let exec_output = Command::new(&bin_path)
                    .current_dir(&dir_path)
                    .output()
                    .map_err(|e| format!("Failed to run compiled binary: {}", e))?;

                stdout = String::from_utf8_lossy(&exec_output.stdout).to_string();
                stderr = String::from_utf8_lossy(&exec_output.stderr).to_string();
                exit_code = exec_output.status.code().unwrap_or(-1);
            }
        }
        "c" => {
            let file_path = dir_path.join("temp.c");
            let bin_path = dir_path.join("temp");
            fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;

            let compile_output = Command::new("gcc")
                .arg(&file_path)
                .arg("-o")
                .arg(&bin_path)
                .current_dir(&dir_path)
                .output()
                .map_err(|e| format!("Failed to execute gcc: {}", e))?;

            if !compile_output.status.success() {
                stderr = String::from_utf8_lossy(&compile_output.stderr).to_string();
                exit_code = compile_output.status.code().unwrap_or(-1);
            } else {
                let exec_output = Command::new(&bin_path)
                    .current_dir(&dir_path)
                    .output()
                    .map_err(|e| format!("Failed to run compiled C binary: {}", e))?;

                stdout = String::from_utf8_lossy(&exec_output.stdout).to_string();
                stderr = String::from_utf8_lossy(&exec_output.stderr).to_string();
                exit_code = exec_output.status.code().unwrap_or(-1);
            }
        }
        "java" => {
            let file_path = dir_path.join("Temp.java");
            fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;

            let compile_output = Command::new("javac")
                .arg(&file_path)
                .current_dir(&dir_path)
                .output()
                .map_err(|e| format!("Failed to execute javac: {}", e))?;

            if !compile_output.status.success() {
                stderr = String::from_utf8_lossy(&compile_output.stderr).to_string();
                exit_code = compile_output.status.code().unwrap_or(-1);
            } else {
                let exec_output = Command::new("java")
                    .arg("Temp")
                    .current_dir(&dir_path)
                    .output()
                    .map_err(|e| format!("Failed to execute java runtime: {}", e))?;

                stdout = String::from_utf8_lossy(&exec_output.stdout).to_string();
                stderr = String::from_utf8_lossy(&exec_output.stderr).to_string();
                exit_code = exec_output.status.code().unwrap_or(-1);
            }
        }
        "swift" => {
            let file_path = dir_path.join("temp.swift");
            let bin_path = dir_path.join("temp");
            fs::write(&file_path, &source_code).map_err(|e| e.to_string())?;

            let compile_output = Command::new("swiftc")
                .arg(&file_path)
                .arg("-o")
                .arg(&bin_path)
                .current_dir(&dir_path)
                .output()
                .map_err(|e| format!("Failed to execute swiftc: {}", e))?;

            if !compile_output.status.success() {
                stderr = String::from_utf8_lossy(&compile_output.stderr).to_string();
                exit_code = compile_output.status.code().unwrap_or(-1);
            } else {
                let exec_output = Command::new(&bin_path)
                    .current_dir(&dir_path)
                    .output()
                    .map_err(|e| format!("Failed to run compiled Swift binary: {}", e))?;

                stdout = String::from_utf8_lossy(&exec_output.stdout).to_string();
                stderr = String::from_utf8_lossy(&exec_output.stderr).to_string();
                exit_code = exec_output.status.code().unwrap_or(-1);
            }
        }
        _ => {
            return Err(format!("Unsupported language execution target: {}", language));
        }
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;

    Ok(ExecutionResult {
        stdout,
        stderr,
        exit_code,
        duration_ms,
    })
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![execute_code])
        .run(tauri::generate_context!())
        .expect("error while running Crux Tauri application");
}
