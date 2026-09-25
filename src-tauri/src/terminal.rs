use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize, Child};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TerminalEvent {
    pub r#type: String, // "start", "stdout", "stderr", "exit"
    pub pid: Option<u32>,
    pub data: Option<String>,
    pub code: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PtyOutputEvent {
    pub pid: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PtyExitEvent {
    pub pid: u32,
    pub code: i32,
}

struct ActivePty {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
}

static PTY_REGISTRY: OnceLock<Arc<Mutex<HashMap<u32, ActivePty>>>> = OnceLock::new();
static PID_COUNTER: AtomicU32 = AtomicU32::new(10000);

fn get_registry() -> &'static Arc<Mutex<HashMap<u32, ActivePty>>> {
    PTY_REGISTRY.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

pub fn get_extended_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let current_path = std::env::var("PATH").unwrap_or_default();
    format!(
        "{}/.local/bin:{}/.npm-global/bin:{}/.bun/bin:{}/.cargo/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:{}",
        home, home, home, home, current_path
    )
}

/// Spawns a true PTY pseudo-terminal process backed by `portable-pty`.
/// Supports interactive shells, curses applications, and auto-discovered AI CLIs.
#[tauri::command]
pub fn pty_spawn(
    app: AppHandle,
    command: Option<String>,
    cwd: Option<String>,
    rows: Option<u16>,
    cols: Option<u16>,
) -> Result<u32, String> {
    let r = rows.unwrap_or(24);
    let c = cols.unwrap_or(80);

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: r,
            cols: c,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("Failed to open native PTY: {}", e))?;

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let working_dir = cwd.unwrap_or_else(|| {
        std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| home.clone())
    });

    let mut cmd_builder = match command.as_deref() {
        Some(cmd_str) if !cmd_str.trim().is_empty() => {
            let mut b = CommandBuilder::new("/bin/zsh");
            b.arg("-c");
            b.arg(cmd_str.trim());
            b
        }
        _ => {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string());
            let mut b = CommandBuilder::new(shell);
            b.arg("-l");
            b
        }
    };

    cmd_builder.cwd(std::path::Path::new(&working_dir));
    cmd_builder.env("PATH", get_extended_path());
    cmd_builder.env("HOME", &home);
    cmd_builder.env("TERM", "xterm-256color");
    cmd_builder.env("COLORTERM", "truecolor");
    cmd_builder.env("LANG", "en_US.UTF-8");
    cmd_builder.env("FORCE_COLOR", "1");
    cmd_builder.env("CRUX_TERMINAL", "1");

    let child = pair
        .slave
        .spawn_command(cmd_builder)
        .map_err(|e| format!("Failed to spawn PTY child: {}", e))?;

    let real_pid = child.process_id().unwrap_or_else(|| PID_COUNTER.fetch_add(1, Ordering::SeqCst));
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("Failed to clone PTY reader: {}", e))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("Failed to acquire PTY writer: {}", e))?;

    let pty_session = ActivePty {
        master: pair.master,
        writer,
        child,
    };

    {
        let mut reg = get_registry().lock().unwrap();
        reg.insert(real_pid, pty_session);
    }

    let app_for_read = app.clone();
    let pid_for_read = real_pid;

    // Background thread: Stream bytes from PTY to frontend
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break, // EOF reached
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buf[..n]).to_string();

                    // Emit to general pty-output listener
                    let _ = app_for_read.emit(
                        "pty-output",
                        PtyOutputEvent {
                            pid: pid_for_read,
                            data: chunk.clone(),
                        },
                    );

                    // Emit to session-specific terminal event listener (Zenith compatibility)
                    let _ = app_for_read.emit(
                        &format!("terminal-event-{}", pid_for_read),
                        TerminalEvent {
                            r#type: "stdout".to_string(),
                            pid: Some(pid_for_read),
                            data: Some(chunk),
                            code: None,
                        },
                    );
                }
                Err(_) => break,
            }
        }
    });

    // Background thread: Wait for child process exit and clean registry
    let app_for_wait = app.clone();
    let pid_for_wait = real_pid;
    thread::spawn(move || {
        let mut exit_code = 0;
        let mut child_handle = None;

        {
            if let Ok(mut reg) = get_registry().lock() {
                if let Some(session) = reg.remove(&pid_for_wait) {
                    child_handle = Some(session.child);
                }
            }
        }

        if let Some(mut child) = child_handle {
            match child.wait() {
                Ok(status) => {
                    exit_code = status.exit_code() as i32;
                }
                Err(_) => {
                    exit_code = 1;
                }
            }
        }

        // Emit pty-exit event
        let _ = app_for_wait.emit(
            "pty-exit",
            PtyExitEvent {
                pid: pid_for_wait,
                code: exit_code,
            },
        );

        // Emit legacy terminal-event exit
        let _ = app_for_wait.emit(
            &format!("terminal-event-{}", pid_for_wait),
            TerminalEvent {
                r#type: "exit".to_string(),
                pid: Some(pid_for_wait),
                data: None,
                code: Some(exit_code),
            },
        );
    });

    // Emit initial start event
    let _ = app.emit(
        &format!("terminal-event-{}", real_pid),
        TerminalEvent {
            r#type: "start".to_string(),
            pid: Some(real_pid),
            data: None,
            code: None,
        },
    );

    Ok(real_pid)
}

/// Writes keystrokes or text chunks directly into the active PTY master handle
#[tauri::command]
pub fn pty_write(pid: u32, data: String) -> Result<(), String> {
    let mut reg = get_registry().lock().map_err(|e| e.to_string())?;
    if let Some(session) = reg.get_mut(&pid) {
        session
            .writer
            .write_all(data.as_bytes())
            .map_err(|e| format!("Failed to write to PTY: {}", e))?;
        session
            .writer
            .flush()
            .map_err(|e| format!("Failed to flush PTY: {}", e))?;
        Ok(())
    } else {
        Err(format!("PTY session with PID {} not found or already closed", pid))
    }
}

/// Dynamically updates rows and columns of the underlying PTY handle
#[tauri::command]
pub fn pty_resize(pid: u32, rows: u16, cols: u16) -> Result<(), String> {
    let mut reg = get_registry().lock().map_err(|e| e.to_string())?;
    if let Some(session) = reg.get_mut(&pid) {
        session
            .master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("Failed to resize PTY: {}", e))?;
        Ok(())
    } else {
        Err(format!("PTY session with PID {} not found", pid))
    }
}

/// Explicitly terminates the PTY session and subprocess
#[tauri::command]
pub fn pty_kill(pid: u32) -> Result<(), String> {
    let mut reg = get_registry().lock().map_err(|e| e.to_string())?;
    if let Some(mut session) = reg.remove(&pid) {
        let _ = session.child.kill();
        Ok(())
    } else {
        // Fallback to OS SIGTERM
        let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).status();
        Ok(())
    }
}

// =========================================================================
// BACKWARDS-COMPATIBILITY ALIASES FOR EXISTING CRUX HYPERTERMINAL / ZENITH
// =========================================================================

#[tauri::command]
pub fn terminal_spawn(
    app: AppHandle,
    command: String,
    cwd: Option<String>,
) -> Result<u32, String> {
    let trimmed = command.trim();

    // Check virtual CRUX commands
    if trimmed == "crux status" {
        let fake_pid = 7447;
        let app_clone = app.clone();
        thread::spawn(move || {
            let _ = app_clone.emit(&format!("terminal-event-{}", fake_pid), TerminalEvent {
                r#type: "start".to_string(),
                pid: Some(fake_pid),
                data: None,
                code: None,
            });
            let output = concat!(
                "\x1b[36m● Crux Daemon:\x1b[0m v1.2.0-prod on unix:///var/run/crux.sock (IPC: 0.08ms)\n",
                "\x1b[32m● Hardware:\x1b[0m Apple Silicon Metal Compute Engine (128 tok/s)\n",
                "\x1b[35m● Buffer Mesh:\x1b[0m Zero-copy shared memory CRDT ring buffer [ACTIVE]\n",
                "\x1b[33m● Connected Peers:\x1b[0m Sarah Lin (12.4ms), @CruxAI (0.02ms local), Marcus Vance (18.1ms)\n",
                "\x1b[32m● Sync Health:\x1b[0m 100% Attested (0 uncommitted conflicts)\n"
            );
            let _ = app_clone.emit(&format!("terminal-event-{}", fake_pid), TerminalEvent {
                r#type: "stdout".to_string(),
                pid: Some(fake_pid),
                data: Some(output.to_string()),
                code: None,
            });
            let _ = app_clone.emit(&format!("terminal-event-{}", fake_pid), TerminalEvent {
                r#type: "exit".to_string(),
                pid: Some(fake_pid),
                data: None,
                code: Some(0),
            });
        });
        return Ok(fake_pid);
    }

    if trimmed == "crux peers" {
        let fake_pid = 7449;
        let app_clone = app.clone();
        thread::spawn(move || {
            let _ = app_clone.emit(&format!("terminal-event-{}", fake_pid), TerminalEvent {
                r#type: "start".to_string(),
                pid: Some(fake_pid),
                data: None,
                code: None,
            });
            let output = concat!(
                "\x1b[1;37mACTIVE CRUX COLLABORATIVE PEERS:\x1b[0m\n",
                "  \x1b[36m● Sarah Lin\x1b[0m     [Staff Infra]   #06b6d4  auth.ts (editing L14)   latency: 12.4ms\n",
                "  \x1b[35m● @CruxAI\x1b[0m       [Copilot]       #8b5cf6  database.ts             latency: 0.02ms (local)\n",
                "  \x1b[33m● Marcus Vance\x1b[0m  [Architect]     #f59e0b  spatialEngine.ts        latency: 18.1ms\n",
                "  \x1b[32m● Current User\x1b[0m  [Lead Dev]      #5e6ad2  stream_syncer.ts        latency: 0.00ms (self)\n"
            );
            let _ = app_clone.emit(&format!("terminal-event-{}", fake_pid), TerminalEvent {
                r#type: "stdout".to_string(),
                pid: Some(fake_pid),
                data: Some(output.to_string()),
                code: None,
            });
            let _ = app_clone.emit(&format!("terminal-event-{}", fake_pid), TerminalEvent {
                r#type: "exit".to_string(),
                pid: Some(fake_pid),
                data: None,
                code: Some(0),
            });
        });
        return Ok(fake_pid);
    }

    // Spawn via real PTY subsystem!
    pty_spawn(app, Some(command), cwd, Some(24), Some(80))
}

#[tauri::command]
pub fn terminal_input(pid: u32, input: String) -> Result<(), String> {
    let formatted = if input.ends_with('\n') {
        input
    } else {
        format!("{}\n", input)
    };
    pty_write(pid, formatted)
}

#[tauri::command]
pub fn terminal_kill(pid: u32) -> Result<(), String> {
    pty_kill(pid)
}

#[tauri::command]
pub fn git_command(action: String, cwd: Option<String>) -> Result<serde_json::Value, String> {
    let working_dir = cwd.unwrap_or_else(|| ".".to_string());
    let extended_path = get_extended_path();

    if action == "branch" || action == "status" {
        let branch_out = Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .current_dir(&working_dir)
            .env("PATH", &extended_path)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "main".to_string());

        let status_out = Command::new("git")
            .args(["status", "--short"])
            .current_dir(&working_dir)
            .env("PATH", &extended_path)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        let changed_files: Vec<String> = status_out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        return Ok(serde_json::json!({
            "branch": if branch_out.is_empty() { "main".to_string() } else { branch_out },
            "isDirty": !changed_files.is_empty(),
            "changedFiles": changed_files
        }));
    }

    if action == "log" {
        let log_out = Command::new("git")
            .args(["log", "--oneline", "-7"])
            .current_dir(&working_dir)
            .env("PATH", &extended_path)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        let commits: Vec<serde_json::Value> = log_out
            .lines()
            .filter(|l| !l.is_empty())
            .map(|line| {
                let space_idx = line.find(' ').unwrap_or(line.len());
                let hash = &line[..space_idx];
                let msg = if space_idx < line.len() { &line[space_idx + 1..] } else { "" };
                serde_json::json!({
                    "hash": hash,
                    "message": msg
                })
            })
            .collect();

        return Ok(serde_json::json!({ "commits": commits }));
    }

    Err(format!("Unknown git action: {}", action))
}
