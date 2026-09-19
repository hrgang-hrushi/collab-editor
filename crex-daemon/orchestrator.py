#!/usr/bin/env python3
"""
Crex Local Hardware Orchestration & Automation Daemon
Discovers local compute endpoints (Ollama, OpenClaw) and parses IDE workspace configs.
"""

import os
import sys
import json
import socket
import subprocess
from pathlib import Path
from typing import Dict, List, Any

TARGET_PORTS = {
    "ollama": (11434, "http://127.0.0.1:11434/api/tags"),
    "lmstudio": (1234, "http://127.0.0.1:1234/v1/models"),
    "openclaw": (8080, "http://127.0.0.1:8080/v1/models"),
    "vllm": (8000, "http://127.0.0.1:8000/v1/models"),
}

def check_port(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.06)
            return s.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        return False

def discover_endpoints() -> List[Dict[str, Any]]:
    results = []
    for name, (port, endpoint) in TARGET_PORTS.items():
        is_active = check_port(port)
        results.append({
            "name": name,
            "port": port,
            "active": is_active,
            "endpoint": endpoint
        })
    return results

def get_macos_hardware() -> Dict[str, Any]:
    chip = "Unknown"
    mem_bytes = 0
    try:
        res = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            chip = res.stdout.strip()
        mem_res = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True)
        if mem_res.returncode == 0:
            mem_bytes = int(mem_res.stdout.strip())
    except Exception:
        pass

    return {
        "platform": sys.platform,
        "chip": chip,
        "memory_gb": round(mem_bytes / (1024 ** 3), 1) if mem_bytes else None,
        "cores": os.cpu_count() or 1
    }

def parse_workspace_configs(root: Path) -> Dict[str, Any]:
    tasks = []

    # Parse .vscode/tasks.json
    vscode_tasks = root / ".vscode" / "tasks.json"
    if vscode_tasks.exists():
        try:
            with open(vscode_tasks, "r", encoding="utf-8") as f:
                data = json.load(f)
                for t in data.get("tasks", []):
                    tasks.append({
                        "source": ".vscode",
                        "label": t.get("label", "unnamed"),
                        "command": t.get("command", ""),
                        "type": t.get("type", "shell")
                    })
        except Exception:
            pass

    # Parse .idea directory
    idea_dir = root / ".idea"
    idea_configs = []
    if idea_dir.exists():
        for run_cfg in idea_dir.glob("runConfigurations/*.xml"):
            idea_configs.append({
                "source": ".idea",
                "label": run_cfg.stem,
                "path": str(run_cfg.relative_to(root))
            })

    return {
        "tasks": tasks,
        "idea_configurations": idea_configs
    }

def main():
    root = Path.cwd()
    report = {
        "daemon": "crex-hardware-orchestrator",
        "version": "1.0.0",
        "hardware": get_macos_hardware(),
        "local_services": discover_endpoints(),
        "workspace": parse_workspace_configs(root)
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
