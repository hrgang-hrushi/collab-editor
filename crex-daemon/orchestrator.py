#!/usr/bin/env python3
"""
Crex Local Hardware Orchestration & Agnostic AI Router Daemon
Discovers local compute endpoints, parses workspace configs, and routes
AI prompts across OpenAI, Anthropic (Claude), AGY, OpenCode, and Ollama.
No graphical settings menus: configured strictly via environment variables,
OS keychain sweeps, or terminal-style commands `> route add [provider] [token/endpoint]`.
"""

import os
import sys
import json
import socket
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

TARGET_PORTS = {
    "ollama": (11434, "http://127.0.0.1:11434/api/tags"),
    "lmstudio": (1234, "http://127.0.0.1:1234/v1/models"),
    "openclaw": (8080, "http://127.0.0.1:8080/v1/models"),
    "vllm": (8000, "http://127.0.0.1:8000/v1/models"),
}

DEFAULT_ENDPOINTS = {
    "openai": ("https://api.openai.com/v1/chat/completions", "gpt-4o"),
    "anthropic": ("https://api.anthropic.com/v1/messages", "claude-3-5-sonnet-20241022"),
    "agy": ("https://api.antigravity.ai/v1/completions", "agy-kernel-v1"),
    "opencode": ("https://api.opencode.ai/v1/chat", "opencode-deepseek-33b"),
    "ollama": ("http://127.0.0.1:11434/api/generate", "codellama"),
}

class AgnosticAiRouter:
    def __init__(self):
        self.config_dir = Path.home() / ".crex"
        self.config_file = self.config_dir / "routes.json"
        self.routes: Dict[str, Dict[str, Any]] = {}
        self.active_provider = "ollama"

        self.sweep_environment()
        self.sweep_keychain()
        self.load_persisted()

        if "ollama" not in self.routes:
            self.routes["ollama"] = {
                "provider": "ollama",
                "endpoint": DEFAULT_ENDPOINTS["ollama"][0],
                "model": DEFAULT_ENDPOINTS["ollama"][1],
                "token": None,
                "source": "default",
                "active": True
            }

    def sweep_environment(self):
        # OpenAI
        if os.environ.get("OPENAI_API_KEY"):
            self.routes["openai"] = {
                "provider": "openai",
                "endpoint": os.environ.get("OPENAI_ENDPOINT", DEFAULT_ENDPOINTS["openai"][0]),
                "model": os.environ.get("OPENAI_MODEL", DEFAULT_ENDPOINTS["openai"][1]),
                "token": os.environ.get("OPENAI_API_KEY"),
                "source": "env:OPENAI_API_KEY",
                "active": True
            }
            self.active_provider = "openai"

        # Anthropic
        if os.environ.get("ANTHROPIC_API_KEY"):
            self.routes["anthropic"] = {
                "provider": "anthropic",
                "endpoint": os.environ.get("ANTHROPIC_ENDPOINT", DEFAULT_ENDPOINTS["anthropic"][0]),
                "model": os.environ.get("ANTHROPIC_MODEL", DEFAULT_ENDPOINTS["anthropic"][1]),
                "token": os.environ.get("ANTHROPIC_API_KEY"),
                "source": "env:ANTHROPIC_API_KEY",
                "active": False
            }

        # AGY
        agy_key = os.environ.get("AGY_API_KEY") or os.environ.get("ANTIGRAVITY_API_KEY")
        if agy_key:
            self.routes["agy"] = {
                "provider": "agy",
                "endpoint": os.environ.get("AGY_ENDPOINT", DEFAULT_ENDPOINTS["agy"][0]),
                "model": DEFAULT_ENDPOINTS["agy"][1],
                "token": agy_key,
                "source": "env:AGY_API_KEY",
                "active": False
            }

        # OpenCode
        if os.environ.get("OPENCODE_API_KEY"):
            self.routes["opencode"] = {
                "provider": "opencode",
                "endpoint": os.environ.get("OPENCODE_ENDPOINT", DEFAULT_ENDPOINTS["opencode"][0]),
                "model": DEFAULT_ENDPOINTS["opencode"][1],
                "token": os.environ.get("OPENCODE_API_KEY"),
                "source": "env:OPENCODE_API_KEY",
                "active": False
            }

        # Ollama host
        ollama_host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
        self.routes["ollama"] = {
            "provider": "ollama",
            "endpoint": f"{ollama_host}/api/generate",
            "model": os.environ.get("OLLAMA_MODEL", DEFAULT_ENDPOINTS["ollama"][1]),
            "token": None,
            "source": "env:OLLAMA_HOST",
            "active": False
        }

    def sweep_keychain(self):
        if sys.platform == "darwin":
            for prov in ["openai", "anthropic", "agy", "opencode"]:
                if prov in self.routes and self.routes[prov].get("token"):
                    continue
                try:
                    res = subprocess.run(
                        ["security", "find-generic-password", "-s", f"crex-ai-{prov}", "-w"],
                        capture_output=True, text=True, timeout=1
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        token = res.stdout.strip()
                        def_ep, def_mod = DEFAULT_ENDPOINTS.get(prov, ("", ""))
                        self.routes[prov] = {
                            "provider": prov,
                            "endpoint": def_ep,
                            "model": def_mod,
                            "token": token,
                            "source": "keychain",
                            "active": False
                        }
                except Exception:
                    pass

    def load_persisted(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k, v in data.items():
                        self.routes[k] = {
                            "provider": v.get("provider", k),
                            "endpoint": v.get("endpoint", ""),
                            "model": v.get("model", ""),
                            "token": v.get("auth_token") or v.get("token"),
                            "source": v.get("source", "persisted"),
                            "active": v.get("is_active", False)
                        }
                        if v.get("is_active"):
                            self.active_provider = k
            except Exception:
                pass

    def save_persisted(self):
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            serializable = {}
            for k, v in self.routes.items():
                serializable[k] = {
                    "provider": v["provider"],
                    "endpoint": v["endpoint"],
                    "auth_token": v["token"],
                    "model": v["model"],
                    "is_active": (k == self.active_provider),
                    "source": v["source"]
                }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2)
        except Exception:
            pass

    def handle_command(self, cmd: str) -> str:
        clean = cmd.strip()
        if clean.startswith(">"):
            clean = clean[1:].strip()
        parts = clean.split()
        if not parts or parts[0] != "route":
            return "Usage: > route add [provider] [token/url] | > route list | > route set [provider]"

        subcmd = parts[1] if len(parts) > 1 else "list"

        if subcmd == "list":
            lines = ["ACTIVE AI ROUTES:"]
            for name, r in self.routes.items():
                mark = " [*ACTIVE*]" if name == self.active_provider else ""
                t = r.get("token")
                th = f"{t[:3]}...{t[-3:]}" if t and len(t) > 6 else ("none" if not t else "***")
                lines.append(f"  - {name:<10} -> {r['endpoint']:<35} (model: {r['model']}) [src: {r['source']}] [token: {th}]{mark}")
            return "\n".join(lines)

        if subcmd == "set" and len(parts) >= 3:
            prov = parts[2].lower()
            if prov in self.routes:
                self.active_provider = prov
                self.save_persisted()
                return f"[AiRouter] Active provider switched to: {prov}"
            return f"[AiRouter] Provider '{prov}' not configured. Run '> route add {prov} [token]'"

        if subcmd == "add" and len(parts) >= 3:
            prov = parts[2].lower()
            if prov not in DEFAULT_ENDPOINTS:
                return f"[AiRouter] Unknown provider '{prov}'. Supported: openai, anthropic, agy, opencode, ollama"

            val = parts[3] if len(parts) >= 4 else None
            def_ep, def_mod = DEFAULT_ENDPOINTS[prov]
            endpoint = val if val and val.startswith("http") else def_ep
            token = val if val and not val.startswith("http") else None

            self.routes[prov] = {
                "provider": prov,
                "endpoint": endpoint,
                "model": def_mod,
                "token": token,
                "source": "omnibar",
                "active": True
            }
            self.active_provider = prov
            self.save_persisted()
            return f"[AiRouter] Successfully configured route: {prov} (model: {def_mod})"

        if subcmd == "remove" and len(parts) >= 3:
            prov = parts[2].lower()
            if prov in self.routes:
                del self.routes[prov]
                self.save_persisted()
                return f"[AiRouter] Removed route: {prov}"
            return f"[AiRouter] Route '{prov}' not found."

        return "Unknown route command."

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
    ai_router = AgnosticAiRouter()

    if len(sys.argv) >= 3 and sys.argv[1] == "--route":
        cmd = " ".join(sys.argv[2:])
        print(ai_router.handle_command(cmd))
        return

    root = Path.cwd()
    report = {
        "daemon": "crex-hardware-orchestrator",
        "version": "1.1.0",
        "hardware": get_macos_hardware(),
        "local_services": discover_endpoints(),
        "ai_routes": ai_router.routes,
        "active_ai_provider": ai_router.active_provider,
        "workspace": parse_workspace_configs(root)
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
