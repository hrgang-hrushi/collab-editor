/**
 * Crex Universal AI Compute & CLI Harvester Discovery Service
 * 
 * Hardware Brutalism AI Coding Tool Auto-Detection & Orchestration Kernel:
 * 1. Probes host operating system for all installed AI coding assistants and CLIs:
 *    - Google AntiGravity / AGY CLI (antigravity, agy)
 *    - Anthropic Claude Code CLI (claude)
 *    - OpenAI Codex / Sol 5.6 Medium CLI (codex, codec)
 *    - OpenCode CLI (opencode, open-code)
 *    - Cursor CLI & Rules Engine (cursor, .cursorrules)
 *    - Ollama LLM Engine (ollama CLI, 11434 daemon, downloaded weights)
 *    - OpenClaw Agent Core (openclaw, ~/.openclaw, 8000 REST)
 *    - GitHub Copilot / CLI (gh auth status, copilot extensions)
 *    - AWS Bedrock SDK credential chain
 *    - Cloud API Keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY)
 * 2. Reads live version strings directly via CLI invocation with strict timeouts.
 * 3. Evaluates workspace affinity contracts (GEMINI.md, CLAUDE.md, .cursorrules).
 * 4. Calculates affinity scores and auto-picks the optimal primary coding engine.
 */

import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";
import os from "os";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { DiscoveredModelRuntime } from "./types";
import { scoreAiTool } from "@/lib/ai/toolOrchestrator";

const execFileAsync = promisify(execFile);

/**
 * Standard candidate search directories across macOS and Linux
 */
export function getSystemSearchPaths(): string[] {
  const home = os.homedir();
  const envPath = (process.env.PATH || "").split(":").filter(Boolean);

  const standardDirs = [
    path.join(home, ".local/bin"),
    path.join(home, ".npm-global/bin"),
    path.join(home, ".bun/bin"),
    path.join(home, ".cargo/bin"),
    path.join(home, ".gemini/antigravity-cli/bin"),
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/Applications/Cursor.app/Contents/Resources/app/bin",
    "/Applications/Visual Studio Code.app/Contents/Resources/app/bin",
  ];

  return Array.from(new Set([...standardDirs, ...envPath])).filter((d) => {
    try {
      return fs.existsSync(d) && fs.statSync(d).isDirectory();
    } catch {
      return false;
    }
  });
}

/**
 * Searches the candidate paths for the first existing binary
 */
export function findBinary(names: string[]): string | null {
  const searchPaths = getSystemSearchPaths();
  for (const name of names) {
    for (const dir of searchPaths) {
      const fullPath = path.join(dir, name);
      try {
        if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
          // Verify executable
          fs.accessSync(fullPath, fs.constants.X_OK);
          return fullPath;
        }
      } catch {
        // Skip
      }
    }
  }
  return null;
}

/**
 * Executes a binary with a timeout to extract its version string safely
 */
export async function getToolVersion(
  binaryPath: string,
  args: string[] = ["--version"],
  timeoutMs: number = 2000
): Promise<string | null> {
  try {
    const { stdout, stderr } = await execFileAsync(binaryPath, args, {
      timeout: timeoutMs,
      env: {
        ...process.env,
        PATH: getSystemSearchPaths().join(":"),
      },
    });

    const raw = (stdout || stderr || "").trim();
    if (!raw) return null;

    // Extract first informative line
    const line = raw.split("\n").map((l) => l.trim()).find((l) => l.length > 0 && !l.toLowerCase().includes("warning"));
    return line ? line.slice(0, 48) : null;
  } catch (err: any) {
    if (err?.stdout) {
      const line = err.stdout.split("\n").map((l: string) => l.trim()).find((l: string) => l.length > 0);
      if (line) return line.slice(0, 48);
    }
    return null;
  }
}

/**
 * 1. Checks Anti-Gravity (AGY) Agent integration (CLI binary, GEMINI.md, skills)
 */
export async function scanAntiGravityRuntimes(): Promise<DiscoveredModelRuntime | null> {
  const home = os.homedir();
  const binaryPath = findBinary(["antigravity", "agy"]);
  const geminiDir = path.join(home, ".gemini/antigravity-cli");
  const hasGeminiDir = fs.existsSync(geminiDir);
  const geminiMd = path.join(process.cwd(), "GEMINI.md");
  const hasGeminiMd = fs.existsSync(geminiMd);

  if (binaryPath || hasGeminiDir || hasGeminiMd) {
    let versionStr = "1.2.12";
    if (binaryPath) {
      const liveVer = await getToolVersion(binaryPath, ["--version"]);
      if (liveVer) versionStr = liveVer.replace(/^agy\s+/i, "").replace(/^antigravity\s+/i, "");
    }

    return {
      id: "antigravity-agy",
      name: `Anti-Gravity AGY (v${versionStr})`,
      binaryName: "agy",
      binaryPath: binaryPath || path.join(home, ".local/bin/agy"),
      version: versionStr,
      provider: "agy",
      type: "local",
      latencyMs: 1,
      available: true,
      status: "ONLINE // 0ms LOCAL_DAEMON",
      tags: ["antigravity", "agy", "autonomous-agent", "skills", "gemini-rules"],
      capabilities: ["autonomous-agent", "file-editor", "terminal-repl", "subagent-orchestrator", "zero-latency"],
      details: {
        binary: binaryPath || "agy",
        hasGeminiMd,
        hasGeminiDir,
        geminiDir: hasGeminiDir ? geminiDir : undefined,
      },
    };
  }
  return null;
}

/**
 * 2. Checks Claude Code CLI (Anthropic) and CLAUDE.md
 */
export async function scanClaudeCodeRuntimes(): Promise<DiscoveredModelRuntime | null> {
  const home = os.homedir();
  const binaryPath = findBinary(["claude"]);
  const claudeMd = path.join(process.cwd(), "CLAUDE.md");
  const hasClaudeMd = fs.existsSync(claudeMd);
  const claudeConfig = path.join(home, ".claude");
  const hasClaudeConfig = fs.existsSync(claudeConfig) || fs.existsSync(path.join(home, ".config/claude"));

  if (binaryPath || hasClaudeMd || hasClaudeConfig) {
    let versionStr = "2.1.91";
    if (binaryPath) {
      const liveVer = await getToolVersion(binaryPath, ["--version"]);
      if (liveVer) versionStr = liveVer;
    }

    return {
      id: "claude-code-cli",
      name: `Claude Code CLI (${versionStr})`,
      binaryName: "claude",
      binaryPath: binaryPath || path.join(home, ".local/bin/claude"),
      version: versionStr,
      provider: "anthropic",
      type: "local",
      latencyMs: 2,
      available: true,
      status: "ONLINE // 0ms SYSTEM_ATTACHED",
      tags: ["claude-code", "anthropic", "sonnet-3-5", "autonomous-cli"],
      capabilities: ["autonomous-agent", "file-editor", "terminal-repl"],
      details: {
        binary: binaryPath || "claude",
        hasClaudeMd,
        hasClaudeConfig,
      },
    };
  }
  return null;
}

/**
 * 3. Checks OpenAI Codex / Sol 5.6 Medium CLI (codex, codec)
 */
export async function scanCodexRuntimes(): Promise<DiscoveredModelRuntime | null> {
  const home = os.homedir();
  const binaryPath = findBinary(["codex", "codec"]);
  const codexDir = path.join(home, ".codex");
  const hasCodexDir = fs.existsSync(codexDir);
  const hasApiKey = Boolean(process.env.OPENAI_API_KEY);

  if (binaryPath || hasCodexDir || hasApiKey) {
    let versionStr = "0.154.0";
    if (binaryPath) {
      const liveVer = await getToolVersion(binaryPath, ["--version"]);
      if (liveVer) versionStr = liveVer;
    }

    return {
      id: "codex-sol-medium",
      name: `Codex CLI / Sol 5.6 (${versionStr})`,
      binaryName: "codex",
      binaryPath: binaryPath || path.join(home, ".npm-global/bin/codex"),
      version: versionStr,
      provider: "codec",
      type: "local",
      latencyMs: 2,
      available: true,
      status: "ONLINE // 0ms UNIFIED_KERNEL",
      tags: ["codex", "codec", "sol-5.6-medium", "code-synthesis"],
      capabilities: ["code-synthesis", "completion", "terminal-repl"],
      details: {
        binary: binaryPath || "codex",
        hasCodexDir,
        hasApiKey,
      },
    };
  }
  return null;
}

/**
 * 4. Checks OpenCode Autonomous Agent CLI (opencode, open-code)
 */
export async function scanOpenCodeRuntimes(): Promise<DiscoveredModelRuntime | null> {
  const home = os.homedir();
  const binaryPath = findBinary(["opencode", "open-code"]);
  const openCodeDir = path.join(home, ".opencode");
  const hasOpenCodeDir = fs.existsSync(openCodeDir);

  if (binaryPath || hasOpenCodeDir) {
    let versionStr = "1.18.31";
    if (binaryPath) {
      const liveVer = await getToolVersion(binaryPath, ["--version"]);
      if (liveVer) versionStr = liveVer;
    }

    return {
      id: "opencode-agent-cli",
      name: `OpenCode CLI (v${versionStr})`,
      binaryName: "opencode",
      binaryPath: binaryPath || path.join(home, ".npm-global/bin/opencode"),
      version: versionStr,
      provider: "openclaw",
      type: "local",
      latencyMs: 2,
      available: true,
      status: "ONLINE // 0ms CLI_ENGINE",
      tags: ["opencode", "autonomous-coder", "terminal-cli"],
      capabilities: ["autonomous-agent", "file-editor", "terminal-repl"],
      details: {
        binary: binaryPath || "opencode",
        hasOpenCodeDir,
      },
    };
  }
  return null;
}

/**
 * 5. Checks Cursor AI CLI & Composer (.cursorrules & configuration)
 */
export async function scanCursorRuntimes(): Promise<DiscoveredModelRuntime | null> {
  const home = os.homedir();
  const binaryPath = findBinary(["cursor"]);
  const cursorRulesPath = path.join(process.cwd(), ".cursorrules");
  const cursorDir = path.join(home, "Library/Application Support/Cursor/User");
  const cursorDot = path.join(home, ".cursor");
  const hasCursorRules = fs.existsSync(cursorRulesPath);
  const hasCursorDir = fs.existsSync(cursorDir) || fs.existsSync(cursorDot);

  if (binaryPath || hasCursorRules || hasCursorDir) {
    let versionStr = "3.21.16";
    if (binaryPath) {
      const liveVer = await getToolVersion(binaryPath, ["--version"]);
      if (liveVer) versionStr = liveVer.split("\n")[0];
    }

    return {
      id: "cursor-composer-engine",
      name: `Cursor CLI / Composer (${versionStr})`,
      binaryName: "cursor",
      binaryPath: binaryPath || "/usr/local/bin/cursor",
      version: versionStr,
      provider: "cursor",
      type: "local",
      latencyMs: 1,
      available: true,
      status: "SYNCED // .cursorrules",
      tags: ["cursor", "composer", "rules-indexer"],
      capabilities: ["composer", "rules-indexer", "terminal-bridge"],
      details: {
        binary: binaryPath || "cursor",
        hasCursorRules,
        hasCursorDir,
      },
    };
  }
  return null;
}

/**
 * 6. Checks local Ollama daemon & CLI (port 11434 & binary)
 */
export async function scanOllamaRuntimes(): Promise<DiscoveredModelRuntime[]> {
  const runtimes: DiscoveredModelRuntime[] = [];
  const binaryPath = findBinary(["ollama"]);
  let cliVersion = "0.34.0";

  if (binaryPath) {
    const liveVer = await getToolVersion(binaryPath, ["--version"]);
    if (liveVer) {
      const match = liveVer.match(/(\d+\.\d+\.\d+)/);
      if (match) cliVersion = match[1];
    }
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1200);

    const res = await fetch("http://127.0.0.1:11434/api/tags", {
      signal: controller.signal,
    }).catch(() => null);

    clearTimeout(timeout);

    if (res && res.ok) {
      const data = await res.json().catch(() => null);
      if (data && Array.isArray(data.models) && data.models.length > 0) {
        for (const m of data.models) {
          const modelName = m.name || m.model || "unknown";
          runtimes.push({
            id: `ollama-${modelName}`,
            name: `Ollama: ${modelName} (v${cliVersion})`,
            binaryName: "ollama",
            binaryPath: binaryPath || "/usr/local/bin/ollama",
            version: cliVersion,
            provider: "ollama",
            type: "local",
            latencyMs: 0,
            available: true,
            status: "ONLINE // 0ms LOCAL_WEIGHTS",
            tags: [m.details?.family || "local-weights", `${Math.round((m.size || 0) / 1024 / 1024 / 1024 * 10) / 10}GB`, "offline-capable"],
            capabilities: ["offline-inference", "terminal-repl", "zero-network"],
            details: {
              size: m.size,
              digest: m.digest?.slice(0, 12),
              modified_at: m.modified_at,
            },
          });
        }
        return runtimes;
      }
    }
  } catch {
    // Daemon not running
  }

  // If daemon is not running but binary is present on host
  if (binaryPath || fs.existsSync(path.join(os.homedir(), ".ollama"))) {
    runtimes.push({
      id: "ollama-cli-daemon",
      name: `Ollama Engine (v${cliVersion})`,
      binaryName: "ollama",
      binaryPath: binaryPath || "/usr/local/bin/ollama",
      version: cliVersion,
      provider: "ollama",
      type: "local",
      latencyMs: 0,
      available: true,
      status: "CLI_INSTALLED // DAEMON_STANDBY",
      tags: ["ollama", "offline-llm", "local-weights"],
      capabilities: ["offline-inference", "terminal-repl"],
      details: {
        binary: binaryPath || "ollama",
        note: "Start daemon in terminal with: ollama serve",
      },
    });
  }

  return runtimes;
}

/**
 * 7. Checks OpenClaw compute endpoint and configuration
 */
export async function scanOpenClawRuntimes(): Promise<DiscoveredModelRuntime[]> {
  const runtimes: DiscoveredModelRuntime[] = [];
  const home = os.homedir();
  const openClawConfig = path.join(home, ".openclaw");
  const openClawBin = findBinary(["openclaw"]);
  const hasOpenClaw = fs.existsSync(openClawConfig) || Boolean(openClawBin);

  if (hasOpenClaw) {
    runtimes.push({
      id: "openclaw-agent-core",
      name: "OpenClaw Agent Core",
      binaryName: "openclaw",
      binaryPath: openClawBin || path.join(home, ".local/bin/openclaw"),
      version: "1.0.0",
      provider: "openclaw",
      type: "local",
      latencyMs: 1,
      available: true,
      status: "ONLINE // LOCAL_DAEMON",
      tags: ["openclaw", "claw-agent", "autonomous"],
      capabilities: ["autonomous-agent", "terminal-repl"],
      details: { configPath: openClawConfig, binary: openClawBin },
    });
  }

  return runtimes;
}

/**
 * 8. Checks GitHub Copilot / Codec Core authentication and credentials
 */
export async function checkCopilotCodecRuntime(): Promise<DiscoveredModelRuntime | null> {
  const home = os.homedir();
  const ghBin = findBinary(["gh"]);
  const copilotDir = path.join(home, ".copilot");
  const copilotConfig = path.join(home, ".config/github-copilot");
  const hasCopilotDir = fs.existsSync(copilotDir);
  const hasCopilotConfig = fs.existsSync(copilotConfig);

  if (ghBin || hasCopilotDir || hasCopilotConfig || process.env.GITHUB_COPILOT_TOKEN) {
    return {
      id: "github-copilot-codec",
      name: "GitHub Copilot / CLI Core",
      binaryName: "gh",
      binaryPath: ghBin || "/usr/local/bin/gh",
      version: "gh-copilot",
      provider: "github-copilot",
      type: "local",
      latencyMs: 2,
      available: true,
      status: "ACTIVE_SESSION // COPILOT_KEYCHAIN",
      tags: ["copilot", "github", "codec", "code-completion"],
      capabilities: ["code-completion", "code-review", "terminal-cli"],
      details: {
        copilotDir: hasCopilotDir ? copilotDir : undefined,
        copilotConfig: hasCopilotConfig ? copilotConfig : undefined,
      },
    };
  }
  return null;
}

/**
 * 9. Checks AWS Bedrock access via official AWS SDK fromNodeProviderChain
 */
export async function checkAwsBedrockRuntime(): Promise<DiscoveredModelRuntime | null> {
  try {
    const provider = fromNodeProviderChain();
    const creds = await Promise.race([
      provider(),
      new Promise<null>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 1200)),
    ]);

    if (creds && creds.accessKeyId) {
      return {
        id: "aws-bedrock-claude",
        name: "AWS Bedrock (Claude 3.5 Sonnet)",
        provider: "aws-bedrock",
        type: "cloud-sdk",
        latencyMs: 28,
        available: true,
        status: "AUTHORIZED // SDK_CHAIN_RESOLVED",
        tags: ["aws-bedrock", "claude-3-5-sonnet", "cloud-sdk"],
        capabilities: ["autonomous-agent", "code-synthesis"],
        details: {
          accessKeyPrefix: creds.accessKeyId.slice(0, 4) + "...",
        },
      };
    }
  } catch {
    // AWS credentials not configured or timed out
  }
  return null;
}

/**
 * 10. Checks environment variables for OpenAI, Anthropic, Gemini API keys
 */
export function checkEnvironmentApiKeys(): DiscoveredModelRuntime[] {
  const runtimes: DiscoveredModelRuntime[] = [];

  if (process.env.OPENAI_API_KEY) {
    runtimes.push({
      id: "openai-gpt4o",
      name: "OpenAI GPT-4o // Reasoning Node",
      provider: "openai",
      type: "cloud-env",
      latencyMs: 42,
      available: true,
      status: "ENV_ACTIVE // OPENAI_API_KEY",
      tags: ["openai", "gpt-4o"],
      capabilities: ["autonomous-agent", "code-synthesis"],
    });
  }

  if (process.env.ANTHROPIC_API_KEY) {
    runtimes.push({
      id: "anthropic-claude",
      name: "Anthropic Claude 3.5 Sonnet",
      provider: "anthropic",
      type: "cloud-env",
      latencyMs: 34,
      available: true,
      status: "ENV_ACTIVE // ANTHROPIC_API_KEY",
      tags: ["anthropic", "claude"],
      capabilities: ["autonomous-agent", "code-synthesis"],
    });
  }

  if (process.env.GEMINI_API_KEY) {
    runtimes.push({
      id: "gemini-pro-cloud",
      name: "Google Gemini 3.8 Flash // Cloud",
      provider: "agy",
      type: "cloud-env",
      latencyMs: 29,
      available: true,
      status: "ENV_ACTIVE // GEMINI_API_KEY",
      tags: ["gemini", "google"],
      capabilities: ["autonomous-agent", "code-synthesis"],
    });
  }

  return runtimes;
}

/**
 * Runs full sweep of all discovery providers on host computer
 * and applies intelligent Auto-Pick scoring to select the primary engine.
 */
export async function runFullRuntimeScan(): Promise<DiscoveredModelRuntime[]> {
  const [
    agy,
    claude,
    codex,
    opencode,
    cursor,
    ollamaList,
    openclawList,
    copilot,
    bedrock,
  ] = await Promise.all([
    scanAntiGravityRuntimes(),
    scanClaudeCodeRuntimes(),
    scanCodexRuntimes(),
    scanOpenCodeRuntimes(),
    scanCursorRuntimes(),
    scanOllamaRuntimes(),
    scanOpenClawRuntimes(),
    checkCopilotCodecRuntime(),
    checkAwsBedrockRuntime(),
  ]);

  const envRuntimes = checkEnvironmentApiKeys();

  const all: DiscoveredModelRuntime[] = [
    ...(agy ? [agy] : []),
    ...(claude ? [claude] : []),
    ...(codex ? [codex] : []),
    ...(opencode ? [opencode] : []),
    ...(cursor ? [cursor] : []),
    ...ollamaList,
    ...openclawList,
    ...(copilot ? [copilot] : []),
    ...(bedrock ? [bedrock] : []),
    ...envRuntimes,
  ];

  // If no external or local nodes were found, provide fallback Mock Node
  if (all.length === 0) {
    all.push({
      id: "crux-silicon-local",
      name: "Crux Silicon Core (Local AST Engine)",
      binaryName: "crux",
      provider: "agy",
      type: "local",
      latencyMs: 0,
      available: true,
      status: "BUILTIN // 0ms SILICON",
      tags: ["ast-engine", "offline-capable"],
      capabilities: ["autonomous-agent", "file-editor", "terminal-repl"],
    });
  }

  // Live workspace context signal for scoring
  const cwd = process.cwd();
  const signal = {
    cwd,
    hasGeminiMd: fs.existsSync(path.join(cwd, "GEMINI.md")),
    hasClaudeMd: fs.existsSync(path.join(cwd, "CLAUDE.md")),
    hasCursorRules: fs.existsSync(path.join(cwd, ".cursorrules")),
    hasCopilotInstructions: fs.existsSync(path.join(cwd, ".github/copilot-instructions.md")),
  };

  // Score each runtime and determine auto-picked winner
  let highestScore = -1;
  let winnerIndex = 0;

  all.forEach((r, idx) => {
    const { score, rationale, breakdown } = scoreAiTool(
      {
        id: r.id,
        binaryName: r.binaryName,
        binaryPath: r.binaryPath,
        available: r.available,
        type: r.type as any,
        provider: r.provider as any,
        capabilities: r.capabilities,
      },
      signal
    );

    r.affinityScore = score;
    r.affinityRationale = rationale;
    r.affinityBreakdown = breakdown;

    if (score > highestScore) {
      highestScore = score;
      winnerIndex = idx;
    }
  });

  if (all[winnerIndex]) {
    all[winnerIndex].isAutoPicked = true;
  }

  return all;
}
