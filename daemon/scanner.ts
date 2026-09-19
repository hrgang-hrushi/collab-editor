/**
 * Crex Local & SDK Runtime Discovery Service
 * 
 * Hardware Brutalism AI Compute & Credential Harvester Discovery:
 * 1. Probes local compute runtimes (Ollama @ http://127.0.0.1:11434/api/tags, OpenClaw @ http://127.0.0.1:8000).
 *    Registers active local models as [LOCAL] compute nodes with 0ms external latency.
 * 2. Official SDK resolution:
 *    - AWS Bedrock: fromNodeProviderChain() from @aws-sdk/credential-providers. Resolves without file scraping.
 *    - GitHub CLI: execFile('gh', ['auth', 'status']). Marks GitHub Copilot/Codex integration available if authenticated.
 *    - Environment variables: checks OPENAI_API_KEY, ANTHROPIC_API_KEY.
 */

import { execFile } from "child_process";
import { promisify } from "util";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { DiscoveredModelRuntime } from "./types";

const execFileAsync = promisify(execFile);

/**
 * Checks local Ollama daemon (port 11434)
 */
export async function scanOllamaRuntimes(): Promise<DiscoveredModelRuntime[]> {
  const runtimes: DiscoveredModelRuntime[] = [];
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);

    const res = await fetch("http://127.0.0.1:11434/api/tags", {
      signal: controller.signal,
    }).catch(() => null);

    clearTimeout(timeout);

    if (res && res.ok) {
      const data = await res.json().catch(() => null);
      if (data && Array.isArray(data.models)) {
        for (const m of data.models) {
          const modelName = m.name || m.model || "unknown";
          runtimes.push({
            id: `ollama-${modelName}`,
            name: `Ollama: ${modelName}`,
            provider: "ollama",
            type: "local",
            latencyMs: 0,
            available: true,
            status: "ONLINE // 0ms LOCAL_COMPUTE",
            tags: [m.details?.family || "local-weights", `${Math.round((m.size || 0) / 1024 / 1024 / 1024 * 10) / 10}GB`],
            details: {
              size: m.size,
              digest: m.digest?.slice(0, 12),
              modified_at: m.modified_at,
            },
          });
        }
      }
    }
  } catch {
    // Ollama not active
  }
  return runtimes;
}

/**
 * Checks local OpenClaw compute endpoint
 */
export async function scanOpenClawRuntimes(): Promise<DiscoveredModelRuntime[]> {
  const runtimes: DiscoveredModelRuntime[] = [];
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1200);

    const res = await fetch("http://127.0.0.1:8000/v1/models", {
      signal: controller.signal,
    }).catch(() => null);

    clearTimeout(timeout);

    if (res && res.ok) {
      const data = await res.json().catch(() => null);
      if (data && Array.isArray(data.data)) {
        for (const m of data.data) {
          runtimes.push({
            id: `openclaw-${m.id}`,
            name: `OpenClaw: ${m.id}`,
            provider: "openclaw",
            type: "local",
            latencyMs: 0,
            available: true,
            status: "ONLINE // 0ms LOCAL_REST",
            tags: ["openclaw", "local-weights"],
          });
        }
      }
    }
  } catch {
    // OpenClaw not active
  }
  return runtimes;
}

/**
 * Checks AWS Bedrock access via official AWS SDK fromNodeProviderChain
 */
export async function checkAwsBedrockRuntime(): Promise<DiscoveredModelRuntime | null> {
  try {
    const provider = fromNodeProviderChain();
    // Resolve credentials through official AWS SDK chain
    const creds = await Promise.race([
      provider(),
      new Promise<null>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 1500)),
    ]);

    if (creds && creds.accessKeyId) {
      return {
        id: "aws-bedrock-claude",
        name: "AWS Bedrock (Anthropic Claude 3.5 Sonnet)",
        provider: "aws-bedrock",
        type: "cloud-sdk",
        latencyMs: 28,
        available: true,
        status: "AUTHORIZED // SDK_CHAIN_RESOLVED",
        tags: ["aws-bedrock", "claude-3-5-sonnet", "cloud-sdk"],
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
 * Checks GitHub CLI status via official `gh auth status` command
 */
export async function checkGitHubCliAuth(): Promise<DiscoveredModelRuntime | null> {
  try {
    const { stdout, stderr } = await execFileAsync("gh", ["auth", "status"], {
      timeout: 2000,
      env: { ...process.env, PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin" },
    });

    const output = `${stdout || ""} ${stderr || ""}`;
    if (output.includes("Logged in to") || output.includes("Active account: true") || output.includes("account")) {
      return {
        id: "github-copilot",
        name: "GitHub Copilot / Models (gh CLI)",
        provider: "github-copilot",
        type: "cloud-sdk",
        latencyMs: 34,
        available: true,
        status: "AUTHORIZED // GH_CLI_READY",
        tags: ["github", "copilot", "cli-auth"],
      };
    }
  } catch {
    // gh CLI not installed or not logged in
  }
  return null;
}

/**
 * Checks standard environment variable keys already active in process.env
 */
export function checkEnvironmentApiKeys(): DiscoveredModelRuntime[] {
  const runtimes: DiscoveredModelRuntime[] = [];

  if (process.env.OPENAI_API_KEY) {
    runtimes.push({
      id: "openai-gpt4o",
      name: "OpenAI GPT-4o // Reasoning Node",
      provider: "openai",
      type: "cloud-env",
      latencyMs: 45,
      available: true,
      status: "ENV_ACTIVE // OPENAI_API_KEY",
      tags: ["openai", "gpt-4o"],
    });
  }

  if (process.env.ANTHROPIC_API_KEY) {
    runtimes.push({
      id: "anthropic-claude",
      name: "Anthropic Claude 3.5 Sonnet",
      provider: "anthropic",
      type: "cloud-env",
      latencyMs: 32,
      available: true,
      status: "ENV_ACTIVE // ANTHROPIC_API_KEY",
      tags: ["anthropic", "claude"],
    });
  }

  return runtimes;
}

/**
 * Runs full sweep of all discovery providers
 */
export async function runFullRuntimeScan(): Promise<DiscoveredModelRuntime[]> {
  const [ollama, openclaw, bedrock, ghCli] = await Promise.all([
    scanOllamaRuntimes(),
    scanOpenClawRuntimes(),
    checkAwsBedrockRuntime(),
    checkGitHubCliAuth(),
  ]);

  const envRuntimes = checkEnvironmentApiKeys();

  const all: DiscoveredModelRuntime[] = [
    ...ollama,
    ...openclaw,
    ...(bedrock ? [bedrock] : []),
    ...(ghCli ? [ghCli] : []),
    ...envRuntimes,
  ];

  // If no external or local nodes were found, provide fallback Mock Node to ensure zero-state reliability
  if (all.length === 0) {
    all.push({
      id: "crux-silicon-local",
      name: "Crex Silicon Core (Local AST Engine)",
      provider: "openclaw",
      type: "local",
      latencyMs: 0,
      available: true,
      status: "BUILTIN // 0ms SILICON",
      tags: ["ast-engine", "offline-capable"],
    });
  }

  return all;
}
