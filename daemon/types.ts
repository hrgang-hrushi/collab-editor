/**
 * Crex Run Profile Normalized Interface
 * 
 * Hardware Brutalism execution contract:
 * Unifies run/debug configs from VS Code (.vscode/), JetBrains (.idea/), and Crex native.
 */
export interface CrexRunProfile {
  id: string;
  source: "jetbrains" | "vscode" | "native";
  name: string;
  command: string;
  args: string[];
  cwd?: string;
  env?: Record<string, string>;
  sdk?: string;
  entryPoint?: string;
  isDefault?: boolean;
}

export interface DiscoveredModelRuntime {
  id: string;
  name: string;
  provider: "ollama" | "openclaw" | "aws-bedrock" | "openai" | "anthropic" | "github-copilot" | "agy" | "codec" | "cursor" | "custom";
  type: "local" | "cloud-sdk" | "cloud-env";
  latencyMs: number;
  available: boolean;
  status: string;
  tags?: string[];
  details?: Record<string, any>;
}

export interface DiscoveryReport {
  timestamp: number;
  runtimes: DiscoveredModelRuntime[];
  profiles: CrexRunProfile[];
  detectedSdk?: {
    type: string;
    version?: string;
    path?: string;
  };
}
