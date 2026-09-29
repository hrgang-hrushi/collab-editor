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

export interface AffinityBreakdown {
  binaryHealth: number;       // max 25
  contractMatch: number;      // max 35
  latencyIpc: number;         // max 20
  agenticCapability: number;  // max 20
  total: number;              // max 100
}

export interface DiscoveredModelRuntime {
  id: string;
  name: string;
  binaryName?: string;
  binaryPath?: string;
  version?: string;
  category?: "ai" | "runtime" | "package_manager" | "vcs" | "tool" | string;
  provider: "ollama" | "openclaw" | "aws-bedrock" | "openai" | "anthropic" | "github-copilot" | "agy" | "codec" | "cursor" | "custom";
  type: "local" | "cloud-sdk" | "cloud-env";
  latencyMs: number;
  available: boolean;
  status: string;
  tags?: string[];
  capabilities?: string[];
  affinityScore?: number;
  affinityRationale?: string;
  affinityBreakdown?: AffinityBreakdown;
  isAutoPicked?: boolean;
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
  orchestration?: {
    selectionMode: "auto" | "pinned";
    activeToolId: string;
    autoPickedId: string;
    autoPickedName: string;
    rationale: string;
    totalDetected: number;
  };
}
