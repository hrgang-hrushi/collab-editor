export interface DetectedIde {
  id: string; // "vscode" | "cursor" | "windsurf"
  name: string; // "Visual Studio Code" | "Cursor" | "Windsurf"
  config_path: string;
  has_settings: boolean;
  has_keybindings: boolean;
  has_snippets: boolean;
  has_cursorrules: boolean;
  settings_json?: Record<string, any> | null;
  keybindings_json?: any[] | null;
  cursorrules?: string | null;
  active_theme?: string | null;
}

export interface ExtensionSummary {
  id: string;
  name: string;
  version: string;
  themes: string[];
  has_grammars: boolean;
}

export interface DiscoveredAgentSkill {
  name: string;
  path: string;
  description?: string;
}

export interface IdeScanManifest {
  timestamp: number;
  permission_granted?: boolean;
  ides: DetectedIde[];
  extensions: ExtensionSummary[];
  rules_files: string[];
  custom_skills: DiscoveredAgentSkill[];
  total_settings_count: number;
  total_keybindings_count: number;
}

export interface MigrationStepStatus {
  step: 1 | 2 | 3 | 4;
  label: string;
  detail: string;
  isComplete: boolean;
  isCurrent: boolean;
}

export interface MigrationSummary {
  ideName: string;
  settingsCount: number;
  keybindingsCount: number;
  themeName: string;
  rulesCount: number;
  timestamp: number;
}
