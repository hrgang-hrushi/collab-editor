/**
 * Crex Universal Workspace Configuration Importer
 * 
 * Ingests legacy IDE project configurations:
 * 1. JetBrains (.idea/):
 *    - Parses misc.xml for project SDK (JDK / Python virtual environments).
 *    - Parses workspace.xml (RunManager) for run/debug configurations.
 * 2. VS Code (.vscode/):
 *    - Parses .vscode/launch.json and .vscode/tasks.json.
 *    - Converts configurations into unified CrexRunProfile instances.
 * 3. Normalizes all discovered configs into CrexRunProfile contract.
 */

import fs from "fs/promises";
import path from "path";
import { XMLParser } from "fast-xml-parser";
import { CrexRunProfile } from "./types";

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
});

/**
 * Strips JSON comments (// and /* *\/) for relaxed VS Code JSON parsing
 */
function cleanJsonComments(raw: string): string {
  return raw
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n\r]*/g, "")
    .trim();
}

/**
 * Checks if a file exists safely
 */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Parses VS Code .vscode/launch.json and .vscode/tasks.json
 */
export async function importVsCodeConfigurations(workspaceRoot: string): Promise<CrexRunProfile[]> {
  const profiles: CrexRunProfile[] = [];
  const vscodeDir = path.join(workspaceRoot, ".vscode");

  // 1. Parse launch.json
  const launchFile = path.join(vscodeDir, "launch.json");
  if (await fileExists(launchFile)) {
    try {
      const raw = await fs.readFile(launchFile, "utf-8");
      const cleaned = cleanJsonComments(raw);
      const parsed = JSON.parse(cleaned);

      if (parsed && Array.isArray(parsed.configurations)) {
        for (let idx = 0; idx < parsed.configurations.length; idx++) {
          const cfg = parsed.configurations[idx];
          const name = cfg.name || `VSCode Launch ${idx + 1}`;
          let command = "node";
          let args: string[] = [];

          if (cfg.type === "node" || cfg.type === "pwa-node") {
            command = cfg.runtimeExecutable || "node";
            if (cfg.program) {
              args.push(cfg.program.replace("${workspaceFolder}/", ""));
            }
          } else if (cfg.type === "python") {
            command = cfg.pythonPath || "python3";
            if (cfg.program) {
              args.push(cfg.program.replace("${workspaceFolder}/", ""));
            }
          } else if (cfg.type === "chrome") {
            command = "open";
            args = [cfg.url || "http://localhost:3000"];
          } else {
            command = cfg.program || cfg.type || "npm run start";
          }

          if (Array.isArray(cfg.args)) {
            args.push(...cfg.args);
          }

          profiles.push({
            id: `vscode-launch-${idx}-${name.toLowerCase().replace(/\s+/g, "-")}`,
            source: "vscode",
            name: `[VSCode] ${name}`,
            command,
            args,
            cwd: cfg.cwd ? cfg.cwd.replace("${workspaceFolder}", ".") : undefined,
            env: cfg.env || undefined,
            entryPoint: cfg.program || undefined,
          });
        }
      }
    } catch {
      // Ignored: Malformed or unreadable launch.json
    }
  }

  // 2. Parse tasks.json
  const tasksFile = path.join(vscodeDir, "tasks.json");
  if (await fileExists(tasksFile)) {
    try {
      const raw = await fs.readFile(tasksFile, "utf-8");
      const cleaned = cleanJsonComments(raw);
      const parsed = JSON.parse(cleaned);

      if (parsed && Array.isArray(parsed.tasks)) {
        for (let idx = 0; idx < parsed.tasks.length; idx++) {
          const t = parsed.tasks[idx];
          const label = t.label || `Task ${idx + 1}`;
          const command = t.command || "npm run build";
          const args = Array.isArray(t.args) ? t.args : [];

          profiles.push({
            id: `vscode-task-${idx}-${label.toLowerCase().replace(/\s+/g, "-")}`,
            source: "vscode",
            name: `[VSCode Task] ${label}`,
            command,
            args,
            cwd: t.options?.cwd ? t.options.cwd.replace("${workspaceFolder}", ".") : undefined,
            env: t.options?.env || undefined,
          });
        }
      }
    } catch {
      // Ignored: Malformed tasks.json
    }
  }

  return profiles;
}

/**
 * Parses JetBrains .idea/ directory (misc.xml & workspace.xml)
 */
export async function importJetBrainsConfigurations(workspaceRoot: string): Promise<{
  profiles: CrexRunProfile[];
  detectedSdk?: { type: string; version?: string; path?: string };
}> {
  const profiles: CrexRunProfile[] = [];
  let detectedSdk: { type: string; version?: string; path?: string } | undefined = undefined;

  const ideaDir = path.join(workspaceRoot, ".idea");
  if (!(await fileExists(ideaDir))) {
    return { profiles, detectedSdk };
  }

  // 1. Parse misc.xml for ProjectRootManager / SDK
  const miscFile = path.join(ideaDir, "misc.xml");
  if (await fileExists(miscFile)) {
    try {
      const raw = await fs.readFile(miscFile, "utf-8");
      const xml = xmlParser.parse(raw);

      const project = xml?.project;
      if (project) {
        const components = Array.isArray(project.component)
          ? project.component
          : [project.component];

        for (const comp of components) {
          if (comp && comp["@_name"] === "ProjectRootManager") {
            const projectJdkName = comp["@_project-jdk-name"];
            const projectJdkType = comp["@_project-jdk-type"];
            if (projectJdkName || projectJdkType) {
              detectedSdk = {
                type: projectJdkType || "JDK/Python",
                version: projectJdkName,
              };
            }
          }
        }
      }
    } catch {
      // Ignore parse failure
    }
  }

  // 2. Parse workspace.xml for RunManager configurations
  const workspaceXmlFile = path.join(ideaDir, "workspace.xml");
  if (await fileExists(workspaceXmlFile)) {
    try {
      const raw = await fs.readFile(workspaceXmlFile, "utf-8");
      const xml = xmlParser.parse(raw);

      const project = xml?.project;
      if (project) {
        const components = Array.isArray(project.component)
          ? project.component
          : [project.component];

        for (const comp of components) {
          if (comp && comp["@_name"] === "RunManager") {
            const configs = Array.isArray(comp.configuration)
              ? comp.configuration
              : comp.configuration
              ? [comp.configuration]
              : [];

            for (let idx = 0; idx < configs.length; idx++) {
              const cfg = configs[idx];
              const cfgName = cfg["@_name"] || `Configuration ${idx + 1}`;
              const cfgType = cfg["@_type"] || "Application";
              const isDefault = cfg["@_default"] === "true";

              let command = "node";
              let args: string[] = [];
              let entryPoint: string | undefined = undefined;
              let envVars: Record<string, string> = {};

              // Extract option tags
              const options = Array.isArray(cfg.option) ? cfg.option : cfg.option ? [cfg.option] : [];
              for (const opt of options) {
                const optName = opt["@_name"];
                const optVal = opt["@_value"];
                if (optName === "SCRIPT_NAME" || optName === "MAIN_CLASS_NAME" || optName === "filePath") {
                  entryPoint = optVal;
                }
                if (optName === "PARAMETERS") {
                  args = optVal ? optVal.split(" ") : [];
                }
                if (optName === "SDK_HOME") {
                  if (!detectedSdk) detectedSdk = { type: "Python", path: optVal };
                }
              }

              if (cfgType.toLowerCase().includes("python")) {
                command = "python3";
                if (entryPoint) args.unshift(entryPoint);
              } else if (cfgType.toLowerCase().includes("node") || cfgType.toLowerCase().includes("js")) {
                command = "node";
                if (entryPoint) args.unshift(entryPoint);
              } else if (cfgType.toLowerCase().includes("npm")) {
                command = "npm run dev";
              } else {
                command = entryPoint || "bash";
              }

              profiles.push({
                id: `jetbrains-run-${idx}-${cfgName.toLowerCase().replace(/\s+/g, "-")}`,
                source: "jetbrains",
                name: `[JetBrains] ${cfgName}`,
                command,
                args,
                entryPoint,
                isDefault,
                env: Object.keys(envVars).length > 0 ? envVars : undefined,
                sdk: detectedSdk?.version || detectedSdk?.type,
              });
            }
          }
        }
      }
    } catch {
      // Ignore parse failure
    }
  }

  return { profiles, detectedSdk };
}

/**
 * Combined importer that scans workspace root for all legacy IDE configs
 */
export async function importAllWorkspaceConfigurations(workspaceRoot: string = process.cwd()): Promise<{
  profiles: CrexRunProfile[];
  detectedSdk?: { type: string; version?: string; path?: string };
}> {
  const [vscodeProfiles, jetbrainsData] = await Promise.all([
    importVsCodeConfigurations(workspaceRoot),
    importJetBrainsConfigurations(workspaceRoot),
  ]);

  const allProfiles = [...vscodeProfiles, ...jetbrainsData.profiles];

  // If no external configs detected, provide native Crex default run profile
  if (allProfiles.length === 0) {
    allProfiles.push({
      id: "crex-native-dev",
      source: "native",
      name: "[Crex] Native Mesh Dev Server",
      command: "npm",
      args: ["run", "dev"],
      cwd: ".",
      isDefault: true,
    });
    allProfiles.push({
      id: "crex-native-build",
      source: "native",
      name: "[Crex] Incremental AST Build",
      command: "npm",
      args: ["run", "build"],
      cwd: ".",
    });
  }

  return {
    profiles: allProfiles,
    detectedSdk: jetbrainsData.detectedSdk,
  };
}
