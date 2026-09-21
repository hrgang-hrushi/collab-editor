import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";
import os from "os";

export const dynamic = "force-dynamic";

function cleanJsonComments(input: string): string {
  return input
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n\r]*/g, "")
    .trim();
}

async function readRelaxedJson(filePath: string): Promise<any | null> {
  try {
    const raw = await fs.readFile(filePath, "utf-8");
    const cleaned = cleanJsonComments(raw);
    return JSON.parse(cleaned);
  } catch {
    return null;
  }
}

export async function GET(_req: NextRequest) {
  try {
    const home = os.homedir();
    const candidatePaths = [
      { id: "vscode", name: "Visual Studio Code", configDir: path.join(home, "Library/Application Support/Code/User") },
      { id: "cursor", name: "Cursor", configDir: path.join(home, "Library/Application Support/Cursor/User") },
      { id: "windsurf", name: "Windsurf", configDir: path.join(home, "Library/Application Support/Windsurf/User") },
      { id: "vscode-linux", name: "Visual Studio Code", configDir: path.join(home, ".config/Code/User") },
      { id: "cursor-linux", name: "Cursor", configDir: path.join(home, ".config/Cursor/User") },
    ];

    const detectedIdes: any[] = [];
    let totalSettings = 0;
    let totalKeybindings = 0;

    for (const candidate of candidatePaths) {
      try {
        const stats = await fs.stat(candidate.configDir);
        if (!stats.isDirectory()) continue;

        const baseId = candidate.id.replace("-linux", "");
        if (detectedIdes.some((d) => d.id === baseId)) continue;

        const settingsPath = path.join(candidate.configDir, "settings.json");
        const keybindingsPath = path.join(candidate.configDir, "keybindings.json");
        const snippetsDir = path.join(candidate.configDir, "snippets");

        const settingsJson = await readRelaxedJson(settingsPath);
        const keybindingsJson = await readRelaxedJson(keybindingsPath);

        let hasSnippets = false;
        try {
          const s = await fs.stat(snippetsDir);
          hasSnippets = s.isDirectory();
        } catch {
          // ignore
        }

        if (settingsJson && typeof settingsJson === "object") {
          totalSettings += Object.keys(settingsJson).length;
        }
        if (Array.isArray(keybindingsJson)) {
          totalKeybindings += keybindingsJson.length;
        }

        const activeTheme = settingsJson?.["workbench.colorTheme"] || null;

        // Check for .cursorrules
        let cursorrules: string | null = null;
        try {
          cursorrules = await fs.readFile(path.join(process.cwd(), ".cursorrules"), "utf-8");
        } catch {
          try {
            cursorrules = await fs.readFile(path.join(home, ".cursorrules"), "utf-8");
          } catch {
            // ignore
          }
        }

        detectedIdes.push({
          id: baseId,
          name: candidate.name,
          config_path: candidate.configDir,
          has_settings: !!settingsJson,
          has_keybindings: !!keybindingsJson,
          has_snippets: hasSnippets,
          has_cursorrules: !!cursorrules,
          settings_json: settingsJson,
          keybindings_json: keybindingsJson,
          cursorrules,
          active_theme: activeTheme,
        });
      } catch {
        // config dir does not exist
      }
    }

    // Extensions summary
    const extensions: any[] = [];
    const extDirs = [path.join(home, ".vscode/extensions"), path.join(home, ".cursor/extensions")];
    for (const extDir of extDirs) {
      try {
        const entries = await fs.readdir(extDir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            const pkgPath = path.join(extDir, entry.name, "package.json");
            try {
              const pkgRaw = await fs.readFile(pkgPath, "utf-8");
              const pkg = JSON.parse(pkgRaw);
              const themes: string[] = [];
              if (pkg.contributes?.themes && Array.isArray(pkg.contributes.themes)) {
                for (const t of pkg.contributes.themes) {
                  if (t.label) themes.push(t.label);
                }
              }
              const hasGrammars = !!(pkg.contributes?.grammars && Array.isArray(pkg.contributes.grammars));
              extensions.push({
                id: pkg.name || entry.name,
                name: pkg.displayName || pkg.name || entry.name,
                version: pkg.version || "1.0.0",
                themes,
                has_grammars: hasGrammars,
              });
            } catch {
              // ignore
            }
          }
        }
      } catch {
        // ignore
      }
    }

    return NextResponse.json({
      timestamp: Date.now(),
      ides: detectedIdes,
      extensions: extensions.slice(0, 50),
      rules_files: [".cursorrules"],
      custom_skills: [],
      total_settings_count: totalSettings,
      total_keybindings_count: totalKeybindings,
    });
  } catch (err: any) {
    return NextResponse.json({ error: err?.message || "Migration scan failed" }, { status: 500 });
  }
}
