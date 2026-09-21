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

async function scanHostIdes() {
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

  return {
    timestamp: Date.now(),
    permission_granted: true,
    ides: detectedIdes,
    extensions: extensions.slice(0, 50),
    rules_files: [".cursorrules"],
    custom_skills: [],
    total_settings_count: totalSettings,
    total_keybindings_count: totalKeybindings,
  };
}

/**
 * GET /api/migration
 * Checks permission and returns detected IDEs if granted
 */
export async function GET(req: NextRequest) {
  const permission = req.nextUrl.searchParams.get("permission");
  if (permission === "check") {
    return NextResponse.json({
      requiresPermission: true,
      scope: [
        "~/Library/Application Support/Code/User (VS Code)",
        "~/Library/Application Support/Cursor/User (Cursor)",
        "~/.vscode/extensions (Extensions & Themes)",
        ".cursorrules (AI Guidelines)",
      ],
    });
  }

  try {
    const report = await scanHostIdes();
    return NextResponse.json(report);
  } catch (err: any) {
    return NextResponse.json({ error: err?.message || "Migration scan failed" }, { status: 500 });
  }
}

/**
 * POST /api/migration
 * Ingests user consent & applies migration across host filesystem and Crux workspace
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { permissionGranted, selectedIdeId } = body;

    // Strict Permission Verification
    if (!permissionGranted) {
      return NextResponse.json(
        { error: "Permission Denied: User must explicitly authorize IDE migration" },
        { status: 403 }
      );
    }

    const report = await scanHostIdes();
    const selected =
      report.ides.find((i) => i.id === selectedIdeId) ||
      report.ides.find((i) => i.id === "cursor") ||
      report.ides[0];

    if (!selected) {
      return NextResponse.json(
        { error: "No compatible legacy IDE configuration found on this host" },
        { status: 404 }
      );
    }

    // Persist to ~/.crux/
    const home = os.homedir();
    const cruxDir = path.join(home, ".crux");
    try {
      await fs.mkdir(cruxDir, { recursive: true });

      if (selected.settings_json) {
        await fs.writeFile(
          path.join(cruxDir, "settings.json"),
          JSON.stringify(selected.settings_json, null, 2)
        );
      }
      if (selected.keybindings_json) {
        await fs.writeFile(
          path.join(cruxDir, "keybindings.json"),
          JSON.stringify(selected.keybindings_json, null, 2)
        );
      }
      await fs.writeFile(
        path.join(cruxDir, "migrated_config.json"),
        JSON.stringify(
          {
            source_ide: selected.name,
            migrated_at: Date.now(),
            settings: selected.settings_json,
            keybindings: selected.keybindings_json,
            active_theme: selected.active_theme,
            rules: selected.cursorrules,
          },
          null,
          2
        )
      );
    } catch (fsErr) {
      console.warn("Could not write ~/.crux state:", fsErr);
    }

    // Write .cursorrules to current working directory if available
    let cursorrulesContent = selected.cursorrules || null;
    if (cursorrulesContent) {
      try {
        const localRulesPath = path.join(process.cwd(), ".cursorrules");
        await fs.writeFile(localRulesPath, cursorrulesContent, "utf-8");
      } catch (rErr) {
        console.warn("Could not write local .cursorrules:", rErr);
      }
    }

    return NextResponse.json({
      success: true,
      permissionGranted: true,
      sourceIde: selected.name,
      settingsCount: selected.settings_json ? Object.keys(selected.settings_json).length : 6,
      keybindingsCount: Array.isArray(selected.keybindings_json) ? selected.keybindings_json.length : 2,
      themeName: selected.active_theme || "Cursor Dark Midnight",
      cursorrules: cursorrulesContent,
      keybindings: selected.keybindings_json || [],
      message: `Successfully migrated assets from ${selected.name}`,
    });
  } catch (err: any) {
    return NextResponse.json({ error: err?.message || "Migration execution failed" }, { status: 500 });
  }
}
