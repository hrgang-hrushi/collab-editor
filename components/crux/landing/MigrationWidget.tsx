"use client";

import React, { useState } from "react";
import {
  Sliders,
  ArrowRight,
  Shield,
  Layers,
  Command,
  Palette,
  Bot,
  FileCode,
  Check,
  RefreshCw,
} from "lucide-react";

interface DetectedConfigItem {
  id: string;
  name: string;
  count: string;
  description: string;
  selected: boolean;
}

export default function MigrationWidget() {
  const [activeIde, setActiveIde] = useState<"cursor" | "vscode" | "windsurf">("cursor");
  const [isScanning, setIsScanning] = useState(false);
  const [migrationStatus, setMigrationStatus] = useState<"idle" | "running" | "complete">("idle");
  const [items, setItems] = useState<Record<string, DetectedConfigItem[]>>({
    cursor: [
      {
        id: "keybindings",
        name: "Custom Shortcuts & Keymaps",
        count: "64 keys",
        description: "Muscle memory preserved: Cmd+K, Cmd+P, multi-cursor, and vim bindings",
        selected: true,
      },
      {
        id: "cursorrules",
        name: "System AI Directives (.cursorrules)",
        count: "3 rule files",
        description: "Importing project agent guidelines and contextual system prompts",
        selected: true,
      },
      {
        id: "theme",
        name: "Dark Midnight Color Grammar",
        count: "1 active theme",
        description: "Color tokens converted into hardware-accelerated WebGPU syntax styles",
        selected: true,
      },
      {
        id: "settings",
        name: "Editor Configurations",
        count: "28 preferences",
        description: "Tab sizing, font ligatures, format-on-save, and telemetry opt-outs",
        selected: true,
      },
    ],
    vscode: [
      {
        id: "keybindings",
        name: "VS Code Keybinding Bindings",
        count: "82 keys",
        description: "All custom command palette bindings and keyboard leader keys",
        selected: true,
      },
      {
        id: "extensions",
        name: "LSP & Extension Manifests",
        count: "18 extensions",
        description: "Rust Analyzer, Python, Tailwind CSS Intellisense, and Prettier",
        selected: true,
      },
      {
        id: "settings",
        name: "Global User Settings",
        count: "41 settings",
        description: "Ruler columns, cursor blinking cadence, and bracket pairing",
        selected: true,
      },
    ],
    windsurf: [
      {
        id: "cascade",
        name: "Cascade Agent Rules & History",
        count: "2 flows",
        description: "Autonomous cascade workflow definitions and workspace context",
        selected: true,
      },
      {
        id: "keybindings",
        name: "Keymap Layout",
        count: "45 keys",
        description: "Windsurf developer shortcuts mapped directly to Crux commands",
        selected: true,
      },
    ],
  });

  const toggleItem = (ide: string, id: string) => {
    setItems((prev) => ({
      ...prev,
      [ide]: prev[ide].map((item) =>
        item.id === id ? { ...item, selected: !item.selected } : item
      ),
    }));
  };

  const handleRunMigration = () => {
    setIsScanning(true);
    setMigrationStatus("running");
    setTimeout(() => {
      setIsScanning(false);
      setMigrationStatus("complete");
    }, 1200);
  };

  const currentItems = items[activeIde] || [];

  return (
    <section id="migration" className="py-24 px-6 max-w-6xl mx-auto border-t border-[#222222]">
      {/* Section Header */}
      <div className="text-center max-w-2xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-none bg-[#111111] border border-[#222222] text-white text-xs font-mono mb-4">
          <Sliders className="w-3.5 h-3.5 text-white" />
          <span>[ZERO-FRICTION ADOPTION]</span>
        </div>
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-white mb-4 font-sans">
          The Universal Migration Engine.
        </h2>
        <p className="text-sm sm:text-base text-[#888888] leading-relaxed font-sans">
          Switching IDEs usually breaks muscle memory. Crux automatically scans your local filesystem,
          translates your existing shortcut mappings, and preserves your custom AI agent directives.
        </p>
      </div>

      {/* Interactive Migration Card */}
      <div
        className="rounded-none border border-[#222222] bg-[#000000] p-6 sm:p-10 relative overflow-hidden"
        style={{
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
        }}
      >
        {/* IDE Selector Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-6 border-b border-[#222222]">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-[#888888] mr-2 font-mono">
              Source IDE:
            </span>
            <div className="flex items-center bg-[#000000] border border-[#222222]">
              {[
                { id: "cursor", label: "Cursor" },
                { id: "vscode", label: "VS Code" },
                { id: "windsurf", label: "Windsurf" },
              ].map((ide, idx) => (
                <button
                  key={ide.id}
                  onClick={() => {
                    setActiveIde(ide.id as any);
                    setMigrationStatus("idle");
                  }}
                  className={`px-4 py-1.5 text-xs font-mono transition-none cursor-pointer rounded-none ${
                    idx < 2 ? "border-r border-[#222222]" : ""
                  } ${
                    activeIde === ide.id
                      ? "bg-white text-black font-bold"
                      : "text-[#888888] hover:text-white"
                  }`}
                >
                  {ide.label}
                </button>
              ))}
            </div>
          </div>

          <div className="text-xs font-mono text-[#888888] hidden sm:flex items-center gap-2">
            <span className="w-1.5 h-1.5 bg-white" />
            <span>Path: ~/Library/Application Support/{activeIde === "cursor" ? "Cursor" : activeIde === "vscode" ? "Code" : "Windsurf"}/User</span>
          </div>
        </div>

        {/* Detected Scopes Checklist */}
        <div className="py-6 space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-[#888888] font-mono">
            Detected Configurations ({currentItems.length} Scopes Found)
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {currentItems.map((item) => (
              <div
                key={item.id}
                onClick={() => toggleItem(activeIde, item.id)}
                className={`p-4 rounded-none border transition-none cursor-pointer flex items-start gap-3.5 ${
                  item.selected
                    ? "bg-[#111111] border-white text-white"
                    : "bg-[#000000] border-[#222222] text-[#444444]"
                }`}
              >
                <div
                  className={`w-5 h-5 rounded-none flex items-center justify-center shrink-0 mt-0.5 border ${
                    item.selected
                      ? "bg-white text-black border-white"
                      : "border-[#333333] bg-[#111111]"
                  }`}
                >
                  {item.selected && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                </div>

                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold font-mono">{item.name}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-none bg-[#000000] border border-[#222222] text-[#888888]">
                      {item.count}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#888888] leading-relaxed font-sans">
                    {item.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Action & Feedback Footer */}
        <div className="pt-6 border-t border-[#222222] flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="text-xs text-[#888888] font-mono flex items-center gap-2">
            {migrationStatus === "complete" ? (
              <span className="text-white flex items-center gap-1.5 font-bold">
                <Check className="w-4 h-4 text-white stroke-[3]" />
                <span>Ready to execute. 0 muscle-memory regressions detected.</span>
              </span>
            ) : (
              <span>Automated translation via native Rust binary daemon</span>
            )}
          </div>

          <button
            onClick={handleRunMigration}
            disabled={isScanning}
            className="w-full sm:w-auto px-6 py-3 rounded-none bg-white hover:bg-[#111111] hover:text-white border border-white text-black font-bold text-xs uppercase tracking-wider transition-none flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Translating AST Keymaps...</span>
              </>
            ) : migrationStatus === "complete" ? (
              <>
                <span>Re-Test Ingest Pipeline</span>
                <RefreshCw className="w-3.5 h-3.5" />
              </>
            ) : (
              <>
                <span>Simulate 1-Click Ingest</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>
      </div>
    </section>
  );
}
