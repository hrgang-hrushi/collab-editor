"use client";

import React, { useEffect, useState, useRef } from "react";
import { useWorkspaceStore } from "@/lib/store";
import {
  Search,
  FileCode,
  Layers,
  Sparkles,
  Layout,
  RotateCcw,
  CheckCheck,
  X,
  Terminal,
  PanelLeft,
  Bot,
  Database,
  ShieldCheck,
  Code2,
  FileText,
  FileCode2,
  FilePlus,
  Download,
  Play,
  Maximize2,
  Trash2,
  Lock,
  SplitSquareVertical,
  Contrast,
} from "lucide-react";
import { exportWorkspaceAsZip } from "@/lib/fileUtils";

export default function CommandPalette() {
  const isOpen = useWorkspaceStore((state) => state.isCommandPaletteOpen);
  const setIsOpen = useWorkspaceStore((state) => state.setCommandPaletteOpen);
  const files = useWorkspaceStore((state) => state.files);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const mode = useWorkspaceStore((state) => state.mode);
  const setMode = useWorkspaceStore((state) => state.setMode);
  const resetView = useWorkspaceStore((state) => state.resetView);
  const suggestions = useWorkspaceStore((state) => state.suggestions);
  const acceptSuggestion = useWorkspaceStore((state) => state.acceptSuggestion);
  const toggleSidebar = useWorkspaceStore((state) => state.toggleSidebar);
  const toggleTerminal = useWorkspaceStore((state) => state.toggleTerminal);
  const setAiPromptOpen = useWorkspaceStore((state) => state.setAiPromptOpen);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const createFile = useWorkspaceStore((state) => state.createFile);
  const runActiveFile = useWorkspaceStore((state) => state.runActiveFile);
  const toggleTerminalMaximized = useWorkspaceStore((state) => state.toggleTerminalMaximized);
  const clearTerminalSession = useWorkspaceStore((state) => state.clearTerminalSession);
  const activeTerminalSessionId = useWorkspaceStore((state) => state.activeTerminalSessionId);
  const toggleViewerLock = useWorkspaceStore((state) => state.toggleViewerLock);
  const projectName = useWorkspaceStore((state) => state.projectName);
  const toggleMonochromeTheme = useWorkspaceStore((state) => state.toggleMonochromeTheme);
  const setZeroStateOpen = useWorkspaceStore((state) => state.setZeroStateOpen);
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);

  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "p") {
        e.preventDefault();
        setIsOpen(!isOpen);
      }
      if (e.key === "Escape" && isOpen) {
        setIsOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, setIsOpen]);

  useEffect(() => {
    if (isOpen) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const getFileIcon = (name: string) => {
    if (name.includes("db") || name.includes("database")) {
      return <Database className="w-4 h-4 text-[#858585] shrink-0" />;
    }
    if (name.includes("auth") || name.includes("session")) {
      return <ShieldCheck className="w-4 h-4 text-[#858585] shrink-0" />;
    }
    if (name.endsWith(".rs")) {
      return <Code2 className="w-4 h-4 text-[#858585] shrink-0" />;
    }
    if (name.endsWith(".json")) {
      return <FileCode2 className="w-4 h-4 text-[#858585] shrink-0" />;
    }
    if (name.endsWith(".css")) {
      return <FileCode2 className="w-4 h-4 text-[#858585] shrink-0" />;
    }
    return <FileCode2 className="w-4 h-4 text-[#858585] shrink-0" />;
  };

  const filteredFiles = files.filter(
    (f) =>
      f.name.toLowerCase().includes(query.toLowerCase()) ||
      f.path.toLowerCase().includes(query.toLowerCase())
  );

  const commands = [
    {
      id: "cmd-switch-canvas",
      title: "Switch to Canvas View",
      category: "Navigation",
      icon: <Layers className="w-4 h-4 text-[#858585]" />,
      action: () => setMode("canvas"),
    },
    {
      id: "cmd-switch-ide",
      title: "Switch to Editor View",
      category: "Navigation",
      icon: <Layout className="w-4 h-4 text-[#858585]" />,
      action: () => setMode("edit"),
    },
    {
      id: "cmd-ask-ai",
      title: "Ask AI Assistant (Cmd+I)",
      category: "AI",
      icon: <Bot className="w-4 h-4 text-[#858585]" />,
      action: () => setAiPromptOpen(true),
    },
    {
      id: "cmd-toggle-sidebar",
      title: "Toggle File Explorer (Cmd+B)",
      category: "View",
      icon: <PanelLeft className="w-4 h-4 text-[#858585]" />,
      action: () => toggleSidebar(),
    },
    {
      id: "cmd-toggle-terminal",
      title: "Toggle Terminal (Cmd+J)",
      category: "View",
      icon: <Terminal className="w-4 h-4 text-[#858585]" />,
      action: () => toggleTerminal(),
    },
    {
      id: "cmd-reset-zoom",
      title: "Reset Canvas Pan & Zoom (100%)",
      category: "Canvas",
      icon: <RotateCcw className="w-4 h-4 text-[#858585]" />,
      action: () => resetView(),
    },
    ...(suggestions.some((s) => s.status === "pending")
      ? [
          {
            id: "cmd-accept-all",
            title: "Accept All Pending Inline Suggestions",
            category: "Review",
            icon: <CheckCheck className="w-4 h-4 text-emerald-400" />,
            action: () => {
              suggestions
                .filter((s) => s.status === "pending")
                .forEach((s) => acceptSuggestion(s.id));
            },
          },
        ]
      : []),
    {
      id: "cmd-new-file",
      title: "New File",
      category: "File",
      icon: <FilePlus className="w-4 h-4 text-[#858585]" />,
      action: () => {
        createFile("untitled.ts");
        setMode("edit");
      },
    },
    {
      id: "cmd-export-zip",
      title: "Export Workspace as ZIP",
      category: "File",
      icon: <Download className="w-4 h-4 text-[#858585]" />,
      action: () => exportWorkspaceAsZip(files, projectName),
    },
    {
      id: "cmd-run-code",
      title: "Run Active File (⌘+Enter)",
      category: "Run",
      icon: <Play className="w-4 h-4 text-[#858585]" />,
      action: () => runActiveFile(),
    },
    {
      id: "cmd-maximize-terminal",
      title: "Maximize / Restore Terminal",
      category: "View",
      icon: <Maximize2 className="w-4 h-4 text-[#858585]" />,
      action: () => toggleTerminalMaximized(),
    },
    {
      id: "cmd-clear-terminal",
      title: "Clear Terminal Buffer",
      category: "Terminal",
      icon: <Trash2 className="w-4 h-4 text-[#858585]" />,
      action: () => {
        if (activeTerminalSessionId) clearTerminalSession(activeTerminalSessionId);
      },
    },
    {
      id: "cmd-viewer-lock",
      title: "Toggle Viewer Lock",
      category: "Permissions",
      icon: <Lock className="w-4 h-4 text-[#858585]" />,
      action: () => toggleViewerLock(),
    },
    {
      id: "cmd-split-editor",
      title: "Split Editor Pane",
      category: "View",
      icon: <SplitSquareVertical className="w-4 h-4 text-[#858585]" />,
      action: () => setMode("edit"),
    },
    {
      id: "cmd-switch-monochrome",
      title: "Toggle Monochrome Theme",
      category: "Appearance",
      icon: <Contrast className="w-4 h-4 text-[#858585]" />,
      action: () => toggleMonochromeTheme(),
    },
    {
      id: "cmd-open-launcher",
      title: "Open Launcher / Omnibar Void",
      category: "View",
      icon: <Terminal className="w-4 h-4 text-[#858585]" />,
      action: () => setZeroStateOpen(true),
    },
    {
      id: "cmd-replay-onboarding",
      title: "Replay GA Onboarding & Calibration",
      category: "System",
      icon: <Sparkles className="w-4 h-4 text-[#858585]" />,
      action: () => setOnboarded(false),
    },
  ];

  const filteredCommands = commands.filter((c) =>
    c.title.toLowerCase().includes(query.toLowerCase())
  );

  const allItems = [
    ...filteredFiles.map((f) => ({
      type: "file" as const,
      id: f.id,
      title: f.name,
      subtitle: f.path,
      icon: getFileIcon(f.name),
      action: () => {
        openTab(f.id);
        setActiveFile(f.id);
        setMode("edit");
      },
    })),
    ...filteredCommands.map((c) => ({
      type: "cmd" as const,
      id: c.id,
      title: c.title,
      subtitle: c.category,
      icon: c.icon,
      action: c.action,
    })),
  ];

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (allItems.length || 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + allItems.length) % (allItems.length || 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const item = allItems[selectedIndex];
      if (item) {
        item.action();
        setIsOpen(false);
      }
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-20 px-4 bg-black/80 font-sans">
      <div className="w-full max-w-xl bg-[#0A0A0A] border border-[#222222] rounded-none overflow-hidden text-white">
        {/* Search Bar Input */}
        <div className="flex items-center px-3 py-2 border-b border-[#222222] gap-2.5 bg-black">
          <Search className="w-4 h-4 text-[#888888] shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleKeyDown}
            placeholder="Type a command or search workspace files..."
            className="w-full bg-transparent text-xs text-white placeholder-[#888888] focus:outline-none font-mono"
          />
          <button
            onClick={() => setIsOpen(false)}
            className="p-1 rounded-none text-[#888888] hover:text-white transition-colors"
          >
            <kbd className="text-[9px] bg-black px-1 py-0.5 rounded-none border border-[#222222] text-[#888888] font-mono">ESC</kbd>
          </button>
        </div>

        {/* Results List */}
        <div className="p-1 max-h-[360px] overflow-y-auto space-y-0.5 text-xs bg-[#0A0A0A]">
          {allItems.length === 0 ? (
            <div className="py-8 text-center text-[#888888] text-xs font-mono">
              No matching files or commands found
            </div>
          ) : (
            allItems.map((item, idx) => {
              const isSelected = idx === selectedIndex;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    item.action();
                    setIsOpen(false);
                  }}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-none text-left transition-none ${
                    isSelected
                      ? "bg-[#222222] text-white"
                      : "text-[#888888] hover:text-white hover:bg-black"
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    <span className="shrink-0">{item.icon}</span>
                    <span className="truncate text-xs font-mono">{item.title}</span>
                  </div>

                  <span
                    className={`text-[9px] font-mono shrink-0 ml-3 px-1.5 py-0.5 rounded-none ${
                      isSelected
                        ? "bg-black text-white border border-[#222222]"
                        : "bg-black text-[#888888] border border-[#222222]"
                    }`}
                  >
                    {item.subtitle}
                  </span>
                </button>
              );
            })
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="px-3 py-1.5 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[10px] text-[#888888] font-sans">
          <div className="flex items-center gap-2">
            <span>↑↓ Navigate</span>
            <span>·</span>
            <span>↵ Select</span>
            <span>·</span>
            <span>Esc Close</span>
          </div>
          <span className="text-[#888888] font-mono text-[10px] uppercase tracking-widest">
            QUICK OPEN
          </span>
        </div>
      </div>
    </div>
  );
}
