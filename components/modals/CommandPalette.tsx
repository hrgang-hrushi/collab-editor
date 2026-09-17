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
} from "lucide-react";

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

  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
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

  const filteredFiles = files.filter(
    (f) =>
      f.name.toLowerCase().includes(query.toLowerCase()) ||
      f.path.toLowerCase().includes(query.toLowerCase())
  );

  const commands = [
    {
      id: "cmd-switch-canvas",
      title: "Switch to Nexus Spatial Canvas",
      category: "Navigation",
      icon: <Layers className="w-4 h-4 text-linear-primary" />,
      action: () => setMode("canvas"),
    },
    {
      id: "cmd-switch-ide",
      title: "Switch to Studio IDE View",
      category: "Navigation",
      icon: <Layout className="w-4 h-4 text-linear-primary" />,
      action: () => setMode("edit"),
    },
    {
      id: "cmd-toggle-suggest",
      title: mode === "suggest" ? "Disable Suggesting Mode" : "Enable Inline Suggesting Mode",
      category: "Review",
      icon: <Sparkles className="w-4 h-4 text-linear-primary" />,
      action: () => setMode(mode === "suggest" ? "edit" : "suggest"),
    },
    {
      id: "cmd-ask-ai",
      title: "Ask CruxAI Co-Pilot (Cmd+I)",
      category: "AI",
      icon: <Bot className="w-4 h-4 text-linear-primary" />,
      action: () => setAiPromptOpen(true),
    },
    {
      id: "cmd-toggle-sidebar",
      title: "Toggle File Explorer Sidebar (Cmd+B)",
      category: "View",
      icon: <PanelLeft className="w-4 h-4 text-linear-ink-subtle" />,
      action: () => toggleSidebar(),
    },
    {
      id: "cmd-toggle-terminal",
      title: "Toggle Terminal & Daemon Console (Cmd+J)",
      category: "View",
      icon: <Terminal className="w-4 h-4 text-linear-ink-subtle" />,
      action: () => toggleTerminal(),
    },
    {
      id: "cmd-reset-zoom",
      title: "Reset Canvas Pan & Zoom (100%)",
      category: "Canvas",
      icon: <RotateCcw className="w-4 h-4 text-linear-ink-subtle" />,
      action: () => resetView(),
    },
    ...(suggestions.some((s) => s.status === "pending")
      ? [
          {
            id: "cmd-accept-all",
            title: "Accept All Pending Inline Suggestions",
            category: "Review",
            icon: <CheckCheck className="w-4 h-4 text-linear-success" />,
            action: () => {
              suggestions
                .filter((s) => s.status === "pending")
                .forEach((s) => acceptSuggestion(s.id));
            },
          },
        ]
      : []),
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
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/80 animate-in fade-in duration-75 font-mono">
      <div className="w-full max-w-lg bg-[#0A0A0A] border border-[#222222] overflow-hidden text-[#f7f8f8]">
        {/* Search Bar Input */}
        <div className="flex items-center px-3 py-2.5 border-b border-[#222222] gap-2.5 bg-[#0A0A0A]">
          <Search className="w-4 h-4 text-[#5e6ad2] shrink-0" />
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
            className="w-full bg-transparent text-xs text-[#f7f8f8] placeholder-[#62666d] focus:outline-none font-mono"
          />
          <button
            onClick={() => setIsOpen(false)}
            className="p-1 text-[#8a8f98] hover:text-[#f7f8f8]"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="p-1 max-h-[340px] overflow-y-auto space-y-0.5 text-xs bg-black">
          {allItems.length === 0 ? (
            <div className="py-6 text-center text-[#62666d] text-xs font-mono">
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
                  className={`w-full flex items-center justify-between px-3 py-1.5 text-left transition-colors font-mono ${
                    isSelected
                      ? "bg-[#141516] text-[#f7f8f8] border-l-2 border-[#5e6ad2]"
                      : "text-[#8a8f98] hover:bg-[#141516]/50 hover:text-[#f7f8f8] border-l-2 border-transparent"
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    {item.type === "file" ? (
                      <FileCode className={`w-3.5 h-3.5 shrink-0 ${isSelected ? "text-[#5e6ad2]" : "text-[#62666d]"}`} />
                    ) : (
                      <span className="shrink-0">{item.icon}</span>
                    )}
                    <span className="truncate text-xs">{item.title}</span>
                  </div>

                  <span
                    className={`text-[10px] font-mono shrink-0 ml-2 ${
                      isSelected ? "text-[#f7f8f8]" : "text-[#62666d]"
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
        <div className="px-3 py-1.5 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[10px] text-[#62666d] font-mono">
          <div className="flex items-center gap-2">
            <span>↑↓ Navigate</span>
            <span>·</span>
            <span>↵ Select</span>
            <span>·</span>
            <span>Esc Close</span>
          </div>
          <span className="text-[#5e6ad2]">Crux Command Palette</span>
        </div>
      </div>
    </div>
  );
}
