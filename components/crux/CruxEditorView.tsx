"use client";

import React, { useState, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import ZenithFileTree from "./zenith/ZenithFileTree";
import ZenithEditorPane from "./zenith/ZenithEditorPane";
import ZenithTerminal from "./zenith/ZenithTerminal";
import NexusCanvas from "./nexus/NexusCanvas";
import CruxAgentPanel from "./agent/CruxAgentPanel";
import CommandPalette from "@/components/modals/CommandPalette";
import {
  Copy,
  Check,
  Code,
  Layers,
  ChevronRight,
  Command,
  Bot,
  Volume2,
  VolumeX,
  Sparkles,
} from "lucide-react";
import { triggerHaptic, toggleHaptics, isHapticsEnabled } from "@/lib/haptics";

export default function CruxEditorView() {
  const [copied, setCopied] = useState(false);
  const [isAgentOpen, setIsAgentOpen] = useState(false);
  const [hapticsOn, setHapticsOn] = useState(true);

  const mode = useWorkspaceStore((state) => state.mode);
  const projectName = useWorkspaceStore((state) => state.projectName);
  const setMode = useWorkspaceStore((state) => state.setMode);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const setCommandPaletteOpen = useWorkspaceStore(
    (state) => state.setCommandPaletteOpen
  );

  const isNexus = mode === "canvas";

  const activeFile =
    files.find((f) => f.id === activeFileId) ||
    files.find((f) => f.name === "stream_syncer.ts") ||
    files[0];

  useEffect(() => {
    setHapticsOn(isHapticsEnabled());
  }, []);

  // Global hotkeys: Cmd+Space (toggle mode) & Cmd+I (toggle agent)
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      if (params.get("mode") === "edit" || params.get("mode") === "ide") {
        setMode("edit");
      }
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.code === "Space") {
        e.preventDefault();
        triggerHaptic("toggle");
        setMode(mode === "canvas" ? "edit" : "canvas");
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "i") {
        e.preventDefault();
        triggerHaptic("toggle");
        setIsAgentOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [mode, setMode]);

  const toggleSound = () => {
    const newState = toggleHaptics();
    setHapticsOn(newState);
  };

  const handleCopyCode = () => {
    if (activeFile) {
      navigator.clipboard?.writeText(activeFile.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="relative w-screen h-screen overflow-hidden bg-black text-[#f7f8f8] flex flex-col font-sans select-none">
      {/* Linear-Style Command Palette (Cmd+K) */}
      <CommandPalette />

      {/* Top Precision Header - Strict 1px bottom border, zero gradients, zero drop shadows */}
      <header className="h-10 px-3 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A] z-40 shrink-0">
        {/* Left: Brand Mark & Breadcrumbs */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-5 h-5 bg-[#141516] border border-[#222222] flex items-center justify-center">
              <span className="font-mono font-bold text-[10px] text-[#5e6ad2]">✕</span>
            </div>
            <span className="font-bold text-xs tracking-tight text-[#f7f8f8]">
              CRUX
            </span>
            <span className="w-1.5 h-1.5 bg-[#27a644]" />
            <span className="text-[10px] text-[#62666d] font-mono hidden sm:inline">
              0.08ms IPC
            </span>
          </div>

          <div className="h-3 w-[1px] bg-[#222222] mx-0.5 hidden sm:block" />

          {/* Dynamic Breadcrumb path with quick Cmd+K file switcher */}
          <div className="hidden md:flex items-center gap-1.5 text-xs text-[#8a8f98]">
            <span className="text-[#62666d]">{projectName}</span>
            {activeFile?.path && activeFile.path.includes("/") && (
              <>
                <ChevronRight className="w-3 h-3 text-[#62666d]" />
                <span className="text-[#62666d]">
                  {activeFile.path.split("/").slice(0, -1).join("/")}
                </span>
              </>
            )}
            <ChevronRight className="w-3 h-3 text-[#62666d]" />
            <button
              onClick={() => setCommandPaletteOpen(true)}
              className="text-[#f7f8f8] px-1.5 py-0.5 bg-[#141516] hover:bg-[#191a1b] border border-[#222222] flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Open Command Palette / Switch File (Cmd+K)"
            >
              <span>{activeFile?.name || "stream_syncer.ts"}</span>
              <kbd className="text-[9px] text-[#62666d] bg-black px-1 border border-[#222222]">
                ⌘K
              </kbd>
            </button>
          </div>
        </div>

        {/* Center: The View Toggle - Sleek, Ultra-Minimal Segmented Control */}
        <div className="flex items-center p-0.5 bg-black border border-[#222222]">
          <button
            onClick={() => setMode("edit")}
            className={`flex items-center gap-1.5 px-3 py-0.5 text-xs transition-colors ${
              !isNexus
                ? "bg-[#141516] text-[#f7f8f8] font-medium border border-[#222222]"
                : "text-[#8a8f98] hover:text-[#f7f8f8]"
            }`}
          >
            <Code className="w-3 h-3 text-[#5e6ad2]" />
            <span>Zenith (IDE)</span>
          </button>

          <button
            onClick={() => setMode("canvas")}
            className={`flex items-center gap-1.5 px-3 py-0.5 text-xs transition-colors ${
              isNexus
                ? "bg-[#141516] text-[#f7f8f8] font-medium border border-[#222222]"
                : "text-[#8a8f98] hover:text-[#f7f8f8]"
            }`}
          >
            <Layers className="w-3 h-3 text-[#8a8f98]" />
            <span>Nexus (Canvas)</span>
          </button>

          <div className="hidden lg:flex items-center gap-1 ml-1 px-1 text-[10px] text-[#62666d]">
            <Command className="w-2.5 h-2.5" />
            <span>Space</span>
          </div>
        </div>

        {/* Right: Flat Collaborator Badges & Telemetry */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1">
            <div
              className="px-1.5 py-0.5 text-[10px] font-mono bg-[#141516] border border-[#06b6d4]/40 text-[#06b6d4]"
              title="Sarah Lin (Staff Infrastructure - Cyan)"
            >
              <span className="font-semibold mr-1">●</span>
              <span>SL</span>
            </div>

            {/* Autonomous Copilot Toggle */}
            <button
              onClick={() => {
                triggerHaptic("toggle");
                setIsAgentOpen(!isAgentOpen);
              }}
              className={`px-2 py-0.5 text-[10px] font-sans flex items-center gap-1 border transition-colors cursor-pointer ${
                isAgentOpen
                  ? "bg-[#8b5cf6]/20 border-[#8b5cf6] text-[#c4b5fd] font-medium"
                  : "bg-[#141516] border-[#8b5cf6]/40 text-[#8b5cf6] hover:bg-[#8b5cf6]/10"
              }`}
              title="Toggle CruxAI Autonomous Coding Agent (⌘I)"
            >
              <Bot className="w-3 h-3 text-[#8b5cf6]" />
              <span>@CruxAI</span>
              <kbd className="text-[8px] bg-black text-[#8b5cf6] px-1 border border-[#8b5cf6]/30">⌘I</kbd>
            </button>

            <div
              className="px-1.5 py-0.5 text-[10px] font-mono bg-[#141516] border border-[#f59e0b]/40 text-[#f59e0b] hidden sm:block"
              title="Marcus Vance (Systems Architect - Amber)"
            >
              <span>MV</span>
            </div>
          </div>

          <div className="h-3 w-[1px] bg-[#222222] mx-0.5" />

          {/* Tactile Audio & Haptics Toggle */}
          <button
            onClick={toggleSound}
            title={hapticsOn ? "Tactile Audio & Haptics: Active (Click to Mute)" : "Tactile Audio & Haptics: Muted"}
            className={`p-1 border transition-colors ${
              hapticsOn
                ? "text-[#5e6ad2] border-[#5e6ad2]/40 bg-[#5e6ad2]/10"
                : "text-[#62666d] border-[#222222] hover:text-white"
            }`}
          >
            {hapticsOn ? <Volume2 className="w-3 h-3" /> : <VolumeX className="w-3 h-3" />}
          </button>

          <button
            onClick={handleCopyCode}
            title={`Copy buffer (${activeFile?.name})`}
            className="p-1 bg-[#141516] hover:bg-[#191a1b] text-[#8a8f98] hover:text-[#f7f8f8] border border-[#222222] transition-colors"
          >
            {copied ? (
              <Check className="w-3 h-3 text-[#27a644]" />
            ) : (
              <Copy className="w-3 h-3" />
            )}
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <div className="flex-1 w-full overflow-hidden relative">
        {!isNexus ? (
          /* ZENITH MODE (IDE SHELL)
             - Pure black (bg-black) central editor area
             - Dark gray (bg-[#0A0A0A]) file tree on the left
             - Terminal on the bottom
             - Autonomous Agent Copilot on the right
             - Strict 1px solid border (border-[#222222]) separating every panel
          */
          <div className="w-full h-full flex flex-row overflow-hidden">
            <ZenithFileTree />
            <div className="flex-1 flex flex-col overflow-hidden min-w-0">
              <ZenithEditorPane />
              <ZenithTerminal />
            </div>
            {/* Autonomous CruxAI Coding Agent Side Panel */}
            <CruxAgentPanel
              isOpen={isAgentOpen}
              onClose={() => setIsAgentOpen(false)}
            />
          </div>
        ) : (
          /* NEXUS MODE: Spatial Architecture Canvas */
          <div className="w-full h-full relative overflow-hidden bg-black">
            <NexusCanvas
              onSwitchToZenith={(fileId) => {
                if (fileId) {
                  openTab(fileId);
                  setActiveFile(fileId);
                }
                setMode("edit");
              }}
            />
          </div>
        )}
      </div>

      {/* Bottom Status Bar - Strict 1px top border */}
      <footer className="h-6 px-3 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[11px] text-[#8a8f98] select-none shrink-0 font-sans">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5 text-[#f7f8f8]">
            <span className="w-1.5 h-1.5 bg-[#27a644]" />
            <span>Daemon IPC 0.08ms</span>
          </div>
          <span className="text-[#333333]">·</span>
          <span>{activeFile?.name}</span>
          <span className="text-[#333333]">·</span>
          <span>TypeScript · UTF-8</span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={toggleSound}
            className="flex items-center gap-1 hover:text-white transition-colors"
            title="Toggle Tactile Haptics & Acoustics"
          >
            {hapticsOn ? <Volume2 className="w-3 h-3 text-[#5e6ad2]" /> : <VolumeX className="w-3 h-3 text-[#62666d]" />}
            <span className={hapticsOn ? "text-[#f7f8f8]" : "text-[#62666d]"}>Haptics: {hapticsOn ? "On" : "Off"}</span>
          </button>
          <span className="text-[#333333]">·</span>
          <button
            onClick={() => {
              triggerHaptic("toggle");
              setIsAgentOpen(!isAgentOpen);
            }}
            className="flex items-center gap-1 text-[#8b5cf6] hover:text-[#c4b5fd] transition-colors"
            title="Toggle Coding Agent (Cmd+I)"
          >
            <Bot className="w-3 h-3" />
            <span>Agent (⌘I)</span>
          </button>
          <span className="text-[#333333]">·</span>
          <span className="text-[#27a644]">3 Peers In-Sync</span>
        </div>
      </footer>
    </div>
  );
}
