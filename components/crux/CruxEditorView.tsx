"use client";

import React, { useState, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import ZenithFileTree from "./zenith/ZenithFileTree";
import ZenithEditorPane from "./zenith/ZenithEditorPane";
import ZenithTerminal from "./zenith/ZenithTerminal";
import NexusCanvas from "./nexus/NexusCanvas";
import CruxAgentPanel from "./agent/CruxAgentPanel";
import CommandPalette from "@/components/modals/CommandPalette";
import CruxOnboardingStartPage from "./onboarding/CruxOnboardingStartPage";
import CruxOmnibarVoid from "./void/CruxOmnibarVoid";
import CruxShareModal from "./modals/CruxShareModal";
import CruxInboxModal from "./modals/CruxInboxModal";
import CruxIdentityDrawer from "./modals/CruxIdentityDrawer";
import CruxLibraryModal from "./modals/CruxLibraryModal";
import CruxBrandLogo from "./CruxBrandLogo";
import {
  Layers,
  Code,
  Search,
  PanelLeft,
  Terminal,
  Sparkles,
  Bot,
  Bell,
  Check,
  ChevronRight,
  SplitSquareVertical,
  GitBranch,
  Radio,
  CheckCheck,
  Lock,
  Unlock,
  Inbox,
  Share2,
} from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";

export default function CruxEditorView() {
  const [isAgentOpen, setIsAgentOpen] = useState(false);
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const [gitInfo, setGitInfo] = useState<{ branch: string; isDirty: boolean }>({
    branch: "main",
    isDirty: false,
  });

  const isOnboarded = useWorkspaceStore((state) => state.isOnboarded);
  const isZeroStateOpen = useWorkspaceStore((state) => state.isZeroStateOpen);
  const setZeroStateOpen = useWorkspaceStore((state) => state.setZeroStateOpen);
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const viewerLock = useWorkspaceStore((state) => state.viewerLock);
  const toggleViewerLock = useWorkspaceStore((state) => state.toggleViewerLock);
  const inboxInvites = useWorkspaceStore((state) => state.inboxInvites);
  const isIdentityDrawerOpen = useWorkspaceStore((state) => state.isIdentityDrawerOpen);
  const setIdentityDrawerOpen = useWorkspaceStore((state) => state.setIdentityDrawerOpen);
  const isShareModalOpen = useWorkspaceStore((state) => state.isShareModalOpen);
  const setShareModalOpen = useWorkspaceStore((state) => state.setShareModalOpen);
  const isInboxOpen = useWorkspaceStore((state) => state.isInboxOpen);
  const setInboxOpen = useWorkspaceStore((state) => state.setInboxOpen);

  const mode = useWorkspaceStore((state) => state.mode);
  const projectName = useWorkspaceStore((state) => state.projectName);
  const setMode = useWorkspaceStore((state) => state.setMode);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const isSidebarOpen = useWorkspaceStore((state) => state.isSidebarOpen);
  const toggleSidebar = useWorkspaceStore((state) => state.toggleSidebar);
  const isTerminalOpen = useWorkspaceStore((state) => state.isTerminalOpen);
  const toggleTerminal = useWorkspaceStore((state) => state.toggleTerminal);
  const cursorPos = useWorkspaceStore((state) => state.cursorPos);
  const setCommandPaletteOpen = useWorkspaceStore(
    (state) => state.setCommandPaletteOpen
  );

  const pendingInvitesCount = inboxInvites.filter((inv) => inv.status === "pending").length;

  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  useEffect(() => {
    fetch("/api/git", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "branch" }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.branch) {
          setGitInfo({ branch: data.branch, isDirty: !!data.isDirty });
        }
      })
      .catch(() => {/* keep defaults */});
  }, []);

  const isNexus = mode === "canvas";

  const activeFile =
    files.find((f) => f.id === activeFileId) ||
    files.find((f) => f.name === "stream_syncer.ts") ||
    files[0];

  // Global hotkeys: Cmd+Space (toggle mode) & Cmd+B (sidebar) & Cmd+J (terminal) & Cmd+I (agent)
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
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "b") {
        e.preventDefault();
        toggleSidebar();
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "j") {
        e.preventDefault();
        toggleTerminal();
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "i") {
        e.preventDefault();
        setIsAgentOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [mode, setMode, toggleSidebar, toggleTerminal]);

  const menuItems = ["File", "Edit", "Selection", "View", "Go", "Run", "Terminal", "Help"];

  if (!isMounted) {
    return (
      <div className="w-screen h-screen bg-[#000000] flex items-center justify-center font-mono text-xs text-muted">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-signal animate-ping" />
          <span className="tracking-widest uppercase">CRUX_HYBRID_CORE_INITIALIZING...</span>
        </div>
      </div>
    );
  }

  if (!isOnboarded || isZeroStateOpen) {
    return <CruxOmnibarVoid />;
  }

  return (
    <div className="relative w-screen h-screen overflow-hidden bg-black text-white flex flex-col font-sans select-none selection:bg-[#222222]">
      {/* VS Code / Command Palette (Cmd+K / Cmd+P) */}
      <CommandPalette />

      {/* 1. CRUX TOP NAV (48px h-12, bg-surface border-b border-grid) */}
      <header className="h-12 border-b border-grid bg-surface flex items-center justify-between px-4 z-30 shrink-0 font-sans select-none">
        <div className="flex items-center gap-4">
          {/* Crux / Crex Brand Logo */}
          <div className="flex items-center gap-2 cursor-pointer" onClick={() => setCommandPaletteOpen(true)} title="Crux Platform (Cmd+K)">
            <CruxBrandLogo size={18} withText={true} />
          </div>

          {/* Quick Open Command Palette Search */}
          <button
            onClick={() => setCommandPaletteOpen(true)}
            className="hidden md:flex items-center gap-2 px-2.5 py-1 bg-void hover:bg-[#111111] border border-grid text-muted hover:text-signal text-[11px] transition-colors"
            title="Search Files and Commands (Cmd+P)"
          >
            <Search className="w-3 h-3 text-muted" />
            <span className="font-mono text-[11px]">{activeFile?.name || "stream_syncer.ts"}</span>
            <kbd className="text-[9px] bg-surface text-muted px-1 border border-grid font-mono">⌘P</kbd>
          </button>
        </div>

        {/* Segmented Control: Zenith vs Nexus */}
        <div className="flex items-center bg-void border border-grid p-0.5">
          <button
            onClick={() => setMode("edit")}
            className={`px-4 py-1 text-[11px] font-medium tracking-wide uppercase transition-colors ${
              !isNexus
                ? "bg-grid text-signal"
                : "text-muted hover:text-signal"
            }`}
          >
            Zenith (IDE)
          </button>
          <button
            onClick={() => setMode("canvas")}
            className={`px-4 py-1 text-[11px] font-medium tracking-wide uppercase transition-colors ${
              isNexus
                ? "bg-grid text-signal"
                : "text-muted hover:text-signal"
            }`}
          >
            Nexus (Canvas)
          </button>
        </div>

        {/* Right Status & Actions */}
        <div className="flex items-center gap-2.5">
          {/* Identity Pill Button */}
          <button
            onClick={() => {
              triggerHaptic("click");
              setIdentityDrawerOpen(true);
            }}
            className="hidden sm:flex items-center gap-2 px-2.5 py-1 bg-void hover:bg-grid border border-grid text-signal text-[11px] font-mono transition-colors"
            title="Developer Identity & Keyring (Click to switch user or copy UID)"
          >
            <div className="w-1.5 h-1.5 bg-white" />
            <span className="font-medium truncate max-w-[110px]">{currentUser.name || "Developer"}</span>
            <span className="text-[10px] text-muted">[{currentUser.uid || "CRX-7447"}]</span>
          </button>

          {/* Viewer Lock Quick Toggle */}
          <button
            onClick={() => {
              triggerHaptic("toggle");
              toggleViewerLock();
            }}
            className={`flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider border transition-colors ${
              viewerLock
                ? "bg-accent2/20 border-accent2 text-accent2 font-bold"
                : "bg-void border-grid text-muted hover:text-signal"
            }`}
            title={
              viewerLock
                ? "Viewer Lock Active: Workspace edits are frozen across all peers. Click to unlock."
                : "Viewer Lock Off: Click to freeze workspace writes."
            }
          >
            {viewerLock ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
            <span>{viewerLock ? "LOCK ON" : "LOCK OFF"}</span>
          </button>

          {/* Collaborative Inbox Button */}
          <button
            onClick={() => {
              triggerHaptic("click");
              setInboxOpen(true);
            }}
            className="relative p-1.5 border border-grid bg-void hover:bg-grid text-muted hover:text-signal transition-colors flex items-center justify-center"
            title="Workspace Invites & Collaborative Inbox"
          >
            <Inbox className="w-3.5 h-3.5" />
            {pendingInvitesCount > 0 && (
              <span className="absolute -top-1 -right-1 bg-accent1 text-void text-[9px] font-mono font-bold w-4 h-4 flex items-center justify-center leading-none">
                {pendingInvitesCount}
              </span>
            )}
          </button>

          {/* Active Collaborators */}
          <div
            className="hidden xl:flex items-center gap-1 cursor-pointer"
            onClick={() => setShareModalOpen(true)}
            title="Active Peers in Room (Click to open Share / Invites)"
          >
            <div className="px-1.5 py-0.5 bg-accent1 text-void text-[9px] font-mono font-bold leading-none" title="Sarah Lin (CRX-9941-SL)">
              SL
            </div>
            <div className="px-1.5 py-0.5 bg-void border border-grid text-muted text-[9px] font-mono leading-none" title="Marcus Vance (CRX-5520-MV)">
              MV
            </div>
            <div className="px-1.5 py-0.5 bg-accent2 text-signal text-[9px] font-mono font-bold leading-none" title="CruxAI Copilot (CRX-0001-AI)">
              AI
            </div>
          </div>

          {/* Window Layout Toggles */}
          <div className="flex items-center gap-1">
            <button
              onClick={toggleSidebar}
              title="Toggle Explorer (Cmd+B)"
              className={`p-1.5 border border-grid transition-colors ${
                isSidebarOpen ? "bg-grid text-signal" : "bg-void text-muted hover:text-signal"
              }`}
            >
              <PanelLeft className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={toggleTerminal}
              title="Toggle Terminal Drawer (Cmd+J)"
              className={`p-1.5 border border-grid transition-colors ${
                isTerminalOpen ? "bg-grid text-signal" : "bg-void text-muted hover:text-signal"
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setIsAgentOpen(!isAgentOpen)}
              title="Toggle CruxAI Copilot (Cmd+I)"
              className={`p-1.5 border border-grid transition-colors ${
                isAgentOpen ? "bg-grid text-accent2" : "bg-void text-muted hover:text-signal"
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Share Button */}
          <button
            onClick={() => {
              triggerHaptic("click");
              setShareModalOpen(true);
            }}
            className="px-3 py-1 text-[11px] font-medium border border-grid bg-void hover:bg-grid transition-colors text-signal uppercase flex items-center gap-1.5"
            title="Share Workspace with collaborator UID or Email"
          >
            <Share2 className="w-3 h-3 text-accent1" />
            <span>Share</span>
          </button>
        </div>
      </header>

      {/* 1b. CRUX MENU BAR (24px, VS Code-style clickable menu items) */}
      <div className="h-6 border-b border-[#111111] bg-[#050505] flex items-center px-4 shrink-0 select-none">
        {menuItems.map((item) => (
          <button
            key={item}
            onClick={() => setCommandPaletteOpen(true)}
            className="px-3 h-full text-[11px] text-[#666666] hover:text-white hover:bg-[#111111] transition-colors font-sans"
          >
            {item}
          </button>
        ))}
      </div>

      {/* 2. MAIN LAYOUT */}
      <div className="flex flex-1 overflow-hidden">
        {!isNexus ? (
          /* ZENITH: BRUTALIST IDE WORKSPACE */
          <div className="w-full h-full flex flex-col overflow-hidden bg-void">
            <div className="flex flex-1 overflow-hidden">
              {/* SIDEBAR (EXPLORER) */}
              {isSidebarOpen && <ZenithFileTree />}

              {/* EDITOR CANVAS */}
              <ZenithEditorPane />

              {/* AI AGENT PANEL */}
              <CruxAgentPanel
                isOpen={isAgentOpen}
                onClose={() => setIsAgentOpen(false)}
              />
            </div>

            {/* TERMINAL DRAWER */}
            {isTerminalOpen && <ZenithTerminal />}
          </div>
        ) : (
          /* NEXUS: ARCHITECTURAL SPATIAL CANVAS */
          <div className="w-full h-full relative overflow-hidden bg-void">
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

      {/* 3. CRUX STATUS BAR (22px high, bg-surface border-t border-grid) */}
      <footer className="h-[22px] px-3 bg-surface border-t border-grid text-muted flex items-center justify-between text-[11px] font-mono select-none shrink-0 z-30">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 hover:text-signal cursor-pointer">
            <GitBranch className="w-3 h-3 text-muted" />
            <span className="text-signal">{gitInfo.branch}{gitInfo.isDirty ? "*" : ""}</span>
          </div>
          <div className="hidden sm:flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 bg-white" />
            <span className="text-[10px] tracking-wider uppercase">CRDT IN-SYNC</span>
          </div>
          <span className="text-[10px] text-muted">Daemon: 0.08ms</span>
        </div>
        <div className="flex items-center gap-4 text-muted">
          <span>Ln {cursorPos?.line || 1}, Col {cursorPos?.col || 1}</span>
          {activeFile && (
            <span className="hidden md:inline">
              {activeFile.content.split('\n').length}L · {activeFile.content.split(/\s+/).filter(Boolean).length}W
            </span>
          )}
          <span className="hidden sm:inline">UTF-8</span>
          <span className="uppercase text-signal font-medium">
            {({
              typescript: "TypeScript",
              javascript: "JavaScript",
              python: "Python",
              json: "JSON",
              markdown: "Markdown",
              plaintext: "Plain Text",
            } as Record<string, string>)[activeFile?.language ?? "plaintext"] ?? "Plain Text"}
          </span>
        </div>
      </footer>

      {/* 4. COLLABORATIVE OVERLAYS & MODALS */}
      <CruxShareModal />
      <CruxInboxModal />
      <CruxIdentityDrawer />
      <CruxLibraryModal />
    </div>
  );
}
