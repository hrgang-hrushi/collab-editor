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
import CruxAuthGate from "./auth/CruxAuthGate";
import CruxBrandLogo from "./CruxBrandLogo";
import CruxErrorBoundary from "./CruxErrorBoundary";
import { auth } from "@/lib/firebase";
import { onAuthStateChanged } from "firebase/auth";
import { getActiveCrexCRDTSession } from "@/lib/crdt/yjsProvider";
import { Morph } from "cube-motion/react";
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
  ArrowLeft,
} from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";

interface CruxEditorViewProps {
  onBackToEffects?: () => void;
}

export default function CruxEditorView({ onBackToEffects }: CruxEditorViewProps = {}) {
  const [isAgentOpen, setIsAgentOpen] = useState(false);
  const [isAuthGateOpen, setIsAuthGateOpen] = useState(false);
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const [gitInfo, setGitInfo] = useState<{ branch: string; isDirty: boolean }>({
    branch: "main",
    isDirty: false,
  });

  const isOnboarded = useWorkspaceStore((state) => state.isOnboarded);
  const isZeroStateOpen = useWorkspaceStore((state) => state.isZeroStateOpen);
  const setZeroStateOpen = useWorkspaceStore((state) => state.setZeroStateOpen);
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const setUserProfile = useWorkspaceStore((state) => state.setUserProfile);
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

  const [isMounted, setIsMounted] = useState(typeof window !== "undefined");
  const [livePeers, setLivePeers] = useState<Array<{ name: string; color: string; uid?: string }>>([]);

  const isNexus = mode === "canvas";

  const activeFile =
    files && files.length > 0
      ? files.find((f) => f.id === activeFileId) ||
        files.find((f) => f.name === "stream_syncer.ts") ||
        files[0]
      : null;

  // Continuously listen to active Yjs awareness peer states
  useEffect(() => {
    const checkAwareness = () => {
      if (!activeFile?.id) return;
      const session = getActiveCrexCRDTSession(activeFile.id);
      if (session && session.awareness) {
        const states = session.awareness.getStates();
        const peersList: Array<{ name: string; color: string; uid?: string }> = [];
        states.forEach((st: any, clientID: number) => {
          if (st.user) {
            peersList.push({
              name: st.user.name || `Peer-${clientID}`,
              color: st.user.color || "#FFFFFF",
              uid: st.user.uid,
            });
          }
        });
        setLivePeers(peersList);
      }
    };

    const interval = setInterval(checkAwareness, 500);
    checkAwareness();
    return () => clearInterval(interval);
  }, [activeFile?.id]);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  // Listen to Firebase Auth state
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (firebaseUser) => {
      if (firebaseUser) {
        const cleanName = firebaseUser.displayName || firebaseUser.email?.split("@")[0] || "operator";
        setUserProfile({
          name: cleanName,
          email: firebaseUser.email || `${cleanName}@auth`,
          color: "#FFFFFF",
          uid: firebaseUser.uid.slice(0, 8),
        });
      }
    });
    return () => unsubscribe();
  }, [setUserProfile]);

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

  const handleSetMode = (nextMode: "edit" | "canvas") => {
    triggerHaptic("toggle");
    setMode(nextMode);
    if (typeof window !== "undefined") {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set("mode", nextMode);
        window.history.replaceState({}, "", url.toString());
      } catch {}
    }
  };

  // URL query parameter parsing on initial mount only
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const urlMode = params.get("mode");
      if (urlMode === "canvas" || urlMode === "nexus") {
        setMode("canvas");
      } else if (urlMode === "edit" || urlMode === "ide") {
        setMode("edit");
      }
      if (params.get("onboarding") === "true" || params.get("reset") === "true") {
        useWorkspaceStore.getState().setOnboarded(false);
      }
    }
  }, [setMode]);

  // Global hotkeys: Cmd+Space (toggle mode) & Cmd+B (sidebar) & Cmd+J (terminal) & Cmd+I (agent)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.code === "Space") {
        e.preventDefault();
        const currentMode = useWorkspaceStore.getState().mode;
        handleSetMode(currentMode === "canvas" ? "edit" : "canvas");
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
  }, [toggleSidebar, toggleTerminal]);

  const menuItems = ["File", "Edit", "Selection", "View", "Go", "Run", "Terminal", "Help"];

  if (!isMounted) {
    return (
      <div className="w-screen h-screen bg-[#000000] flex items-center justify-center font-mono text-xs text-muted">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-signal animate-ping" />
          <span className="tracking-widest uppercase">Loading Editor...</span>
        </div>
      </div>
    );
  }

  if (!isOnboarded) {
    return <CruxOnboardingStartPage />;
  }

  if (isZeroStateOpen) {
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

        {/* Segmented Control: Editor vs Canvas */}
        <div className="flex items-center bg-void border border-grid p-0.5">
          <button
            type="button"
            onClick={() => handleSetMode("edit")}
            className={`px-4 py-1 text-[11px] font-medium tracking-wide uppercase transition-colors cursor-pointer ${
              !isNexus
                ? "bg-grid text-signal font-bold"
                : "text-muted hover:text-signal"
            }`}
          >
            Editor
          </button>
          <button
            type="button"
            onClick={() => handleSetMode("canvas")}
            className={`px-4 py-1 text-[11px] font-medium tracking-wide uppercase transition-colors cursor-pointer ${
              isNexus
                ? "bg-grid text-signal font-bold"
                : "text-muted hover:text-signal"
            }`}
          >
            Canvas
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
            title="User Profile (Click to switch user)"
          >
            <div className="w-1.5 h-1.5 bg-white" />
            <span className="font-medium truncate max-w-[110px]">{currentUser.name || "Developer"}</span>
            <span className="text-[10px] text-muted">[{currentUser.uid || "User"}]</span>
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
                ? "Lock Active: Workspace edits are frozen. Click to unlock."
                : "Unlocked: Click to freeze workspace writes."
            }
          >
            {viewerLock ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
            <Morph active={viewerLock} off="UNLOCKED" on="LOCKED" />
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

          {/* Active Collaborators (Dynamic WebRTC Mesh Awareness + Mock Fallbacks) */}
          <div
            className="hidden xl:flex items-center gap-1 cursor-pointer"
            onClick={() => setShareModalOpen(true)}
            title={`Active Peers in Mesh (${livePeers.length > 0 ? livePeers.length : 3} connected) · Click to open Share`}
          >
            {livePeers.length > 0 ? (
              livePeers.map((peer, idx) => {
                const initials = peer.name
                  .split(" ")
                  .map((w) => w[0])
                  .join("")
                  .toUpperCase()
                  .slice(0, 2) || "P";
                return (
                  <div
                    key={idx}
                    className="px-1.5 py-0.5 text-[9px] font-mono font-bold leading-none border transition-none"
                    style={{
                      backgroundColor: idx === 0 ? "#FFFFFF" : idx === 1 ? "#888888" : "#444444",
                      color: idx === 0 ? "#000000" : "#FFFFFF",
                      borderColor: "#222222",
                    }}
                    title={`${peer.name} (${peer.uid || "Peer"})`}
                  >
                    {initials}
                  </div>
                );
              })
            ) : (
              <>
                <div className="px-1.5 py-0.5 bg-white text-black text-[9px] font-mono font-bold leading-none border border-[#222222]" title="Sarah Lin (CRX-9941-SL)">
                  SL
                </div>
                <div className="px-1.5 py-0.5 bg-[#888888] text-white text-[9px] font-mono font-bold leading-none border border-[#222222]" title="Marcus Vance (CRX-5520-MV)">
                  MV
                </div>
                <div className="px-1.5 py-0.5 bg-[#444444] text-white text-[9px] font-mono font-bold leading-none border border-[#222222]" title="CruxAI Copilot (CRX-0001-AI)">
                  AI
                </div>
              </>
            )}
            <span className="text-[9px] font-mono text-[#444444] ml-0.5 uppercase tracking-tighter">
              [{livePeers.length > 0 ? livePeers.length : 3} Online]
            </span>
          </div>

          {/* Window Layout Toggles */}
          <div className="flex items-center gap-1">
            <button
              onClick={toggleSidebar}
              title="Files (Cmd+B)"
              className={`p-1.5 border border-grid transition-colors ${
                isSidebarOpen ? "bg-grid text-signal" : "bg-void text-muted hover:text-signal"
              }`}
            >
              <PanelLeft className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={toggleTerminal}
              title="Terminal (Cmd+J)"
              className={`p-1.5 border border-grid transition-colors ${
                isTerminalOpen ? "bg-grid text-signal" : "bg-void text-muted hover:text-signal"
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setIsAgentOpen(!isAgentOpen)}
              title="AI Assistant (Cmd+I)"
              className={`p-1.5 border border-grid transition-colors ${
                isAgentOpen ? "bg-grid text-accent2" : "bg-void text-muted hover:text-signal"
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
            </button>
          </div>


          {/* Auth Gate Trigger */}
          <button
            onClick={() => {
              triggerHaptic("click");
              setIsAuthGateOpen(true);
            }}
            title="Account"
            className="px-2 py-1 text-[10px] font-mono text-muted hover:text-white border border-grid hover:border-white bg-void transition-none uppercase"
          >
            [ACCOUNT]
          </button>

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
              <CruxErrorBoundary
                fallbackTitle="Editor Starter"
                fallbackDescription="A display error occurred in the editor pane. Click below to load the starter workspace."
              >
                <ZenithEditorPane />
              </CruxErrorBoundary>

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
          /* CANVAS VIEW */
          <div className="w-full h-full relative overflow-hidden bg-void">
            <CruxErrorBoundary
              fallbackTitle="Canvas Starter"
              fallbackDescription="An unexpected error occurred while loading the canvas. Click below to load the starter workspace."
            >
              <NexusCanvas
                onSwitchToZenith={(fileId) => {
                  if (fileId) {
                    openTab(fileId);
                    setActiveFile(fileId);
                  }
                  handleSetMode("edit");
                }}
              />
            </CruxErrorBoundary>
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
            <span className="text-[10px] tracking-wider uppercase">IN SYNC</span>
          </div>
          <span className="text-[10px] text-muted">Speed: 0.08ms</span>
        </div>
        <div className="flex items-center gap-4 text-muted">
          <span>Ln {cursorPos?.line || 1}, Col {cursorPos?.col || 1}</span>
          {activeFile && (
            <span className="hidden md:inline">
              {(activeFile.content || "").split('\n').length}L · {(activeFile.content || "").split(/\s+/).filter(Boolean).length}W
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
      {isAuthGateOpen && (
        <div className="fixed inset-0 z-50 bg-[#000000]/90 backdrop-blur-none flex items-center justify-center p-4">
          <CruxAuthGate
            onSuccess={() => setIsAuthGateOpen(false)}
            onCancel={() => setIsAuthGateOpen(false)}
          />
        </div>
      )}
    </div>
  );
}
