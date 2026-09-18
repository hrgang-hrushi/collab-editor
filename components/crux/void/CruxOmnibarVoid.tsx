"use client";

import React, { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { useWorkspaceStore } from "@/lib/store";
import VoidCanvas from "./VoidCanvas";
import VoidHUD from "./VoidHUD";
import VoidKeymapBar from "./VoidKeymapBar";
import VoidSuggestionMatrix, { VoidSuggestion } from "./VoidSuggestionMatrix";
import VoidTerminalStage from "./VoidTerminalStage";
import CruxBrandLogo from "../CruxBrandLogo";
import { triggerHaptic } from "@/lib/haptics";
import { Terminal, Sparkles, Folder, GitBranch, ArrowRight, LayoutGrid } from "lucide-react";

interface TerminalLine {
  id: string;
  text: string;
  type?: "info" | "success" | "warn" | "error" | "dim";
}

export default function CruxOmnibarVoid() {
  const isOnboarded = useWorkspaceStore((state) => state.isOnboarded);
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);
  const setUserProfile = useWorkspaceStore((state) => state.setUserProfile);
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const setZeroStateOpen = useWorkspaceStore((state) => state.setZeroStateOpen);
  const setMode = useWorkspaceStore((state) => state.setMode);
  const createFile = useWorkspaceStore((state) => state.createFile);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const addTerminalEntry = useWorkspaceStore((state) => state.addTerminalEntry);
  const files = useWorkspaceStore((state) => state.files);
  const remoteCursors = useWorkspaceStore((state) => state.remoteCursors);

  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [isShattering, setIsShattering] = useState(false);

  // Terminal Stage state for clone/scaffold streaming
  const [terminalStage, setTerminalStage] = useState<{
    active: boolean;
    title: string;
    command: string;
    lines: TerminalLine[];
    isRunning: boolean;
    isComplete: boolean;
  }>({
    active: false,
    title: "",
    command: "",
    lines: [],
    isRunning: false,
    isComplete: false,
  });

  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-focus input on mount and on key press
  useEffect(() => {
    inputRef.current?.focus();
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      // Don't intercept if terminal stage is active
      if (terminalStage.active) return;

      if (e.key === "Escape") {
        e.preventDefault();
        setQuery("");
        return;
      }

      // If user presses Cmd+K, let the standard handler run
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        return;
      }

      // Automatically focus input if typing alphanumeric
      if (
        document.activeElement !== inputRef.current &&
        !e.metaKey &&
        !e.ctrlKey &&
        !e.altKey &&
        e.key.length === 1
      ) {
        inputRef.current?.focus();
      }
    };

    window.addEventListener("keydown", handleGlobalKeyDown);
    return () => window.removeEventListener("keydown", handleGlobalKeyDown);
  }, [terminalStage.active]);

  // Ensure default developer identity is established
  const ensureIdentity = useCallback(() => {
    if (!isOnboarded) {
      setUserProfile({
        name: currentUser.name || "Principal Developer",
        email: currentUser.email || "developer@crux.engine",
        uid: currentUser.uid || "CRX-7447-HG",
        password: "crux-enclave-key",
        role: "Principal Developer",
        accessLevel: "full",
        isSelf: true,
      });
      setOnboarded(true);
    }
  }, [isOnboarded, currentUser, setUserProfile, setOnboarded]);

  // Launch into Zenith IDE
  const launchIDE = useCallback(() => {
    ensureIdentity();
    setIsShattering(true);
    triggerHaptic("click");
    setTimeout(() => {
      setZeroStateOpen(false);
    }, 240);
  }, [ensureIdentity, setZeroStateOpen]);

  // Launch into Spatial Canvas (Nexus Mode)
  const launchCanvas = useCallback(() => {
    ensureIdentity();
    setMode("canvas");
    setIsShattering(true);
    triggerHaptic("click");
    setTimeout(() => {
      setZeroStateOpen(false);
    }, 240);
  }, [ensureIdentity, setMode, setZeroStateOpen]);

  // Start clone streaming sequence
  const executeClone = useCallback(
    (repoUrl: string) => {
      ensureIdentity();
      triggerHaptic("click");
      setTerminalStage({
        active: true,
        title: "CRUX GIT ENGINE // REPO CLONE",
        command: `git clone ${repoUrl}`,
        lines: [
          { id: "1", text: `→ Resolving remote host: ${repoUrl}`, type: "info" },
          { id: "2", text: "→ Establishing TLS connection with GitHub edge...", type: "dim" },
        ],
        isRunning: true,
        isComplete: false,
      });

      // Stream sequential steps
      setTimeout(() => {
        setTerminalStage((prev) => ({
          ...prev,
          lines: [
            ...prev.lines,
            { id: "3", text: "remote: Enumerating objects: 248, done.", type: "info" },
            { id: "4", text: "remote: Compressing objects: 100% (142/142), done.", type: "info" },
          ],
        }));
      }, 400);

      setTimeout(() => {
        setTerminalStage((prev) => ({
          ...prev,
          lines: [
            ...prev.lines,
            { id: "5", text: "Receiving objects: 100% (248/248), 1.24 MiB | 8.4 MiB/s, done.", type: "info" },
            { id: "6", text: "Resolving deltas: 100% (98/98), completed with 42 local objects.", type: "info" },
            { id: "7", text: "✓ Workspace mounted into active CRUX virtual filesystem.", type: "success" },
          ],
          isRunning: false,
          isComplete: true,
        }));
        triggerHaptic("success");
      }, 1000);
    },
    [ensureIdentity]
  );

  // Start @CruxAI scaffold streaming sequence
  const executeScaffold = useCallback(
    (promptText: string) => {
      ensureIdentity();
      triggerHaptic("click");
      setTerminalStage({
        active: true,
        title: "CRUX_AI // AUTONOMOUS PROJECT SCAFFOLD",
        command: `@CruxAI scaffold ${promptText}`,
        lines: [
          { id: "1", text: "⚡ CruxAI Planner initialized. Analyzing project blueprint...", type: "info" },
        ],
        isRunning: true,
        isComplete: false,
      });

      setTimeout(() => {
        setTerminalStage((prev) => ({
          ...prev,
          lines: [
            ...prev.lines,
            { id: "2", text: "→ Creating src/app/dashboard/layout.tsx [TypeScript]", type: "info" },
            { id: "3", text: "→ Creating src/lib/telemetry.ts [Vector Invariants]", type: "info" },
            { id: "4", text: "→ Injecting Tailwind typography & brutalist 1px borders...", type: "dim" },
          ],
        }));
      }, 450);

      setTimeout(() => {
        setTerminalStage((prev) => ({
          ...prev,
          lines: [
            ...prev.lines,
            { id: "5", text: "✓ Generated 4 files with zero type errors in 72ms.", type: "success" },
            { id: "6", text: "● Vector clocks synchronized with mesh peers.", type: "success" },
          ],
          isRunning: false,
          isComplete: true,
        }));
        triggerHaptic("success");
      }, 1100);
    },
    [ensureIdentity]
  );

  // Construct Dynamic Suggestion Matrix
  const suggestions = useMemo<VoidSuggestion[]>(() => {
    const q = query.trim().toLowerCase();
    const raw = query.trim();

    // 1. If query is a URL or begins with git clone
    if (q.startsWith("http://") || q.startsWith("https://") || q.startsWith("git@") || q.startsWith("clone ")) {
      const url = raw.replace(/^clone\s+/i, "");
      return [
        {
          id: "s-clone-direct",
          category: "CLONE",
          title: `Clone Remote Repository`,
          description: url,
          commandSnippet: `clone ${url}`,
          badge: "GIT",
          action: () => executeClone(url),
        },
      ];
    }

    // 2. If query begins with @CruxAI or ai:
    if (q.startsWith("@cruxai") || q.startsWith("ai:") || q.startsWith("scaffold ")) {
      const prompt = raw.replace(/^(@cruxai|ai:|scaffold)\s*/i, "");
      return [
        {
          id: "s-ai-scaffold",
          category: "AGENT",
          title: `Scaffold Autonomous Project`,
          description: prompt || "Generate Next.js & TypeScript architecture",
          commandSnippet: `@CruxAI scaffold ${prompt || "dashboard"}`,
          badge: "AGENTIC",
          action: () => executeScaffold(prompt || "Next.js dashboard"),
        },
      ];
    }

    // 3. If query mentions canvas or nexus
    if (q === "canvas" || q === "nexus" || q === "spatial") {
      return [
        {
          id: "s-canvas-direct",
          category: "SPATIAL",
          title: "Launch Infinite Spatial Canvas",
          description: "Boot 2D spatial graph with draggable file nodes",
          commandSnippet: "open canvas",
          badge: "NEXUS",
          action: () => launchCanvas(),
        },
      ];
    }

    // Standard pre-filtered lists
    const allOptions: VoidSuggestion[] = [
      {
        id: "s-open-crux-core",
        category: "PROJECT",
        title: "Open crux-core",
        description: "Active collaborative workspace (3 peers online)",
        commandSnippet: "open crux-core",
        badge: "ACTIVE",
        action: () => launchIDE(),
      },
      {
        id: "s-agent-dashboard",
        category: "AGENT",
        title: "@CruxAI scaffold Next.js dashboard",
        description: "Autonomous live multi-file project generator",
        commandSnippet: "@CruxAI scaffold dashboard",
        badge: "AI CORE",
        action: () => executeScaffold("Next.js dashboard with brutalist design"),
      },
      {
        id: "s-clone-preset",
        category: "CLONE",
        title: "clone https://github.com/hrgang-hrushi/collab-editor",
        description: "Fetch and mount remote git workspace",
        commandSnippet: "clone collab-editor",
        badge: "GIT",
        action: () => executeClone("https://github.com/hrgang-hrushi/collab-editor.git"),
      },
      {
        id: "s-radar-marcus",
        category: "RADAR",
        title: "Drop-in: Marcus Vance",
        description: "Pair-program live on file-spatial.ts (Active)",
        commandSnippet: "connect Marcus",
        badge: "LIVE 42ms",
        action: () => {
          setActiveFile("file-spatial");
          launchIDE();
        },
      },
      {
        id: "s-spatial-canvas",
        category: "SPATIAL",
        title: "Open Infinite Spatial Canvas",
        description: "Spatial 2D graph with floating cards (Nexus Mode)",
        commandSnippet: "open canvas",
        badge: "NEXUS",
        action: () => launchCanvas(),
      },
      {
        id: "s-new-buffer",
        category: "NEW",
        title: "Create Scratchpad Buffer",
        description: "Instant empty buffer in Zenith editor",
        commandSnippet: "new untitled.ts",
        badge: "NEW",
        action: () => {
          createFile("untitled.ts");
          launchIDE();
        },
      },
    ];

    if (!q) return allOptions;

    return allOptions.filter(
      (opt) =>
        opt.title.toLowerCase().includes(q) ||
        opt.description.toLowerCase().includes(q) ||
        opt.commandSnippet.toLowerCase().includes(q) ||
        opt.category.toLowerCase().includes(q)
    );
  }, [query, executeClone, executeScaffold, launchCanvas, launchIDE, createFile, setActiveFile]);

  // Keep selected index in bounds
  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, suggestions.length));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + suggestions.length) % Math.max(1, suggestions.length));
    } else if (e.key === "Tab") {
      e.preventDefault();
      if (suggestions[selectedIndex]) {
        setQuery(suggestions[selectedIndex].commandSnippet);
      }
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (suggestions[selectedIndex]) {
        suggestions[selectedIndex].action();
      } else if (query.trim()) {
        // Raw command execution fallback
        if (query.toLowerCase().includes("clone")) {
          executeClone(query.replace(/^clone\s+/i, ""));
        } else if (query.toLowerCase().includes("canvas")) {
          launchCanvas();
        } else {
          launchIDE();
        }
      }
    }
  };

  return (
    <VoidCanvas>
      {/* 1. Top HUD Telemetry */}
      <VoidHUD
        onSelectPeer={(peerName, fileId) => {
          setActiveFile(fileId);
          launchIDE();
        }}
      />

      {/* 2. Centered Omnibar Void */}
      <div
        className={`relative z-10 flex-1 flex flex-col items-center justify-center p-4 transition-all duration-300 ${
          isShattering ? "scale-95 opacity-0 blur-sm" : "scale-100 opacity-100"
        }`}
      >
        <div className="w-full max-w-2xl flex flex-col items-center">
          {/* Header Identity Badge */}
          <div className="mb-4 flex items-center gap-2 select-none">
            <CruxBrandLogo size={20} withText={false} />
            <span className="font-mono text-xs text-[#888888] uppercase tracking-widest">
              CRUX // HYBRID EXECUTION MATRIX
            </span>
          </div>

          {/* If Terminal Stage is Active: show the in-place streaming terminal */}
          {terminalStage.active ? (
            <VoidTerminalStage
              title={terminalStage.title}
              command={terminalStage.command}
              lines={terminalStage.lines}
              isRunning={terminalStage.isRunning}
              isComplete={terminalStage.isComplete}
              onFinish={() => launchIDE()}
            />
          ) : (
            /* The Core Omnibar Container */
            <div className="w-full border border-[#222222] bg-[#050505] shadow-[0_0_50px_rgba(0,0,0,0.8)] transition-all">
              {/* Omnibar Input Row */}
              <div className="h-12 px-4 flex items-center gap-3 bg-[#030303]">
                <span className="font-mono text-base font-bold text-white select-none">
                  ❯
                </span>
                <input
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Type clone URL, @CruxAI prompt, project, or peer..."
                  className="flex-1 bg-transparent text-white font-mono text-sm placeholder:text-[#444444] focus:outline-none caret-white selection:bg-[#222222]"
                  spellCheck={false}
                  autoComplete="off"
                />
                {query && (
                  <button
                    onClick={() => setQuery("")}
                    className="text-xs font-mono text-[#555555] hover:text-white px-1.5 py-0.5 border border-[#222222]"
                  >
                    CLEAR
                  </button>
                )}
                <div className="hidden sm:flex items-center gap-1 font-mono text-[10px] text-[#444444]">
                  <span>EXEC</span>
                  <span className="px-1 border border-[#222222] text-[#888888]">↵</span>
                </div>
              </div>

              {/* Suggestions / Results Matrix */}
              <VoidSuggestionMatrix
                suggestions={suggestions}
                selectedIndex={selectedIndex}
                onSelectIndex={setSelectedIndex}
                onExecute={(item) => item.action()}
              />
            </div>
          )}
        </div>
      </div>

      {/* 3. Bottom Keystroke Keymap Bar */}
      <VoidKeymapBar />
    </VoidCanvas>
  );
}
