"use client";

import React, { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { useWorkspaceStore } from "@/lib/store";
import VoidCanvas from "./VoidCanvas";
import VoidHUD from "./VoidHUD";
import VoidKeymapBar from "./VoidKeymapBar";
import VoidSuggestionMatrix, { VoidSuggestion } from "./VoidSuggestionMatrix";
import VoidTerminalStage from "./VoidTerminalStage";
import { triggerHaptic } from "@/lib/haptics";

interface TerminalLine {
  id: string;
  text: string;
  isAgent?: boolean;
  agentTag?: string;
  isPeer?: boolean;
  peerTag?: string;
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

  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);

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
      if (terminalStage.active) return;

      if (e.key === "Escape") {
        e.preventDefault();
        setQuery("");
        return;
      }

      // If user presses Cmd+K, allow palette
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
        email: currentUser.email || "developer@crex.engine",
        uid: currentUser.uid || "CRX-7447-HG",
        password: "crex-hardware-lock",
        role: "Principal Developer",
        accessLevel: "full",
        isSelf: true,
      });
      setOnboarded(true);
    }
  }, [isOnboarded, currentUser, setUserProfile, setOnboarded]);

  // Launch into Crex Zenith IDE
  const launchIDE = useCallback(() => {
    ensureIdentity();
    triggerHaptic("click");
    setZeroStateOpen(false);
  }, [ensureIdentity, setZeroStateOpen]);

  // Launch into Spatial Canvas (Nexus Mode)
  const launchCanvas = useCallback(() => {
    ensureIdentity();
    setMode("canvas");
    triggerHaptic("click");
    setZeroStateOpen(false);
  }, [ensureIdentity, setMode, setZeroStateOpen]);

  // Start clone streaming sequence
  const executeClone = useCallback(
    (repoUrl: string) => {
      ensureIdentity();
      triggerHaptic("click");
      setTerminalStage({
        active: true,
        title: "CREX_GIT_ENGINE",
        command: `git clone ${repoUrl}`,
        lines: [
          { id: "1", text: `→ RESOLVING_REMOTE: ${repoUrl}` },
          { id: "2", text: "→ ESTABLISHING TLS STREAM WITH EDGE CLUSTER..." },
        ],
        isRunning: true,
        isComplete: false,
      });

      setTimeout(() => {
        setTerminalStage((prev) => ({
          ...prev,
          lines: [
            ...prev.lines,
            { id: "3", text: "remote: Enumerating objects: 248, done." },
            { id: "4", text: "remote: Compressing objects: 100% (142/142), done." },
          ],
        }));
      }, 350);

      setTimeout(() => {
        setTerminalStage((prev) => ({
          ...prev,
          lines: [
            ...prev.lines,
            { id: "5", text: "Receiving objects: 100% (248/248), 1.24 MiB | 8.4 MiB/s, done." },
            { id: "6", text: "Resolving deltas: 100% (98/98), completed with 42 local objects." },
            { id: "7", text: "[OK] WORKSPACE MOUNTED TO MEMORY-MAPPED VIRTUAL DISK." },
          ],
          isRunning: false,
          isComplete: true,
        }));
        triggerHaptic("success");
      }, 900);
    },
    [ensureIdentity]
  );

  // Start @CrexAI scaffold streaming sequence
  const executeScaffold = useCallback(
    (promptText: string) => {
      ensureIdentity();
      triggerHaptic("click");
      setTerminalStage({
        active: true,
        title: "CREX_AGENTIC_KERNEL",
        command: `@CrexAI scaffold ${promptText}`,
        lines: [
          {
            id: "1",
            text: "INITIALIZING BARE-METAL COMPILER AGENT...",
            isAgent: true,
            agentTag: "[@CrexAI]",
          },
        ],
        isRunning: true,
        isComplete: false,
      });

      setTimeout(() => {
        setTerminalStage((prev) => ({
          ...prev,
          lines: [
            ...prev.lines,
            {
              id: "2",
              text: "→ Generating src/app/dashboard/layout.tsx [TypeScript AST]",
              isAgent: true,
              agentTag: "[@CrexAI]",
            },
            {
              id: "3",
              text: "→ Synthesizing hardware brutalist 1px grid boundaries",
              isAgent: true,
              agentTag: "[@CrexAI]",
            },
          ],
        }));
      }, 400);

      setTimeout(() => {
        setTerminalStage((prev) => ({
          ...prev,
          lines: [
            ...prev.lines,
            {
              id: "4",
              text: "[OK] 4 modules synthesized in 68ms. Vector clocks locked.",
              isAgent: true,
              agentTag: "[@CrexAI]",
            },
          ],
          isRunning: false,
          isComplete: true,
        }));
        triggerHaptic("success");
      }, 950);
    },
    [ensureIdentity]
  );

  // Construct Dynamic Suggestion Matrix
  const suggestions = useMemo<VoidSuggestion[]>(() => {
    const q = query.trim().toLowerCase();
    const raw = query.trim();

    // 1. If query is a URL or begins with clone
    if (q.startsWith("http://") || q.startsWith("https://") || q.startsWith("git@") || q.startsWith("clone ")) {
      const url = raw.replace(/^clone\s+/i, "");
      return [
        {
          id: "s-clone-direct",
          category: "CLONE",
          title: `Clone Remote Git Repository`,
          description: url,
          commandSnippet: `clone ${url}`,
          badge: "GIT",
          action: () => executeClone(url),
        },
      ];
    }

    // 2. If query begins with @CrexAI or ai:
    if (q.startsWith("@crexai") || q.startsWith("@cruxai") || q.startsWith("ai:") || q.startsWith("scaffold ")) {
      const prompt = raw.replace(/^(@crexai|@cruxai|ai:|scaffold)\s*/i, "");
      return [
        {
          id: "s-ai-scaffold",
          category: "AGENT",
          title: `Scaffold Bare-Metal Project`,
          description: prompt || "Synthesize Next.js & TypeScript Architecture",
          commandSnippet: `@CrexAI scaffold ${prompt || "dashboard"}`,
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
          title: "Boot Infinite Spatial Canvas",
          description: "2D spatial graph with draggable file nodes",
          commandSnippet: "open canvas",
          badge: "NEXUS",
          action: () => launchCanvas(),
        },
      ];
    }

    const allOptions: VoidSuggestion[] = [
      {
        id: "s-open-crux-core",
        category: "PROJECT",
        title: "Mount crux-core",
        description: "Active collaborative workspace (3 peers online)",
        commandSnippet: "open crux-core",
        badge: "ACTIVE",
        action: () => launchIDE(),
      },
      {
        id: "s-agent-dashboard",
        category: "AGENT",
        title: "@CrexAI scaffold Next.js dashboard",
        description: "Autonomous live machine code synthesizer",
        commandSnippet: "@CrexAI scaffold dashboard",
        badge: "AI CORE",
        action: () => executeScaffold("Next.js dashboard with hardware brutalist tokens"),
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
        title: "Drop-in Spectate: Marcus Vance",
        description: "Pair-program live on file-spatial.ts",
        commandSnippet: "connect Marcus",
        badge: "PEER_LIVE",
        action: () => {
          setActiveFile("file-spatial");
          launchIDE();
        },
      },
      {
        id: "s-spatial-canvas",
        category: "SPATIAL",
        title: "Open Spatial Canvas Matrix",
        description: "Spatial 2D hardware desk (Nexus Mode)",
        commandSnippet: "open canvas",
        badge: "NEXUS",
        action: () => launchCanvas(),
      },
      {
        id: "s-new-buffer",
        category: "NEW",
        title: "Allocate Scratchpad Buffer",
        description: "Instant empty buffer in Zenith editor",
        commandSnippet: "new untitled.ts",
        badge: "BUFFER",
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
      {/* Top Telemetry Bar */}
      <VoidHUD
        onSelectPeer={(peerName, fileId) => {
          setActiveFile(fileId);
          launchIDE();
        }}
      />

      {/* Dead Center Omnibar Interface (Z-50) */}
      <div className="relative z-50 flex-1 flex flex-col items-center justify-center p-2">
        <div className="w-full max-w-2xl flex flex-col items-center">
          {/* Brand Display: Etna Sans Serif, tight tracking, heavy weight, solid fill */}
          <div className="mb-6 flex flex-col items-center select-none text-center">
            <h1 className="font-brand font-black text-white text-5xl -tracking-[0.05em] uppercase leading-none">
              CREX
            </h1>
            <span className="font-mono text-[10px] text-[#444444] uppercase tracking-[0.2em] mt-1">
              [BARE-METAL COLLABORATIVE EXECUTION KERNEL]
            </span>
          </div>

          {/* If Terminal Stage is Active: Show inline streaming terminal */}
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
            /* The Omnibar Blueprint: Dead Center, Arial MT Pro, text-2xl, border-b-2 border-white, no side/top borders */
            <div className="w-full border border-[#222222] bg-[#000000]">
              <div className="px-4 py-3 flex items-center gap-3 bg-[#000000] border-b-2 border-white">
                <span className="font-mono text-xl font-bold text-white select-none">
                  ❯
                </span>
                <input
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="[EXECUTE COMMAND...]"
                  className="flex-1 bg-transparent text-white font-sans text-2xl placeholder:text-[#444444] focus:outline-none caret-white selection:bg-[#222222]"
                  spellCheck={false}
                  autoComplete="off"
                />
                {query && (
                  <button
                    onClick={() => setQuery("")}
                    className="font-mono text-[11px] text-[#444444] hover:text-white px-2 py-0.5 border border-[#222222] hover:border-white transition-none uppercase"
                  >
                    [CLEAR]
                  </button>
                )}
                <div className="hidden sm:flex items-center gap-1 font-mono text-[10px] text-[#444444]">
                  <span>[ENTER]</span>
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

      {/* Bottom Keymap Bar */}
      <VoidKeymapBar />
    </VoidCanvas>
  );
}
