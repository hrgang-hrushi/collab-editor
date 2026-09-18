"use client";

import React, { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { useWorkspaceStore } from "@/lib/store";
import VoidCanvas from "./VoidCanvas";
import VoidHUD from "./VoidHUD";
import VoidKeymapBar from "./VoidKeymapBar";
import VoidSuggestionMatrix, { VoidSuggestion } from "./VoidSuggestionMatrix";
import VoidTerminalStage from "./VoidTerminalStage";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick, playMechanicalEnter } from "@/lib/sound";

interface TerminalLine {
  id: string;
  text: string;
  isAgent?: boolean;
  agentTag?: string;
  isPeer?: boolean;
  peerTag?: string;
}

type FilterCategory = "ALL" | "AGENT" | "CLONE" | "RADAR" | "SPATIAL";

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
  const [activeFilter, setActiveFilter] = useState<FilterCategory>("ALL");

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
        playMechanicalClick("low");
        setQuery("");
        return;
      }

      // Quick filter shortcuts: 1..5 if not focused or Alt+number
      if (e.altKey && ["1", "2", "3", "4", "5"].includes(e.key)) {
        e.preventDefault();
        playMechanicalClick("mid");
        const map: Record<string, FilterCategory> = {
          "1": "ALL",
          "2": "AGENT",
          "3": "CLONE",
          "4": "RADAR",
          "5": "SPATIAL",
        };
        setActiveFilter(map[e.key]);
        return;
      }

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
    playMechanicalEnter();
    triggerHaptic("click");
    setZeroStateOpen(false);
  }, [ensureIdentity, setZeroStateOpen]);

  // Launch into Spatial Canvas (Nexus Mode)
  const launchCanvas = useCallback(() => {
    ensureIdentity();
    setMode("canvas");
    playMechanicalEnter();
    triggerHaptic("click");
    setZeroStateOpen(false);
  }, [ensureIdentity, setMode, setZeroStateOpen]);

  // Start clone streaming sequence
  const executeClone = useCallback(
    (repoUrl: string) => {
      ensureIdentity();
      playMechanicalEnter();
      triggerHaptic("click");
      setTerminalStage({
        active: true,
        title: "CREX_GIT_ENGINE",
        command: `git clone ${repoUrl}`,
        lines: [
          { id: "1", text: `→ RESOLVING_REMOTE: ${repoUrl}` },
          { id: "2", text: "→ ESTABLISHING TLS STREAM WITH HARDWARE EDGE CLUSTERS..." },
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
      playMechanicalEnter();
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

  // Construct Dynamic Suggestion Matrix with Rich Preview Details
  const suggestions = useMemo<VoidSuggestion[]>(() => {
    const q = query.trim().toLowerCase();
    const raw = query.trim();

    // 1. Direct Git Clone URL
    if (q.startsWith("http://") || q.startsWith("https://") || q.startsWith("git@") || q.startsWith("clone ")) {
      const url = raw.replace(/^clone\s+/i, "");
      return [
        {
          id: "s-clone-direct",
          category: "CLONE",
          title: `Clone Remote Git Repository`,
          description: "Streams objects directly into virtual hardware mount",
          commandSnippet: `clone ${url}`,
          badge: "GIT",
          previewDetails: {
            type: "GIT_PROTOCOL",
            target: url,
            payload: `FETCH_HEAD -> refs/heads/main\nTRANSPORT: SSH / TLS 1.3\nVIRTUAL_INODE: /mnt/dev/collab`,
            meta: "PARALLEL_CHUNKS: 8 | ZERO_DISK_THROTTLE",
          },
          action: () => executeClone(url),
        },
      ];
    }

    // 2. Direct @CrexAI Scaffold Query
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
          previewDetails: {
            type: "NEURAL_SYNTHESIS",
            target: prompt || "Next.js Dashboard",
            payload: `AST_PLAN:\n  + app/dashboard/layout.tsx\n  + app/dashboard/page.tsx\n  + lib/hardware_bus.ts`,
            meta: "INFERENCE: LOCAL_EDGE | 240 TOKENS/S",
          },
          action: () => executeScaffold(prompt || "Next.js dashboard"),
        },
      ];
    }

    // 3. Direct Spatial Canvas Query
    if (q === "canvas" || q === "nexus" || q === "spatial") {
      return [
        {
          id: "s-canvas-direct",
          category: "SPATIAL",
          title: "Boot Infinite Spatial Canvas",
          description: "2D spatial graph with draggable file nodes",
          commandSnippet: "open canvas",
          badge: "NEXUS",
          previewDetails: {
            type: "SPATIAL_2D",
            target: "Nexus Canvas Matrix",
            payload: `GRAPH_NODES: 6 ACTIVE\nCONNECTIONS: 4 CONDUITS\nVIEWPORT: 100vw x 100vh INFINITE`,
            meta: "RENDERER: HARDWARE_ACCELERATED",
          },
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
        previewDetails: {
          type: "LOCAL_WORKSPACE",
          target: "~/projects/crux-core",
          payload: `ACTIVE_FILES:\n  • stream_syncer.ts\n  • database.ts\n  • auth.ts`,
          meta: "GIT: main* | 3 PEERS IN-SYNC",
        },
        action: () => launchIDE(),
      },
      {
        id: "s-agent-dashboard",
        category: "AGENT",
        title: "@CrexAI scaffold Next.js dashboard",
        description: "Autonomous live machine code synthesizer",
        commandSnippet: "@CrexAI scaffold dashboard",
        badge: "AI CORE",
        previewDetails: {
          type: "AUTONOMOUS_SCAFFOLD",
          target: "Next.js Bare-Metal Dashboard",
          payload: `GENERATING:\n  • app/dashboard/page.tsx\n  • components/telemetry/CpuDie.tsx\n  • tailwind.config.ts`,
          meta: "ZERO_DEPENDENCY_DRIFT",
        },
        action: () => executeScaffold("Next.js dashboard with hardware brutalist tokens"),
      },
      {
        id: "s-clone-preset",
        category: "CLONE",
        title: "clone https://github.com/hrgang-hrushi/collab-editor",
        description: "Fetch and mount remote git workspace",
        commandSnippet: "clone collab-editor",
        badge: "GIT",
        previewDetails: {
          type: "GIT_REMOTE",
          target: "https://github.com/hrgang-hrushi/collab-editor",
          payload: `ORIGIN: github.com:hrgang-hrushi/collab-editor\nBRANCH: main (ahead 1)\nDELTA: ZERO_CONFLICT`,
          meta: "SSL: TLS_AES_256_GCM_SHA384",
        },
        action: () => executeClone("https://github.com/hrgang-hrushi/collab-editor.git"),
      },
      {
        id: "s-radar-marcus",
        category: "RADAR",
        title: "Drop-in Spectate: Marcus Vance",
        description: "Pair-program live on file-spatial.ts",
        commandSnippet: "connect Marcus",
        badge: "PEER_LIVE",
        previewDetails: {
          type: "CRDT_MESH_PAIRING",
          target: "Marcus Vance (CRX-5520-MV)",
          payload: `// LIVE BUFFER: file-spatial.ts\nexport const Canvas = new InfiniteCanvas({\n  accelerated: true,\n  peerCount: 3\n});`,
          meta: "CURSOR: Ln 42, Col 18 | RTT: 0.04ms",
        },
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
        previewDetails: {
          type: "NEXUS_ENGINE",
          target: "Infinite Spatial Graph",
          payload: `MODES:\n  [E] Structured Editor\n  [C] Spatial Canvas (Active)\n  [T] HyperTerminal Split`,
          meta: "DRAG_SNAP: 16PX HARDWARE GRID",
        },
        action: () => launchCanvas(),
      },
      {
        id: "s-new-buffer",
        category: "NEW",
        title: "Allocate Scratchpad Buffer",
        description: "Instant empty buffer in Zenith editor",
        commandSnippet: "new untitled.ts",
        badge: "BUFFER",
        previewDetails: {
          type: "IN_MEMORY_BUFFER",
          target: "untitled.ts",
          payload: `// RAW BUFFER\nexport default function kernel() {\n  return "bare-metal";\n}`,
          meta: "ENCODING: UTF-8 | CRLF_STRIPPED",
        },
        action: () => {
          createFile("untitled.ts");
          launchIDE();
        },
      },
      {
        id: "s-start-board",
        category: "PROJECT",
        title: "Open Start Board // Identity Enclave",
        description: "Reconfigure cryptographic developer identity",
        commandSnippet: "start board",
        badge: "ENCLAVE",
        previewDetails: {
          type: "SECURITY_ENCLAVE",
          target: "Crux Start Board (Identity Setup)",
          payload: `NODE_KEY: Ed25519 Cryptographic Attestation\nROUTING: Mesh Peer Verification\nMEMORY: Ring-0 MMU Lock`,
          meta: "SECURITY: HARDWARE_LOCKED",
        },
        action: () => {
          setOnboarded(false);
        },
      },
    ];

    let filtered = allOptions;
    if (activeFilter !== "ALL") {
      filtered = filtered.filter((opt) => opt.category === activeFilter);
    }

    if (!q) return filtered;

    return filtered.filter(
      (opt) =>
        opt.title.toLowerCase().includes(q) ||
        opt.description.toLowerCase().includes(q) ||
        opt.commandSnippet.toLowerCase().includes(q) ||
        opt.category.toLowerCase().includes(q)
    );
  }, [query, activeFilter, executeClone, executeScaffold, launchCanvas, launchIDE, createFile, setActiveFile]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [query, activeFilter]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    playMechanicalClick(e.key === "Enter" ? "high" : "mid");

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
      playMechanicalEnter();
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

      {/* Main Omnibar Interface Deck (Z-50) */}
      <div className="relative z-50 flex-1 flex flex-col items-center justify-center p-4">
        <div className="w-full max-w-4xl flex flex-col items-center">
          {/* 1. Monolithic Industrial Brand Centerpiece */}
          <div className="mb-5 flex flex-col items-center select-none text-center">
            <div className="relative">
              <h1 className="font-brand font-black text-white text-7xl sm:text-8xl -tracking-[0.05em] leading-none select-none">
                Crux
              </h1>
              <div className="absolute -top-1 -right-3 text-[9px] font-mono text-[#444444] border border-[#222222] px-1 bg-[#000000]">
                v1.2
              </div>
            </div>

            {/* Hardware Telemetry Strip */}
            <div className="flex items-center gap-2 font-mono text-[9px] text-[#555555] uppercase mt-2 tracking-wider">
              <span>[KERNEL: RUNNING]</span>
              <span className="text-[#222222]">/</span>
              <span>[ARCH: BARE-METAL]</span>
              <span className="text-[#222222]">/</span>
              <span>[IPC: 0.04ms]</span>
              <span className="text-[#222222]">/</span>
              <span>[LOCK: ENCLAVE]</span>
            </div>
          </div>

          {/* 2. Tactical Mode Selector Ribbon (1..5) */}
          <div className="w-full flex items-center justify-between mb-2 font-mono text-[10px] select-none">
            <div className="flex items-center gap-1">
              {[
                { id: "ALL", label: "[1: ALL]" },
                { id: "AGENT", label: "[2: @CruxAI]" },
                { id: "CLONE", label: "[3: CLONE]" },
                { id: "RADAR", label: "[4: RADAR]" },
                { id: "SPATIAL", label: "[5: NEXUS]" },
              ].map((f) => (
                <button
                  key={f.id}
                  onClick={() => {
                    playMechanicalClick("low");
                    setActiveFilter(f.id as FilterCategory);
                  }}
                  className={`px-2 py-0.5 border transition-none uppercase ${
                    activeFilter === f.id
                      ? "border-white bg-white text-black font-bold"
                      : "border-[#222222] bg-[#000000] text-[#666666] hover:text-white hover:border-[#444444]"
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>

            <span className="text-[#333333] hidden sm:inline">
              ALT+[1-5] QUICK SWITCH
            </span>
          </div>

          {/* 3. The Omnibar Terminal Deck */}
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
            <div className="w-full border border-[#222222] bg-[#000000]">
              {/* Upper Ruler Calibrations */}
              <div className="h-2 border-b border-[#161616] bg-[#050505] flex items-center justify-between px-2 text-[6px] text-[#222222] font-mono select-none">
                <span>000</span>
                <span>||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||</span>
                <span>512</span>
              </div>

              {/* Central Mechanical Input Row */}
              <div className="px-4 py-3.5 flex items-center gap-3 bg-[#000000] border-b-2 border-white">
                <span className="font-brand font-black text-sm text-white select-none shrink-0 tracking-tight">
                  Crux ❯
                </span>
                <input
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={(e) => {
                    playMechanicalClick("mid");
                    setQuery(e.target.value);
                  }}
                  onKeyDown={handleKeyDown}
                  placeholder="[EXECUTE COMMAND: clone, @CruxAI, open, connect, canvas...]"
                  className="flex-1 bg-transparent text-white font-space text-xl sm:text-2xl placeholder:text-[#333333] focus:outline-none caret-white selection:bg-[#222222] tracking-tight"
                  spellCheck={false}
                  autoComplete="off"
                />
                <span className="crex-cursor shrink-0" />
                {query && (
                  <button
                    onClick={() => {
                      playMechanicalClick("low");
                      setQuery("");
                    }}
                    className="font-mono text-[10px] text-[#555555] hover:text-white px-2 py-0.5 border border-[#222222] hover:border-white transition-none uppercase"
                  >
                    [CLEAR]
                  </button>
                )}
                <div className="hidden sm:flex items-center gap-1 font-mono text-[10px] text-[#444444] shrink-0">
                  <span>DISPATCH</span>
                  <span className="px-1 border border-[#222222] text-white">[↵]</span>
                </div>
              </div>

              {/* Lower Ruler Calibrations */}
              <div className="h-2 border-b border-[#161616] bg-[#050505] flex items-center justify-between px-2 text-[6px] text-[#222222] font-mono select-none">
                <span>RAW_BUS</span>
                <span>------------------------------------------------------------------------------------------------------------------------</span>
                <span>INTERRUPT_0</span>
              </div>

              {/* Dual-Pane Suggestion & Telemetry Matrix */}
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
