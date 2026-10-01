"use client";

import React, { useState, useRef, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { CrexAiRouter, RouteConfig } from "@/lib/ai/aiRouter";
import { CruxAgentEngine, AgentStep, AgentDiffProposal } from "@/lib/agentEngine";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick } from "@/lib/sound";
import CruxAgentConfigModal from "./CruxAgentConfigModal";
import CruxAiModelDropdown from "./CruxAiModelDropdown";
import CruxAffinityMatrixModal from "../modals/CruxAffinityMatrixModal";
import { autoSyncEngine, SyncStatus } from "@/lib/autoSyncEngine";
import CruxAiProgress from "./CruxAiProgress";
import { BorderBeam } from "@/components/ui/BorderBeam";
import {
  Bot,
  Send,
  X,
  CornerDownLeft,
  GripHorizontal,
  Check,
  Code2,
  Terminal,
  Zap,
  Key,
  Settings,
  Sparkles,
  RotateCcw,
  Shield,
  Sliders,
  Play,
  HardDrive,
  RefreshCw,
  Cpu,
  Square,
} from "lucide-react";

interface HudMessage {
  id: string;
  role: "user" | "agent" | "system";
  content: string;
  provider?: string;
  model?: string;
  command?: string;
  fileAction?: {
    filename: string;
    content: string;
  };
  diffProposal?: AgentDiffProposal;
  timestamp: string;
}

interface CruxDualStateHudProps {
  isAnchorOpen: boolean;
  onCloseAnchor: () => void;
}

export default function CruxDualStateHud({
  isAnchorOpen,
  onCloseAnchor,
}: CruxDualStateHudProps) {
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const updateFileContent = useWorkspaceStore((state) => state.updateFileContent);
  const createFile = useWorkspaceStore((state) => state.createFile);
  const cursorPos = useWorkspaceStore((state) => state.cursorPos);
  const cursorScreenCoords = useWorkspaceStore((state) => state.cursorScreenCoords);
  const aiHudState = useWorkspaceStore((state) => state.aiHudState);
  const isDroneOpen = useWorkspaceStore((state) => state.isDroneOpen);
  const setAiHudState = useWorkspaceStore((state) => state.setAiHudState);
  const setIsDroneOpen = useWorkspaceStore((state) => state.setIsDroneOpen);

  const activeFile = files.find((f) => f.id === activeFileId) || null;

  // Active AI Provider info & Modals
  const [activeRoute, setActiveRoute] = useState<RouteConfig>(() => CrexAiRouter.getActiveRoute());
  const [inputVal, setInputVal] = useState("");
  const [isThinking, setIsThinking] = useState(false);
  const [currentSteps, setCurrentSteps] = useState<AgentStep[]>([]);
  const [isConfigModalOpen, setIsConfigModalOpen] = useState(false);
  const [isAffinityModalOpen, setIsAffinityModalOpen] = useState(false);
  const [aiMode, setAiMode] = useState<"agent" | "chat">("agent");
  const [syncStatus, setSyncStatus] = useState<SyncStatus>(() => autoSyncEngine.getStatus());
  const [appliedDiffIds, setAppliedDiffIds] = useState<Set<string>>(new Set());

  const [messages, setMessages] = useState<HudMessage[]>([
    {
      id: "init",
      role: "agent",
      content: "Crux AI Agent Kernel ready. Auto-synced with host silicon daemons & 100/100 Affinity Runtimes. Execute tasks, ask questions, or run terminal commands directly.",
      provider: "agy",
      command: "antigravity --version",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);

  // Subscribe to real-time auto-sync engine
  useEffect(() => {
    return autoSyncEngine.subscribe((status) => {
      setSyncStatus(status);
    });
  }, []);

  const runInTerminal = (command: string) => {
    triggerHaptic("click");
    playMechanicalClick("mid");
    if (typeof window !== "undefined") {
      window.dispatchEvent(
        new CustomEvent("crux:run-terminal", {
          detail: { command },
        })
      );
    }
  };

  // Drone Drag State
  const [dronePos, setDronePos] = useState<{ x: number; y: number }>({ x: 420, y: 140 });
  const isDraggingRef = useRef(false);
  const dragOffsetRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const droneInputRef = useRef<HTMLInputElement>(null);
  const anchorInputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Check if any messages currently have action widgets
  const hasActions = messages.some((m) => Boolean(m.fileAction || m.command || m.diffProposal));

  // Sync active route on mount and listen for config open event
  useEffect(() => {
    setActiveRoute(CrexAiRouter.getActiveRoute());

    const handleOpenConfig = () => setIsConfigModalOpen(true);
    const handleRouteChanged = () => setActiveRoute(CrexAiRouter.getActiveRoute());
    const handleResetChat = () => {
      setMessages([
        {
          id: "init",
          role: "agent",
          content: "Crux AI Agent Kernel reset. Ready for new prompt dispatch.",
          provider: "agy",
          command: "antigravity --version",
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ]);
      setInputVal("");
      setIsThinking(false);
      setCurrentSteps([]);
    };

    window.addEventListener("crux:open-agent-config", handleOpenConfig);
    window.addEventListener("crux:ai-route-changed", handleRouteChanged);
    window.addEventListener("crux:reset-ai-chat", handleResetChat);
    return () => {
      window.removeEventListener("crux:open-agent-config", handleOpenConfig);
      window.removeEventListener("crux:ai-route-changed", handleRouteChanged);
      window.removeEventListener("crux:reset-ai-chat", handleResetChat);
    };
  }, [isAnchorOpen, isDroneOpen]);

  // Position Drone at current text cursor coordinates on open
  useEffect(() => {
    if (isDroneOpen) {
      const screenW = typeof window !== "undefined" ? window.innerWidth : 1200;
      const screenH = typeof window !== "undefined" ? window.innerHeight : 800;

      // Spawn at cursor coordinates with boundary clamping
      const spawnX = Math.max(20, Math.min(cursorScreenCoords.x, screenW - 480));
      const spawnY = Math.max(60, Math.min(cursorScreenCoords.y + 12, screenH - 380));

      setDronePos({ x: spawnX, y: spawnY });
      setTimeout(() => droneInputRef.current?.focus(), 50);
    }
  }, [isDroneOpen, cursorScreenCoords]);

  // Scroll to latest message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, currentSteps, isThinking]);

  // Global Keyboard Listener for Cmd+K and Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Cmd+K or Ctrl+K: Toggle Drone at text cursor
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        playMechanicalClick("mid");
        triggerHaptic("toggle");

        if (isDroneOpen) {
          setIsDroneOpen(false);
        } else {
          setAiHudState("drone");
          setIsDroneOpen(true);
        }
        return;
      }

      // Escape: Stop running prompt first, or clear actions, or close drone
      if (e.key === "Escape") {
        if (isThinking) {
          e.preventDefault();
          handleStopPrompt();
          return;
        }

        if (hasActions) {
          e.preventDefault();
          handleRemoveActions();
          return;
        }

        if (isDroneOpen) {
          e.preventDefault();
          playMechanicalClick("low");
          setIsDroneOpen(false);
          return;
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isDroneOpen, setIsDroneOpen, setAiHudState, isThinking, hasActions]);

  // Drag listeners for Drone window
  const handleDragStart = (e: React.MouseEvent) => {
    isDraggingRef.current = true;
    dragOffsetRef.current = {
      x: e.clientX - dronePos.x,
      y: e.clientY - dronePos.y,
    };

    const handleMouseMove = (ev: MouseEvent) => {
      if (!isDraggingRef.current) return;
      const nextX = Math.max(10, Math.min(ev.clientX - dragOffsetRef.current.x, window.innerWidth - 460));
      const nextY = Math.max(48, Math.min(ev.clientY - dragOffsetRef.current.y, window.innerHeight - 150));
      setDronePos({ x: nextX, y: nextY });
    };

    const handleMouseUp = () => {
      isDraggingRef.current = false;
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
  };

  // Submit Prompt / Omnibar Route Command
  const handleSubmit = async (overrideText?: string) => {
    const text = (overrideText || inputVal).trim();
    if (!text || isThinking) return;

    playMechanicalClick("high");
    triggerHaptic("click");
    setInputVal("");

    const userMsg: HudMessage = {
      id: `usr-${Date.now()}`,
      role: "user",
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };
    setMessages((prev) => [...prev, userMsg]);

    // Handle terminal-style Omnibar command: `> route add [provider] [token/endpoint]`
    if (text.startsWith("> route") || text.startsWith("route ")) {
      const routeOutput = CrexAiRouter.handleOmnibarCommand(text);
      setActiveRoute(CrexAiRouter.getActiveRoute());

      setMessages((prev) => [
        ...prev,
        {
          id: `sys-${Date.now()}`,
          role: "system",
          content: routeOutput,
          provider: "crex-router",
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ]);
      return;
    }

    // Execute prompt through Agnostic AI Router
    const controller = new AbortController();
    abortControllerRef.current = controller;
    setIsThinking(true);
    setCurrentSteps([]);

    try {
      const response = await CrexAiRouter.executePrompt(
        text,
        {
          file: activeFile?.name || "stream_syncer.ts",
          line: cursorPos.line,
          history: messages.slice(-10).map((m) => ({
            role: m.role,
            content: m.content,
          })),
        },
        controller.signal
      );

      if (controller.signal.aborted) return;

      // Speculative diff engine: only generate diff if modifying an existing file or prompt demands it
      let diffProposal: AgentDiffProposal | undefined = undefined;
      const lower = text.toLowerCase();
      const isNewProjectOrFile =
        lower.includes("new project") ||
        lower.includes("start writing") ||
        lower.includes("clean up") ||
        lower.includes("clean the") ||
        lower.includes("create file") ||
        lower.includes("new file");

      if (response.fileAction) {
        // If fileAction matches an existing file in workspace with changed content, show diff
        const existingFile = files.find(
          (f) =>
            f.name.toLowerCase() === response.fileAction!.filename.toLowerCase() ||
            f.path.toLowerCase() === response.fileAction!.filename.toLowerCase()
        );
        if (existingFile && existingFile.content.trim() !== response.fileAction.content.trim()) {
          diffProposal = {
            fileId: existingFile.id,
            filePath: existingFile.path || existingFile.name,
            fileName: existingFile.name,
            originalContent: existingFile.content,
            proposedContent: response.fileAction.content,
            diffSummary: `Patch generated for ${existingFile.name}`,
            explanation: `Autonomous update for ${existingFile.name} with verified syntax and auto-sync readiness.`,
          };
        }
      } else if (
        !isNewProjectOrFile &&
        activeFile &&
        (aiMode === "agent" || lower.includes("fix") || lower.includes("refactor") || lower.includes("optimize") || lower.includes("test"))
      ) {
        const agentResult = await CruxAgentEngine.executeTask(
          { prompt: text, activeFile, allFiles: files },
          (steps) => {
            if (!controller.signal.aborted) setCurrentSteps(steps);
          }
        );
        diffProposal = agentResult.diffProposal;
      }

      if (controller.signal.aborted) return;

      setCurrentSteps([]);
      setMessages((prev) => [
        ...prev,
        {
          id: `agt-${Date.now()}`,
          role: "agent",
          content: response.text,
          provider: response.provider,
          model: response.model,
          command: response.command,
          fileAction: response.fileAction,
          diffProposal,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ]);
      triggerHaptic("success");
    } catch (err: any) {
      if (controller.signal.aborted || err?.message?.includes("stopped by user")) {
        return;
      }
      setCurrentSteps([]);
      setMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          role: "agent",
          content: `Router execution failed: ${err?.message || "Unknown error"}`,
          provider: activeRoute.provider,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ]);
    } finally {
      abortControllerRef.current = null;
      setIsThinking(false);
    }
  };

  // Stop / Escape running prompt
  const handleStopPrompt = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setIsThinking(false);
    setCurrentSteps([]);
    playMechanicalClick("low");
    triggerHaptic("toggle");
    setMessages((prev) => [
      ...prev,
      {
        id: `stop-${Date.now()}`,
        role: "system",
        content: "[HALTED] Prompt execution stopped by user (ESC).",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      },
    ]);
  };

  // Remove/Dismiss all action cards & proposals (file action, terminal run, diff proposal)
  const handleRemoveActions = () => {
    playMechanicalClick("low");
    triggerHaptic("tap");
    setMessages((prev) =>
      prev.map((m) => ({
        ...m,
        fileAction: undefined,
        command: undefined,
        diffProposal: undefined,
      }))
    );
  };

  const handleApplyDiff = (diff: AgentDiffProposal) => {
    triggerHaptic("success");
    playMechanicalClick("high");
    updateFileContent(diff.fileId, diff.proposedContent);
    setActiveFile(diff.fileId);
    openTab(diff.fileId);
    // Explicit immediate flush to disk via autoSyncEngine
    const targetPath = diff.filePath || diff.fileName;
    autoSyncEngine.enqueue(diff.fileName, targetPath, diff.proposedContent, true);
    setAppliedDiffIds((prev) => new Set([...prev, diff.fileId]));
  };

  const handleCreateFileAction = (filename: string, content: string) => {
    triggerHaptic("success");
    playMechanicalClick("high");
    const existing = files.find(
      (f) =>
        f.name.toLowerCase() === filename.toLowerCase() ||
        f.path.toLowerCase() === filename.toLowerCase()
    );
    if (existing) {
      updateFileContent(existing.id, content);
      setActiveFile(existing.id);
      openTab(existing.id);
      const targetPath = existing.path || filename;
      autoSyncEngine.enqueue(filename, targetPath, content, true);
    } else {
      createFile(filename, content);
      const isRootFile = filename === "index.html" || filename === "package.json" || filename === "README.md" || filename.includes("/");
      const targetPath = isRootFile ? filename : `src/${filename}`;
      autoSyncEngine.enqueue(filename, targetPath, content, true);
    }
  };

  const resetChat = () => {
    playMechanicalClick("low");
    triggerHaptic("tap");
    setMessages([
      {
        id: "init",
        role: "agent",
        content: "Crux AI Agent Kernel reset. Conversation memory cleared. Ready for new instructions.",
        provider: activeRoute.provider,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      },
    ]);
  };

  // Switch to Drone
  const switchToDrone = () => {
    playMechanicalClick("mid");
    onCloseAnchor();
    setAiHudState("drone");
    setIsDroneOpen(true);
  };

  // Dock to Anchor
  const dockToAnchor = () => {
    playMechanicalClick("mid");
    setIsDroneOpen(false);
    setAiHudState("anchor");
  };

  /* ──────────────────────────────────────────────────────────────────────────
     STATE B: THE DRONE (FLOATING, DRAGGABLE EXECUTION WINDOW OVER TEXT BUFFER)
     Strictly 0px border radius, 1px solid #FFFFFF, unblurred hard shadow 4px 4px 0px #111111
  ────────────────────────────────────────────────────────────────────────── */
  const renderDrone = () => {
    if (!isDroneOpen) return null;

    return (
      <div
        style={{
          position: "fixed",
          left: `${dronePos.x}px`,
          top: `${dronePos.y}px`,
          width: "480px",
          maxHeight: "560px",
          zIndex: 9999,
          borderRadius: "0px",
          border: "1px solid #FFFFFF",
          backgroundColor: "#000000",
          boxShadow: "4px 4px 0px #111111",
          userSelect: "none",
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
        }}
        className="flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-100"
      >
        {/* Drone Drag Handle & Top Bar */}
        <div
          onMouseDown={handleDragStart}
          className="h-8 px-2.5 bg-[#111111] border-b border-[#222222] flex items-center justify-between cursor-move select-none shrink-0"
        >
          <div className="flex items-center gap-2">
            <GripHorizontal className="w-3.5 h-3.5 text-[#666666]" />
            <span className="font-mono text-[10px] font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-[#00FF66]" />
              CRUX_AI_AGENT // DRONE
            </span>
          </div>

          <div className="flex items-center gap-1">
            {/* Auto-Sync Indicator */}
            <span
              className={`px-1.5 py-0.5 text-[8.5px] font-mono uppercase tracking-wider border ${
                syncStatus.state === "syncing"
                  ? "bg-[#222200] text-[#FFFF00] border-[#FFFF00]"
                  : "bg-[#050505] text-[#00FF66] border-[#222222]"
              }`}
              title="Universal Background Auto-Sync to Disk (0.04ms)"
            >
              SYNC: {syncStatus.latencyMs}ms
            </span>

            <button
              type="button"
              onClick={dockToAnchor}
              title="Dock to sidebar"
              className="px-1.5 py-0.5 text-[9px] font-mono uppercase bg-void hover:bg-white hover:text-black border border-[#222222] transition-none text-[#888888] cursor-pointer"
            >
              Dock ↙
            </button>
            <button
              type="button"
              onClick={() => setIsDroneOpen(false)}
              title="Close (Esc)"
              className="p-1 hover:bg-white hover:text-black transition-none text-[#888888] cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* AI Model Dropdown Header */}
        <div className="p-1.5 bg-[#080808] border-b border-[#222222] flex items-center gap-1.5 shrink-0">
          <div className="flex-1 min-w-0">
            <CruxAiModelDropdown
              compact
              onOpenAffinityMatrix={() => setIsAffinityModalOpen(true)}
              onOpenConfig={() => setIsConfigModalOpen(true)}
            />
          </div>

          {/* Mode Switch: AGENT vs CHAT */}
          <div className="flex items-center border border-[#222222] shrink-0">
            <button
              type="button"
              onClick={() => {
                setAiMode("agent");
                playMechanicalClick("low");
              }}
              className={`px-2 py-1 text-[9px] font-mono font-bold uppercase transition-none cursor-pointer ${
                aiMode === "agent" ? "bg-white text-black" : "bg-black text-[#666666] hover:text-white"
              }`}
              title="Agent Mode: Autonomous multi-file diffs & terminal commands"
            >
              AGENT
            </button>
            <button
              type="button"
              onClick={() => {
                setAiMode("chat");
                playMechanicalClick("low");
              }}
              className={`px-2 py-1 text-[9px] font-mono font-bold uppercase transition-none cursor-pointer ${
                aiMode === "chat" ? "bg-white text-black" : "bg-black text-[#666666] hover:text-white"
              }`}
              title="Chat Mode: Fast conversational coding Q&A"
            >
              CHAT
            </button>
          </div>

          <button
            type="button"
            onClick={resetChat}
            title="Reset Conversation"
            className="p-1.5 border border-[#222222] bg-[#0A0A0A] hover:bg-white hover:text-black text-[#888888] transition-none cursor-pointer shrink-0"
          >
            <RotateCcw className="w-3 h-3" />
          </button>
        </div>

        {/* Message Log */}
        <div className="flex-1 p-3 overflow-y-auto space-y-2 max-h-[300px] bg-void font-sans text-xs">
          {messages.map((m) => (
            <div
              key={m.id}
              className={`p-2.5 border ${
                m.role === "user"
                  ? "border-white bg-[#111111] text-white"
                  : m.role === "system"
                  ? "border-[#444444] bg-[#050505] text-[#AAAAAA] font-mono text-[11px] whitespace-pre-wrap"
                  : "border-[#222222] bg-[#0A0A0A] text-[#EEEEEE]"
              }`}
            >
              <div className="flex items-center justify-between text-[9px] font-mono text-[#666666] mb-1">
                <span className="font-bold">
                  {m.role === "user" ? "USER" : m.provider ? `AI // ${m.provider.toUpperCase()}` : "CREX_AI"}
                </span>
                <span>{m.timestamp}</span>
              </div>
              <div className="leading-relaxed select-text whitespace-pre-wrap">{m.content}</div>

              {/* Terminal Command Proposal */}
              {(m.command || m.content.match(/\[Suggested Terminal Command\]:\s*`([^`]+)`/)?.[1]) && (
                <div className="mt-2 pt-2 border-t border-[#222222] flex items-center justify-between">
                  <span className="font-mono text-[9px] text-[#888888] truncate max-w-[240px]">
                    cmd: {m.command || m.content.match(/\[Suggested Terminal Command\]:\s*`([^`]+)`/)?.[1]}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      runInTerminal(m.command || m.content.match(/\[Suggested Terminal Command\]:\s*`([^`]+)`/)?.[1] || "")
                    }
                    className="px-2 py-1 bg-white text-black font-mono font-bold text-[9px] uppercase hover:bg-[#CCCCCC] transition-none flex items-center gap-1 cursor-pointer"
                  >
                    <Terminal className="w-2.5 h-2.5" />
                    <span>RUN IN TERMINAL ↵</span>
                  </button>
                </div>
              )}

              {/* File Creation Proposal */}
              {m.fileAction && (
                <div className="mt-2 pt-2 border-t border-[#222222] flex items-center justify-between">
                  <span className="font-mono text-[9px] text-[#00FF66] truncate max-w-[240px]">
                    file: {m.fileAction.filename}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCreateFileAction(m.fileAction!.filename, m.fileAction!.content)}
                    className="px-2 py-1 bg-white text-black font-mono font-bold text-[9px] uppercase hover:bg-[#CCCCCC] transition-none flex items-center gap-1 cursor-pointer"
                  >
                    <HardDrive className="w-2.5 h-2.5" />
                    <span>SAVE &amp; AUTO-SYNC ↵</span>
                  </button>
                </div>
              )}

              {/* Speculative Diff Proposal */}
              {m.diffProposal && (
                <div className="mt-2 pt-2 border-t border-[#222222]">
                  <div className="text-[10px] font-mono text-white font-bold mb-1 flex items-center justify-between">
                    <span>DIFF: {m.diffProposal.fileName}</span>
                    <span className="text-[9px] text-[#00FF66] uppercase">READY</span>
                  </div>
                  <pre className="p-1.5 bg-[#050505] border border-[#222222] font-mono text-[10px] overflow-x-auto text-[#00FF66] max-h-32">
                    {m.diffProposal.proposedContent}
                  </pre>
                  <div className="mt-1.5 flex items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={() => handleApplyDiff(m.diffProposal!)}
                      disabled={appliedDiffIds.has(m.diffProposal.fileId)}
                      className={`px-2.5 py-1 font-mono font-bold uppercase text-[9px] transition-none flex items-center gap-1.5 cursor-pointer ${
                        appliedDiffIds.has(m.diffProposal.fileId)
                          ? "bg-[#00FF66] text-black"
                          : "bg-white text-black hover:bg-[#CCCCCC]"
                      }`}
                    >
                      <Check className="w-3 h-3 stroke-[3]" />
                      <span>
                        {appliedDiffIds.has(m.diffProposal.fileId)
                          ? "✓ APPLIED & SYNCED TO DISK"
                          : "ACCEPT & AUTO-SYNC TO DISK ↵"}
                      </span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}

          {isThinking && (
            <div className="flex items-stretch gap-2">
              <CruxAiProgress steps={currentSteps} layout="float" provider={activeRoute.provider} />
              <button
                type="button"
                onClick={handleStopPrompt}
                className="self-start px-2 py-0.5 border border-[#444444] bg-black hover:bg-white hover:text-black text-white font-mono text-[9px] font-bold uppercase transition-none cursor-pointer flex items-center gap-1"
                title="Stop execution (Esc)"
              >
                <Square className="w-2.5 h-2.5 fill-current" />
                <span>STOP [ESC]</span>
              </button>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Action Clearance Strip (If actions are present) */}
        {hasActions && (
          <div className="px-2 py-1 bg-[#050505] border-t border-[#222222] flex items-center justify-between text-[9px] font-mono">
            <span className="text-[#666666]">PROPOSED ACTIONS ACTIVE</span>
            <button
              type="button"
              onClick={handleRemoveActions}
              className="px-1.5 py-0.5 border border-[#222222] bg-[#0A0A0A] hover:bg-white hover:text-black text-[#AAAAAA] transition-none cursor-pointer flex items-center gap-1"
              title="Remove/Dismiss all action cards (Esc)"
            >
              <X className="w-2.5 h-2.5" />
              <span>REMOVE ACTIONS (ESC)</span>
            </button>
          </div>
        )}

        {/* Input Bar */}
        <div className="p-2 bg-[#050505] border-t border-[#222222] flex items-center gap-2">
          <BorderBeam
            size="md"
            colorVariant="ocean"
            strength={0.85}
            theme="dark"
            active={true}
            borderRadius={0}
            className="flex-1 relative"
          >
            <input
              ref={droneInputRef}
              type="text"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSubmit();
                if (e.key === "Escape") {
                  if (isThinking) {
                    e.preventDefault();
                    handleStopPrompt();
                  } else if (hasActions) {
                    e.preventDefault();
                    handleRemoveActions();
                  } else {
                    setIsDroneOpen(false);
                  }
                }
              }}
              placeholder={`Ask AI or configure '> route add [provider] [token]'...`}
              className="w-full bg-void border border-[#222222] px-2 py-1.5 text-xs text-white placeholder:text-[#555555] font-mono focus:border-white focus:outline-none rounded-none transition-none block"
            />
          </BorderBeam>
          {isThinking ? (
            <button
              type="button"
              onClick={handleStopPrompt}
              className="px-3 py-1.5 bg-[#FF3333] hover:bg-[#FF5555] text-white font-mono font-bold uppercase text-xs transition-none shrink-0 cursor-pointer flex items-center gap-1"
              title="Stop running prompt (Esc)"
            >
              <Square className="w-3 h-3 fill-current" />
              <span>STOP [ESC]</span>
            </button>
          ) : (
            <button
              onClick={() => handleSubmit()}
              disabled={!inputVal.trim()}
              className="px-3 py-1.5 bg-white text-black font-bold uppercase text-xs hover:bg-[#CCCCCC] disabled:opacity-40 transition-none shrink-0 cursor-pointer"
            >
              <Send className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* Footer Meta */}
        <div className="h-5 px-2 bg-[#111111] border-t border-[#222222] flex items-center justify-between text-[9px] font-mono text-[#666666]">
          <span>CONTEXT: {activeFile?.name || "none"}:{cursorPos.line}</span>
          {isThinking ? (
            <span className="text-[#FF4444] font-bold">PRESS ESC TO STOP PROMPT</span>
          ) : hasActions ? (
            <span className="text-[#888888]">PRESS ESC TO REMOVE ACTIONS</span>
          ) : (
            <span>PRESS ESC TO CLOSE</span>
          )}
        </div>
      </div>
    );
  };

  /* ──────────────────────────────────────────────────────────────────────────
     STATE A: THE ANCHOR (FIXED RIGHT-SIDE PANEL OCCUPYING 30% OF VIEWPORT)
     Separated by 1px #222222 border, flush brutalist container
  ────────────────────────────────────────────────────────────────────────── */
  const renderAnchor = () => {
    if (!isAnchorOpen) return null;

    return (
      <aside
        style={{
          width: "30vw",
          minWidth: "320px",
          height: "100%",
          borderLeft: "1px solid #222222",
          backgroundColor: "#000000",
          borderRadius: "0px",
          display: "flex",
          flexDirection: "column",
          userSelect: "none",
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
        }}
        className="shrink-0 z-30 relative transition-none"
      >
        {/* Anchor Top Header */}
        <div className="h-9 px-3 border-b border-[#222222] bg-[#0A0A0A] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 bg-void border border-white flex items-center justify-center text-white">
              <Bot className="w-3 h-3 text-white" />
            </div>
            <span className="font-mono text-xs font-bold text-white uppercase tracking-wider">
              AI Assistant
            </span>
            <span
              className={`px-1.5 py-0.2 text-[8.5px] font-mono uppercase tracking-wider border ${
                syncStatus.state === "syncing"
                  ? "bg-[#222200] text-[#FFFF00] border-[#FFFF00]"
                  : "bg-[#050505] text-[#00FF66] border-[#222222]"
              }`}
              title="Universal Background Auto-Sync to Disk (0.04ms)"
            >
              SYNC: {syncStatus.latencyMs}ms
            </span>
          </div>

          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={resetChat}
              title="Reset Chat Memory"
              className="p-1 text-[#666666] hover:text-white border border-[#222222] hover:bg-white hover:text-black transition-none cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" />
            </button>
            <button
              type="button"
              onClick={switchToDrone}
              title="Pop out to floating drone (Cmd+K)"
              className="p-1 text-[#666666] hover:text-white border border-[#222222] hover:bg-white hover:text-black transition-none cursor-pointer"
            >
              <Zap className="w-3 h-3" />
            </button>
            <button
              type="button"
              onClick={() => {
                playMechanicalClick("low");
                onCloseAnchor();
              }}
              title="Close panel"
              className="p-1 text-[#666666] hover:text-white border border-[#222222] hover:bg-white hover:text-black transition-none cursor-pointer"
            >
              <X className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* AI Model Dropdown Header Strip */}
        <div className="p-2 bg-[#050505] border-b border-[#222222] flex items-center gap-1.5 shrink-0">
          <div className="flex-1 min-w-0">
            <CruxAiModelDropdown
              onOpenAffinityMatrix={() => setIsAffinityModalOpen(true)}
              onOpenConfig={() => setIsConfigModalOpen(true)}
            />
          </div>

          {/* Mode Switch: AGENT vs CHAT */}
          <div className="flex items-center border border-[#222222] shrink-0">
            <button
              type="button"
              onClick={() => {
                setAiMode("agent");
                playMechanicalClick("low");
              }}
              className={`px-2 py-1.5 text-[9px] font-mono font-bold uppercase transition-none cursor-pointer ${
                aiMode === "agent" ? "bg-white text-black" : "bg-black text-[#666666] hover:text-white"
              }`}
              title="Agent Mode: Autonomous multi-file diffs & terminal commands"
            >
              AGENT
            </button>
            <button
              type="button"
              onClick={() => {
                setAiMode("chat");
                playMechanicalClick("low");
              }}
              className={`px-2 py-1.5 text-[9px] font-mono font-bold uppercase transition-none cursor-pointer ${
                aiMode === "chat" ? "bg-white text-black" : "bg-black text-[#666666] hover:text-white"
              }`}
              title="Chat Mode: Fast conversational coding Q&A"
            >
              CHAT
            </button>
          </div>
        </div>

        {/* Active Context Banner */}
        <div className="px-3 py-1.5 bg-[#050505] border-b border-[#222222] flex items-center justify-between text-[10px] font-mono text-[#888888]">
          <div className="flex items-center gap-1 truncate">
            <Code2 className="w-3 h-3 text-signal" />
            <span className="text-white">{activeFile?.name || "stream_syncer.ts"}</span>
            <span>:{cursorPos.line}</span>
          </div>
          <span className="text-[#666666]">30% VIEWPORT</span>
        </div>

        {/* Messages Stream */}
        <div className="flex-1 p-3 overflow-y-auto space-y-2 bg-void font-sans text-xs">
          {messages.map((m) => (
            <div
              key={m.id}
              className={`p-2.5 border ${
                m.role === "user"
                  ? "border-white bg-[#111111] text-white"
                  : m.role === "system"
                  ? "border-[#333333] bg-[#050505] text-[#AAAAAA] font-mono text-[11px] whitespace-pre-wrap"
                  : "border-[#222222] bg-[#0A0A0A] text-[#EEEEEE]"
              }`}
            >
              <div className="flex items-center justify-between text-[9px] font-mono text-[#666666] mb-1">
                <span className="font-bold">
                  {m.role === "user" ? "USER" : m.provider ? `AI // ${m.provider.toUpperCase()}` : "CREX_AI"}
                </span>
                <span>{m.timestamp}</span>
              </div>
              <div className="leading-relaxed select-text whitespace-pre-wrap">{m.content}</div>

              {/* Terminal Command Proposal */}
              {(m.command || m.content.match(/\[Suggested Terminal Command\]:\s*`([^`]+)`/)?.[1]) && (
                <div className="mt-2 pt-2 border-t border-[#222222] flex items-center justify-between">
                  <span className="font-mono text-[9px] text-[#888888] truncate max-w-[180px]">
                    cmd: {m.command || m.content.match(/\[Suggested Terminal Command\]:\s*`([^`]+)`/)?.[1]}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      runInTerminal(m.command || m.content.match(/\[Suggested Terminal Command\]:\s*`([^`]+)`/)?.[1] || "")
                    }
                    className="px-2 py-0.5 bg-white text-black font-mono font-bold text-[9px] uppercase hover:bg-[#CCCCCC] transition-none flex items-center gap-1 cursor-pointer"
                  >
                    <Terminal className="w-2.5 h-2.5" />
                    <span>RUN IN TERMINAL ↵</span>
                  </button>
                </div>
              )}

              {/* File Creation Proposal */}
              {m.fileAction && (
                <div className="mt-2 pt-2 border-t border-[#222222] flex items-center justify-between">
                  <span className="font-mono text-[9px] text-[#00FF66] truncate max-w-[180px]">
                    file: {m.fileAction.filename}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCreateFileAction(m.fileAction!.filename, m.fileAction!.content)}
                    className="px-2 py-0.5 bg-white text-black font-mono font-bold text-[9px] uppercase hover:bg-[#CCCCCC] transition-none flex items-center gap-1 cursor-pointer"
                  >
                    <HardDrive className="w-2.5 h-2.5" />
                    <span>SAVE &amp; AUTO-SYNC ↵</span>
                  </button>
                </div>
              )}

              {/* Speculative Diff Proposal */}
              {m.diffProposal && (
                <div className="mt-2.5 pt-2 border-t border-[#222222]">
                  <div className="text-[10px] font-mono text-signal mb-1.5 flex items-center justify-between">
                    <span>SPECULATIVE PATCH ({m.diffProposal.fileName})</span>
                    <span className="text-[#00FF66] font-bold">READY</span>
                  </div>
                  <pre className="p-2 bg-black border border-[#222222] font-mono text-[10px] overflow-x-auto text-[#00FF66] max-h-40">
                    {m.diffProposal.proposedContent}
                  </pre>
                  <button
                    onClick={() => handleApplyDiff(m.diffProposal!)}
                    disabled={appliedDiffIds.has(m.diffProposal.fileId)}
                    className={`mt-2 w-full py-1.5 font-bold uppercase text-[10px] transition-none flex items-center justify-center gap-1.5 cursor-pointer ${
                      appliedDiffIds.has(m.diffProposal.fileId)
                        ? "bg-[#00FF66] text-black"
                        : "bg-white text-black hover:bg-[#CCCCCC]"
                    }`}
                  >
                    <Check className="w-3.5 h-3.5 text-black stroke-[3]" />
                    <span>
                      {appliedDiffIds.has(m.diffProposal.fileId)
                        ? "✓ APPLIED & SYNCED TO DISK"
                        : "ACCEPT PATCH & AUTO-SYNC TO DISK ↵"}
                    </span>
                  </button>
                </div>
              )}
            </div>
          ))}

          {isThinking && (
            <div className="flex items-stretch gap-2">
              <CruxAiProgress steps={currentSteps} layout="dock" provider={activeRoute.provider} />
              <button
                type="button"
                onClick={handleStopPrompt}
                className="self-start px-2.5 py-1 border border-[#444444] bg-black hover:bg-white hover:text-black text-white font-mono text-[9px] font-bold uppercase transition-none cursor-pointer flex items-center gap-1"
                title="Stop prompt execution (Esc)"
              >
                <Square className="w-2.5 h-2.5 fill-current" />
                <span>STOP [ESC]</span>
              </button>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Action Clearance Strip (If actions are present) */}
        {hasActions && (
          <div className="px-3 py-1.5 bg-[#050505] border-t border-[#222222] flex items-center justify-between text-[9px] font-mono">
            <span className="text-[#666666]">PROPOSED ACTIONS ACTIVE</span>
            <button
              type="button"
              onClick={handleRemoveActions}
              className="px-2 py-0.5 border border-[#222222] bg-[#0A0A0A] hover:bg-white hover:text-black text-[#AAAAAA] transition-none cursor-pointer flex items-center gap-1"
              title="Remove/Dismiss all action cards (Esc)"
            >
              <X className="w-2.5 h-2.5" />
              <span>REMOVE ACTIONS (ESC)</span>
            </button>
          </div>
        )}

        {/* Input Dock */}
        <div className="p-3 bg-[#0A0A0A] border-t border-[#222222] space-y-2">
          <div className="flex items-center gap-2">
            <BorderBeam
              size="md"
              colorVariant="ocean"
              strength={0.85}
              theme="dark"
              active={true}
              borderRadius={0}
              className="flex-1 relative"
            >
              <input
                ref={anchorInputRef}
                type="text"
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSubmit();
                  if (e.key === "Escape") {
                    if (isThinking) {
                      e.preventDefault();
                      handleStopPrompt();
                    } else if (hasActions) {
                      e.preventDefault();
                      handleRemoveActions();
                    }
                  }
                }}
                placeholder="Prompt AI or enter '> route add [provider] [token]'..."
                className="w-full bg-void border border-[#222222] px-3 py-2 text-xs text-white placeholder:text-[#555555] font-mono focus:border-white focus:outline-none rounded-none transition-none block"
              />
            </BorderBeam>
            {isThinking ? (
              <button
                type="button"
                onClick={handleStopPrompt}
                className="px-3.5 py-2 bg-[#FF3333] hover:bg-[#FF5555] text-white font-mono font-bold uppercase text-xs transition-none shrink-0 cursor-pointer flex items-center gap-1.5"
                title="Stop running prompt (Esc)"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>STOP [ESC]</span>
              </button>
            ) : (
              <button
                onClick={() => handleSubmit()}
                disabled={!inputVal.trim()}
                className="px-3.5 py-2 bg-white text-black font-bold uppercase text-xs hover:bg-[#CCCCCC] disabled:opacity-40 transition-none shrink-0 cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="flex items-center justify-between text-[9px] font-mono text-[#555555]">
            <span>CMD+K OPENS AT CURSOR</span>
            {isThinking ? (
              <span className="text-[#FF4444] font-bold">PRESS ESC TO STOP PROMPT</span>
            ) : hasActions ? (
              <span className="text-[#888888]">PRESS ESC TO REMOVE ACTIONS</span>
            ) : (
              <span>ESC TO CANCEL</span>
            )}
          </div>
        </div>
      </aside>
    );
  };

  return (
    <>
      {renderAnchor()}
      {renderDrone()}
      <CruxAgentConfigModal
        isOpen={isConfigModalOpen}
        onClose={() => setIsConfigModalOpen(false)}
      />
      <CruxAffinityMatrixModal
        isOpen={isAffinityModalOpen}
        onClose={() => setIsAffinityModalOpen(false)}
      />
    </>
  );
}
