"use client";

import React, { useState, useRef, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { CrexAiRouter, RouteConfig } from "@/lib/ai/aiRouter";
import { CruxAgentEngine, AgentStep, AgentDiffProposal } from "@/lib/agentEngine";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick } from "@/lib/sound";
import {
  Bot,
  Send,
  X,
  Minimize2,
  Maximize2,
  CornerDownLeft,
  GripHorizontal,
  Check,
  Code2,
  Loader2,
  Terminal,
  Zap,
} from "lucide-react";

interface HudMessage {
  id: string;
  role: "user" | "agent" | "system";
  content: string;
  provider?: string;
  model?: string;
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
  const updateFileContent = useWorkspaceStore((state) => state.updateFileContent);
  const cursorPos = useWorkspaceStore((state) => state.cursorPos);
  const cursorScreenCoords = useWorkspaceStore((state) => state.cursorScreenCoords);
  const aiHudState = useWorkspaceStore((state) => state.aiHudState);
  const isDroneOpen = useWorkspaceStore((state) => state.isDroneOpen);
  const setAiHudState = useWorkspaceStore((state) => state.setAiHudState);
  const setIsDroneOpen = useWorkspaceStore((state) => state.setIsDroneOpen);

  const activeFile = files.find((f) => f.id === activeFileId) || null;

  // Active AI Provider info
  const [activeRoute, setActiveRoute] = useState<RouteConfig>(() => CrexAiRouter.getActiveRoute());
  const [inputVal, setInputVal] = useState("");
  const [isThinking, setIsThinking] = useState(false);
  const [currentSteps, setCurrentSteps] = useState<AgentStep[]>([]);
  const [messages, setMessages] = useState<HudMessage[]>([
    {
      id: "init",
      role: "agent",
      content: "AI Assistant ready. Ask questions, generate code, or configure routes with `> route add [provider] [token]`.",
      provider: "crex-router",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);

  // Drone Drag State
  const [dronePos, setDronePos] = useState<{ x: number; y: number }>({ x: 420, y: 140 });
  const isDraggingRef = useRef(false);
  const dragOffsetRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const droneInputRef = useRef<HTMLInputElement>(null);
  const anchorInputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Sync active route on mount
  useEffect(() => {
    setActiveRoute(CrexAiRouter.getActiveRoute());
  }, [isAnchorOpen, isDroneOpen]);

  // Position Drone at current text cursor coordinates on open
  useEffect(() => {
    if (isDroneOpen) {
      const screenW = typeof window !== "undefined" ? window.innerWidth : 1200;
      const screenH = typeof window !== "undefined" ? window.innerHeight : 800;

      // Spawn at cursor coordinates with boundary clamping
      const spawnX = Math.max(20, Math.min(cursorScreenCoords.x, screenW - 460));
      const spawnY = Math.max(60, Math.min(cursorScreenCoords.y + 12, screenH - 360));

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
      }

      // Escape: Unmount Drone immediately
      if (e.key === "Escape" && isDroneOpen) {
        e.preventDefault();
        playMechanicalClick("low");
        setIsDroneOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isDroneOpen, setIsDroneOpen, setAiHudState]);

  // Drag listeners for Drone window
  const handleDragStart = (e: React.MouseEvent) => {
    isDraggingRef.current = true;
    dragOffsetRef.current = {
      x: e.clientX - dronePos.x,
      y: e.clientY - dronePos.y,
    };

    const handleMouseMove = (ev: MouseEvent) => {
      if (!isDraggingRef.current) return;
      const nextX = Math.max(10, Math.min(ev.clientX - dragOffsetRef.current.x, window.innerWidth - 440));
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
  const handleSubmit = async () => {
    const text = inputVal.trim();
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
    setIsThinking(true);
    setCurrentSteps([
      { id: "1", label: `Routing prompt to ${activeRoute.provider.toUpperCase()} (${activeRoute.model})`, status: "running" },
      { id: "2", label: "Inspecting active buffer AST & context", status: "pending" },
    ]);

    try {
      const response = await CrexAiRouter.executePrompt(text, {
        file: activeFile?.name || "stream_syncer.ts",
        line: cursorPos.line,
      });

      // Also run speculative diff engine if query indicates fix/refactor
      let diffProposal: AgentDiffProposal | undefined = undefined;
      const lower = text.toLowerCase();
      if (activeFile && (lower.includes("fix") || lower.includes("refactor") || lower.includes("optimize"))) {
        const agentResult = await CruxAgentEngine.executeTask({
          prompt: text,
          activeFile,
          allFiles: files,
        });
        diffProposal = agentResult.diffProposal;
      }

      setCurrentSteps([]);
      setMessages((prev) => [
        ...prev,
        {
          id: `agt-${Date.now()}`,
          role: "agent",
          content: response.text,
          provider: response.provider,
          model: response.model,
          diffProposal,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ]);
      triggerHaptic("success");
    } catch (err: any) {
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
      setIsThinking(false);
    }
  };

  const handleApplyDiff = (diff: AgentDiffProposal) => {
    triggerHaptic("success");
    playMechanicalClick("high");
    updateFileContent(diff.fileId, diff.proposedContent);
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
          width: "440px",
          maxHeight: "480px",
          zIndex: 9999,
          borderRadius: "0px",
          border: "1px solid #FFFFFF",
          backgroundColor: "#000000",
          boxShadow: "4px 4px 0px #111111",
          display: "flex",
          flexDirection: "column",
          fontFamily: "Arial, sans-serif",
          userSelect: "none",
        }}
        className="text-white overflow-hidden transition-none"
      >
        {/* Drone Drag Handle & Header */}
        <div
          onMouseDown={handleDragStart}
          className="h-8 bg-[#111111] border-b border-[#222222] px-3 flex items-center justify-between cursor-move shrink-0"
        >
          <div className="flex items-center gap-2">
            <GripHorizontal className="w-3.5 h-3.5 text-[#666666]" />
            <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-white">
              AI Assistant
            </span>
            <span className="text-[9px] font-mono bg-void px-1 border border-[#222222] text-[#888888] uppercase">
              {activeRoute.provider}
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={dockToAnchor}
              title="Dock to sidebar"
              className="px-1.5 py-0.5 text-[9px] font-mono uppercase bg-void hover:bg-white hover:text-black border border-[#222222] transition-none text-[#888888]"
            >
              Dock ↙
            </button>
            <button
              type="button"
              onClick={() => setIsDroneOpen(false)}
              title="Close (Esc)"
              className="p-1 hover:bg-white hover:text-black transition-none text-[#888888]"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Message Log */}
        <div className="flex-1 p-3 overflow-y-auto space-y-2 max-h-[260px] bg-void font-sans text-xs">
          {messages.map((m) => (
            <div
              key={m.id}
              className={`p-2 border ${
                m.role === "user"
                  ? "border-white bg-[#111111] text-white"
                  : m.role === "system"
                  ? "border-[#444444] bg-[#050505] text-[#AAAAAA] font-mono text-[11px] whitespace-pre-wrap"
                  : "border-[#222222] bg-[#0A0A0A] text-[#EEEEEE]"
              }`}
            >
              <div className="flex items-center justify-between text-[9px] font-mono text-[#666666] mb-1">
                <span>{m.role === "user" ? "USER" : m.provider ? `AI (${m.provider})` : "CREX_AI"}</span>
                <span>{m.timestamp}</span>
              </div>
              <div className="leading-relaxed select-text">{m.content}</div>

              {m.diffProposal && (
                <div className="mt-2 pt-2 border-t border-[#222222]">
                  <div className="text-[10px] font-mono text-signal mb-1">Proposed Diff for {m.diffProposal.fileName}:</div>
                  <pre className="p-1.5 bg-[#050505] border border-[#222222] font-mono text-[10px] overflow-x-auto text-[#00FF00]">
                    {m.diffProposal.proposedContent.slice(0, 180)}...
                  </pre>
                  <button
                    onClick={() => handleApplyDiff(m.diffProposal!)}
                    className="mt-1.5 px-2 py-0.5 bg-white text-black font-bold uppercase text-[9px] hover:bg-[#CCCCCC] transition-none"
                  >
                    Apply Patch ↵
                  </button>
                </div>
              )}
            </div>
          ))}

          {isThinking && (
            <div className="p-2 border border-[#222222] bg-[#050505] text-[#888888] font-mono text-[11px] flex items-center gap-2">
              <Loader2 className="w-3.5 h-3.5 animate-spin text-white" />
              <span>Routing query to {activeRoute.provider}...</span>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-2 bg-[#050505] border-t border-[#222222] flex items-center gap-2">
          <input
            ref={droneInputRef}
            type="text"
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleSubmit();
              if (e.key === "Escape") setIsDroneOpen(false);
            }}
            placeholder={`Ask AI or configure '> route add [provider] [token]'...`}
            className="flex-1 bg-void border border-[#222222] px-2 py-1.5 text-xs text-white placeholder:text-[#555555] font-mono focus:border-white focus:outline-none rounded-none transition-none"
          />
          <button
            onClick={handleSubmit}
            disabled={isThinking || !inputVal.trim()}
            className="px-3 py-1.5 bg-white text-black font-bold uppercase text-xs hover:bg-[#CCCCCC] disabled:opacity-40 transition-none shrink-0"
          >
            <Send className="w-3 h-3" />
          </button>
        </div>

        {/* Footer Meta */}
        <div className="h-5 px-2 bg-[#111111] border-t border-[#222222] flex items-center justify-between text-[9px] font-mono text-[#666666]">
          <span>CONTEXT: {activeFile?.name || "none"}:{cursorPos.line}</span>
          <span>PRESS ESC TO CLOSE</span>
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
          minWidth: "300px",
          height: "100%",
          borderLeft: "1px solid #222222",
          backgroundColor: "#000000",
          borderRadius: "0px",
          display: "flex",
          flexDirection: "column",
          userSelect: "none",
          fontFamily: "Arial, sans-serif",
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
            <span className="px-1.5 py-0.5 text-[9px] font-mono bg-void border border-[#222222] text-[#888888] uppercase">
              {activeRoute.provider}
            </span>
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={switchToDrone}
              title="Pop out into floating window"
              className="px-2 py-0.5 text-[9px] font-mono uppercase bg-void hover:bg-white hover:text-black border border-[#222222] text-[#888888] transition-none"
            >
              Float ↗
            </button>
            <button
              onClick={() => {
                playMechanicalClick("low");
                onCloseAnchor();
              }}
              title="Close panel"
              className="p-1 text-[#666666] hover:text-white border border-[#222222] hover:bg-white hover:text-black transition-none"
            >
              <X className="w-3 h-3" />
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
                <span className="font-bold">{m.role === "user" ? "USER" : m.provider ? `AI // ${m.provider.toUpperCase()}` : "CREX_AI"}</span>
                <span>{m.timestamp}</span>
              </div>
              <div className="leading-relaxed select-text">{m.content}</div>

              {m.diffProposal && (
                <div className="mt-2.5 pt-2 border-t border-[#222222]">
                  <div className="text-[10px] font-mono text-signal mb-1.5 flex items-center justify-between">
                    <span>SPECULATIVE PATCH ({m.diffProposal.fileName})</span>
                    <span className="text-[#00FF00] font-bold">READY</span>
                  </div>
                  <pre className="p-2 bg-black border border-[#222222] font-mono text-[10px] overflow-x-auto text-[#00FF00]">
                    {m.diffProposal.proposedContent}
                  </pre>
                  <button
                    onClick={() => handleApplyDiff(m.diffProposal!)}
                    className="mt-2 w-full py-1 bg-white text-black font-bold uppercase text-[10px] hover:bg-[#CCCCCC] transition-none flex items-center justify-center gap-1.5"
                  >
                    <Check className="w-3 h-3 text-black" />
                    <span>Apply Patch to Buffer</span>
                  </button>
                </div>
              )}
            </div>
          ))}

          {isThinking && (
            <div className="p-3 border border-[#222222] bg-[#050505] text-[#888888] font-mono text-xs flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin text-white" />
              <span>Routing via {activeRoute.provider} ({activeRoute.model})...</span>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Dock */}
        <div className="p-3 bg-[#0A0A0A] border-t border-[#222222] space-y-2">
          <div className="flex items-center gap-2">
            <input
              ref={anchorInputRef}
              type="text"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSubmit();
              }}
              placeholder="Prompt AI or enter '> route add [provider] [token]'..."
              className="flex-1 bg-void border border-[#222222] px-3 py-2 text-xs text-white placeholder:text-[#555555] font-mono focus:border-white focus:outline-none rounded-none transition-none"
            />
            <button
              onClick={handleSubmit}
              disabled={isThinking || !inputVal.trim()}
              className="px-3.5 py-2 bg-white text-black font-bold uppercase text-xs hover:bg-[#CCCCCC] disabled:opacity-40 transition-none shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="flex items-center justify-between text-[9px] font-mono text-[#555555]">
            <span>CMD+K OPENS AT CURSOR</span>
            <span>ESC TO CLOSE</span>
          </div>
        </div>
      </aside>
    );
  };

  return (
    <>
      {renderAnchor()}
      {renderDrone()}
    </>
  );
}
