"use client";

import React, { useState, useRef, useEffect, useCallback } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { TerminalSession } from "@/lib/types";
import { AnsiLine, AnsiSpan } from "@/lib/ansiParser";
import {
  Trash2,
  ChevronDown,
  ChevronUp,
  Terminal as TerminalIcon,
  Plus,
  X,
  SplitSquareVertical,
  Columns,
  Square,
  Search,
  Maximize2,
  Minimize2,
  SquareSquare,
  Sparkles,
  Server,
  AlertTriangle,
  Play,
  StopCircle,
  HelpCircle,
  CheckCircle,
} from "lucide-react";

export default function ZenithTerminal() {
  const isTerminalOpen = useWorkspaceStore((state) => state.isTerminalOpen);
  const toggleTerminal = useWorkspaceStore((state) => state.toggleTerminal);
  const files = useWorkspaceStore((state) => state.files);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const setCursorPos = useWorkspaceStore((state) => state.setCursorPos);
  const lastExecutionResult = useWorkspaceStore((state) => state.lastExecutionResult);

  // Store Terminal State
  const terminalSessions = useWorkspaceStore((state) => state.terminalSessions);
  const activeTerminalSessionId = useWorkspaceStore((state) => state.activeTerminalSessionId);
  const secondaryTerminalSessionId = useWorkspaceStore((state) => state.secondaryTerminalSessionId);
  const terminalSplitMode = useWorkspaceStore((state) => state.terminalSplitMode);
  const terminalHeight = useWorkspaceStore((state) => state.terminalHeight);
  const isTerminalMaximized = useWorkspaceStore((state) => state.isTerminalMaximized);
  const terminalSearchQuery = useWorkspaceStore((state) => state.terminalSearchQuery);

  // Store Actions
  const createTerminalSession = useWorkspaceStore((state) => state.createTerminalSession);
  const closeTerminalSession = useWorkspaceStore((state) => state.closeTerminalSession);
  const setActiveTerminalSessionId = useWorkspaceStore((state) => state.setActiveTerminalSessionId);
  const setSecondaryTerminalSessionId = useWorkspaceStore((state) => state.setSecondaryTerminalSessionId);
  const setTerminalSplitMode = useWorkspaceStore((state) => state.setTerminalSplitMode);
  const setTerminalHeight = useWorkspaceStore((state) => state.setTerminalHeight);
  const toggleTerminalMaximized = useWorkspaceStore((state) => state.toggleTerminalMaximized);
  const setTerminalSearchQuery = useWorkspaceStore((state) => state.setTerminalSearchQuery);
  const appendTerminalChunk = useWorkspaceStore((state) => state.appendTerminalChunk);
  const clearTerminalSession = useWorkspaceStore((state) => state.clearTerminalSession);
  const setSessionStreaming = useWorkspaceStore((state) => state.setSessionStreaming);
  const setSessionExitCode = useWorkspaceStore((state) => state.setSessionExitCode);
  const setSessionDiagnosis = useWorkspaceStore((state) => state.setSessionDiagnosis);
  const setSessionInputVal = useWorkspaceStore((state) => state.setSessionInputVal);
  const addSessionHistory = useWorkspaceStore((state) => state.addSessionHistory);

  // Local UI states
  const [activeTabType, setActiveTabType] = useState<"session" | "output">("session");
  const [isSearching, setIsSearching] = useState(false);
  const [isDraggingHeight, setIsDraggingHeight] = useState(false);
  const [aiProposal, setAiProposal] = useState<{ command: string; explanation: string } | null>(null);
  const [isDiagnosing, setIsDiagnosing] = useState(false);

  const activeSession =
    terminalSessions.find((s) => s.id === activeTerminalSessionId) || terminalSessions[0];
  const secondarySession =
    terminalSessions.find((s) => s.id === secondaryTerminalSessionId) ||
    terminalSessions.find((s) => s.id !== activeTerminalSessionId) ||
    null;

  const dragStartYRef = useRef(0);
  const dragStartHeightRef = useRef(0);

  // Drag-to-resize handlers
  const handleMouseDownResize = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsDraggingHeight(true);
    dragStartYRef.current = e.clientY;
    dragStartHeightRef.current = terminalHeight;
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDraggingHeight) return;
      const delta = dragStartYRef.current - e.clientY;
      const newHeight = Math.max(140, Math.min(window.innerHeight * 0.85, dragStartHeightRef.current + delta));
      setTerminalHeight(newHeight);
    };

    const handleMouseUp = () => {
      setIsDraggingHeight(false);
    };

    if (isDraggingHeight) {
      window.addEventListener("mousemove", handleMouseMove);
      window.addEventListener("mouseup", handleMouseUp);
    }
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isDraggingHeight, setTerminalHeight]);

  // Jump to file and line when clicking a hyperlink
  const handleOpenFileLink = (filePath: string, line?: number, col?: number) => {
    const cleanPath = filePath.replace(/^\.\//, "");
    const matched = files.find(
      (f) =>
        f.path === cleanPath ||
        f.name === cleanPath ||
        cleanPath.endsWith(f.name) ||
        f.path.endsWith(cleanPath)
    );
    if (matched) {
      setActiveFile(matched.id);
      if (line !== undefined) {
        setCursorPos({ line, col: col || 1 });
      }
    }
  };

  // Execute command in a specific session via /api/terminal/stream
  const executeCommandInSession = async (session: TerminalSession, cmdToRun?: string) => {
    const rawCmd = cmdToRun !== undefined ? cmdToRun : session.inputVal;
    const trimmed = rawCmd.trim();
    if (!trimmed) return;

    // Reset input
    setSessionInputVal(session.id, "");
    setAiProposal(null);

    // Clear command
    if (trimmed === "clear") {
      clearTerminalSession(session.id);
      return;
    }

    // Help command
    if (trimmed === "help") {
      addSessionHistory(session.id, trimmed);
      appendTerminalChunk(
        session.id,
        [
          "\x1b[1;36mCRUX HYPERTERMINAL ENGINE v1.2.0\x1b[0m\n",
          "  \x1b[32mls\x1b[0m                  List files and sizes\n",
          "  \x1b[32mcat <file>\x1b[0m          Inspect workspace buffer content\n",
          "  \x1b[32mnode <file>\x1b[0m         Execute file via V8 runtime sandbox\n",
          "  \x1b[32mcrux status\x1b[0m         Daemon, IPC socket, and peer latency status\n",
          "  \x1b[32mcrux build\x1b[0m          Incremental AST compiler pipeline\n",
          "  \x1b[32mcrux peers\x1b[0m          Connected collaborative peers\n",
          "  \x1b[35m?? <query>\x1b[0m          Ask CruxAI to generate & preview a shell command\n",
          "  \x1b[32mclear\x1b[0m               Clear session scrollback\n",
          "  \x1b[37m<any shell cmd>\x1b[0m     Run live shell commands (git, npm, curl, lsof)\n\n",
        ].join("")
      );
      return;
    }

    // In-memory file view: cat <file>
    if (trimmed.startsWith("cat ")) {
      addSessionHistory(session.id, trimmed);
      appendTerminalChunk(session.id, `\x1b[36mcrux-sh:~$\x1b[0m ${trimmed}\n`);
      const targetName = trimmed.slice(4).trim();
      const target = files.find(
        (f) => f.name === targetName || f.path === targetName || f.name.toLowerCase() === targetName.toLowerCase()
      );
      if (target) {
        appendTerminalChunk(session.id, `${target.content}\n`);
      } else {
        appendTerminalChunk(session.id, `\x1b[31mcat: ${targetName}: No such file in workspace\x1b[0m\n`, true);
      }
      return;
    }

    // Log the prompt
    addSessionHistory(session.id, trimmed);
    appendTerminalChunk(session.id, `\x1b[36mcrux-sh:~$\x1b[0m ${trimmed}\n`);
    setSessionStreaming(session.id, true, null);
    setSessionExitCode(session.id, null);

    try {
      const response = await fetch("/api/terminal/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: trimmed, cwd: session.cwd }),
      });

      if (!response.ok || !response.body) {
        appendTerminalChunk(session.id, `\x1b[31mExecution failed with HTTP ${response.status}\x1b[0m\n`, true);
        setSessionStreaming(session.id, false, null);
        setSessionExitCode(session.id, 1);
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const event = JSON.parse(line.slice(6));
              if (event.type === "start") {
                setSessionStreaming(session.id, true, event.pid);
              } else if (event.type === "stdout") {
                appendTerminalChunk(session.id, event.data, false);
              } else if (event.type === "stderr") {
                appendTerminalChunk(session.id, event.data, true);
              } else if (event.type === "exit") {
                setSessionStreaming(session.id, false, null);
                setSessionExitCode(session.id, event.code);
              }
            } catch {
              // Parse error on malformed chunk
            }
          }
        }
      }
    } catch (err: any) {
      appendTerminalChunk(session.id, `\x1b[31mNetwork error: ${err.message}\x1b[0m\n`, true);
      setSessionStreaming(session.id, false, null);
      setSessionExitCode(session.id, 1);
    }
  };

  // Kill the active process in a session (Ctrl+C)
  const handleKillSessionProcess = async (session: TerminalSession) => {
    if (!session.activePid) {
      appendTerminalChunk(session.id, "^C\n");
      setSessionStreaming(session.id, false, null);
      return;
    }

    try {
      await fetch("/api/terminal/kill", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pid: session.activePid }),
      });
      appendTerminalChunk(session.id, `\x1b[33m^C [Process ${session.activePid} terminated]\x1b[0m\n`);
    } catch {
      // ignore
    } finally {
      setSessionStreaming(session.id, false, null);
      setSessionExitCode(session.id, 130);
    }
  };

  // Diagnose error with @CruxAI
  const handleDiagnoseError = async (session: TerminalSession) => {
    setIsDiagnosing(true);
    const lastLines = session.lines.slice(-15).map((l) => l.rawText).join("\n");

    try {
      const res = await fetch("/api/terminal/ai", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "diagnose-error",
          stderr: lastLines,
          exitCode: session.lastExitCode || 1,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setSessionDiagnosis(session.id, {
          summary: data.summary,
          suggestedCommand: data.suggestedCommand,
          suggestedDiff: data.suggestedDiff,
        });
      }
    } catch {
      // ignore
    } finally {
      setIsDiagnosing(false);
    }
  };

  // Natural language AI command generation preview
  const handleCheckAiPrompt = async (val: string) => {
    if (val.startsWith("?? ") && val.length > 5) {
      const promptQuery = val.slice(3).trim();
      try {
        const res = await fetch("/api/terminal/ai", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "generate-command", prompt: promptQuery }),
        });
        if (res.ok) {
          const data = await res.json();
          setAiProposal({ command: data.command, explanation: data.explanation });
        }
      } catch {
        // ignore
      }
    } else {
      setAiProposal(null);
    }
  };

  if (!isTerminalOpen) return null;

  return (
    <footer
      style={{ height: isTerminalMaximized ? "85vh" : `${terminalHeight}px` }}
      className="border-t border-grid bg-surface flex flex-col shrink-0 font-sans select-none relative transition-all duration-75"
    >
      {/* DRAG RESIZE HANDLE */}
      <div
        onMouseDown={handleMouseDownResize}
        className="absolute top-0 left-0 right-0 h-1 cursor-ns-resize hover:bg-signal/50 z-30 transition-colors"
        title="Drag to resize terminal height"
      />

      {/* TOP HEADER / SESSION TABS BAR (36px) */}
      <div className="flex h-9 border-b border-grid bg-void items-center justify-between shrink-0 select-none">
        {/* Left: Tab Sessions */}
        <div className="flex h-full items-center overflow-x-auto">
          {terminalSessions.map((session) => {
            const isActive = session.id === activeTerminalSessionId && activeTabType === "session";
            return (
              <div
                key={session.id}
                onClick={() => {
                  setActiveTerminalSessionId(session.id);
                  setActiveTabType("session");
                }}
                className={`px-3.5 h-full text-[11px] font-mono border-r border-grid uppercase tracking-wider transition-colors flex items-center gap-2 cursor-pointer shrink-0 ${
                  isActive
                    ? "text-signal bg-void font-medium"
                    : "text-muted hover:text-signal bg-surface"
                }`}
              >
                {/* Session Type Icon & Status Pulse */}
                <div className="flex items-center gap-1.5">
                  {session.isStreaming ? (
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00FF00] animate-ping" />
                  ) : session.lastExitCode !== null && session.lastExitCode !== 0 ? (
                    <span className="w-1.5 h-1.5 rounded-full bg-accent2" />
                  ) : (
                    <span className="w-1.5 h-1.5 rounded-full bg-[#555]" />
                  )}

                  {session.type === "server" ? (
                    <Server className="w-3 h-3 text-[#00FF00]" />
                  ) : session.type === "ai" ? (
                    <Sparkles className="w-3 h-3 text-accent2" />
                  ) : (
                    <TerminalIcon className="w-3 h-3" />
                  )}
                </div>

                <span>{session.name}</span>

                {/* Close Session Button (only if > 1 session) */}
                {terminalSessions.length > 1 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      closeTerminalSession(session.id);
                    }}
                    className="p-0.5 text-muted hover:text-signal transition-colors ml-1"
                    title="Close session"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
            );
          })}

          {/* New Tab Button */}
          <button
            onClick={() => createTerminalSession()}
            className="px-2.5 h-full border-r border-grid text-muted hover:text-signal bg-surface hover:bg-void transition-colors flex items-center justify-center"
            title="Create new terminal session (+)"
          >
            <Plus className="w-3.5 h-3.5" />
          </button>

          {/* Tab: Output (V8 Sandbox Result from Run button) */}
          <button
            onClick={() => setActiveTabType("output")}
            className={`px-3.5 h-full text-[11px] font-mono border-r border-grid uppercase tracking-wider transition-colors flex items-center gap-2 ${
              activeTabType === "output"
                ? "text-signal bg-void font-medium"
                : "text-muted hover:text-signal bg-surface"
            }`}
          >
            <CheckCircle className="w-3 h-3 text-[#00FF00]" />
            <span>Output</span>
            {lastExecutionResult && (
              <span className="px-1 text-[9px] bg-void border border-grid text-signal">
                {lastExecutionResult.success ? "0" : "1"}
              </span>
            )}
          </button>
        </div>

        {/* Right: Split, Search, Maximize & Close Controls */}
        <div className="flex items-center gap-2 px-3 text-muted shrink-0">
          {/* Split Mode Selector */}
          <div className="flex items-center border border-grid bg-void">
            <button
              onClick={() => setTerminalSplitMode("none")}
              title="Single Pane"
              className={`p-1 transition-colors ${
                terminalSplitMode === "none" ? "bg-grid text-signal" : "text-muted hover:text-signal"
              }`}
            >
              <Square className="w-3 h-3" />
            </button>
            <button
              onClick={() => setTerminalSplitMode("horizontal")}
              title="Split Horizontal"
              className={`p-1 transition-colors border-l border-grid ${
                terminalSplitMode === "horizontal" ? "bg-grid text-signal" : "text-muted hover:text-signal"
              }`}
            >
              <SplitSquareVertical className="w-3 h-3" />
            </button>
            <button
              onClick={() => setTerminalSplitMode("vertical")}
              title="Split Vertical"
              className={`p-1 transition-colors border-l border-grid ${
                terminalSplitMode === "vertical" ? "bg-grid text-signal" : "text-muted hover:text-signal"
              }`}
            >
              <Columns className="w-3 h-3" />
            </button>
          </div>

          {/* Search Toggle */}
          <button
            onClick={() => setIsSearching(!isSearching)}
            title="Search Output (Cmd+F)"
            className={`p-1 border border-grid transition-colors ${
              isSearching ? "bg-grid text-signal" : "bg-void hover:text-signal"
            }`}
          >
            <Search className="w-3.5 h-3.5" />
          </button>

          {/* Kill Running Process Button (Active if session is streaming) */}
          {activeSession?.isStreaming && (
            <button
              onClick={() => handleKillSessionProcess(activeSession)}
              title="Kill Running Process (Ctrl+C)"
              className="px-2 py-0.5 border border-accent2/50 bg-accent2/10 text-accent2 hover:bg-accent2 hover:text-white transition-colors text-[10px] font-mono flex items-center gap-1"
            >
              <StopCircle className="w-3 h-3" />
              <span>KILL</span>
            </button>
          )}

          {/* Clear Logs */}
          <button
            onClick={() => clearTerminalSession(activeSession.id)}
            title="Clear Terminal (Cmd+K)"
            className="p-1 border border-grid bg-void hover:text-signal transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          {/* Maximize / Restore Toggle */}
          <button
            onClick={toggleTerminalMaximized}
            title={isTerminalMaximized ? "Restore Height" : "Maximize Drawer"}
            className="p-1 border border-grid bg-void hover:text-signal transition-colors"
          >
            {isTerminalMaximized ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>

          {/* Collapse Drawer */}
          <button
            onClick={toggleTerminal}
            title="Collapse Drawer (Cmd+J)"
            className="p-1 border border-grid bg-void hover:text-signal transition-colors"
          >
            <ChevronDown className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* OPTIONAL SEARCH BAR */}
      {isSearching && (
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-grid bg-void text-[11px] font-mono shrink-0">
          <Search className="w-3 h-3 text-muted" />
          <input
            type="text"
            value={terminalSearchQuery}
            onChange={(e) => setTerminalSearchQuery(e.target.value)}
            placeholder="Search terminal output buffer..."
            className="flex-1 bg-transparent border-none outline-none text-signal text-[11px] font-mono p-0 focus:ring-0"
            autoFocus
          />
          {terminalSearchQuery && (
            <button
              onClick={() => setTerminalSearchQuery("")}
              className="text-muted hover:text-signal p-0.5"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
      )}

      {/* VIEWPORT AREA: OUTPUT TAB OR TERMINAL PANES */}
      <div className="flex-1 overflow-hidden flex bg-void">
        {activeTabType === "output" ? (
          /* V8 SANDBOX OUTPUT VIEW */
          <div className="flex-1 p-4 font-mono text-[12px] overflow-auto select-text space-y-2">
            {lastExecutionResult ? (
              <>
                <div className="flex items-center justify-between pb-1.5 border-b border-grid/60">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[11px] font-bold px-1.5 py-0.5 border ${
                        lastExecutionResult.success
                          ? "border-[#00FF00]/40 text-[#00FF00] bg-[#00FF00]/10"
                          : "border-accent2/40 text-accent2 bg-accent2/10"
                      }`}
                    >
                      {lastExecutionResult.success ? "✓ EXIT 0" : "✕ EXIT 1"}
                    </span>
                    <span className="text-signal font-medium">
                      {lastExecutionResult.fileName || "buffer"}
                    </span>
                  </div>
                  <span className="text-muted text-[11px]">
                    {lastExecutionResult.durationMs?.toFixed(2)}ms
                  </span>
                </div>

                {lastExecutionResult.stdout && lastExecutionResult.stdout.length > 0 && (
                  <div className="space-y-0.5">
                    {lastExecutionResult.stdout.map((out, idx) => (
                      <div key={idx} className="text-[#00FF00]">
                        {out}
                      </div>
                    ))}
                  </div>
                )}

                {lastExecutionResult.stderr && lastExecutionResult.stderr.length > 0 && (
                  <div className="space-y-0.5">
                    {lastExecutionResult.stderr.map((err, idx) => (
                      <div key={idx} className="text-accent2 whitespace-pre-wrap">
                        {err}
                      </div>
                    ))}
                  </div>
                )}

                {lastExecutionResult.returnValue !== undefined && (
                  <div className="text-muted">
                    =&gt; {lastExecutionResult.returnValue}
                  </div>
                )}
              </>
            ) : (
              <div className="text-muted italic">
                No active execution output. Press ⌘+Enter or click Run in the editor.
              </div>
            )}
          </div>
        ) : (
          /* TERMINAL SESSIONS VIEW (Supports Single or Split Panes) */
          <div
            className={`flex-1 flex overflow-hidden ${
              terminalSplitMode === "horizontal" ? "flex-col" : "flex-row"
            }`}
          >
            {/* Primary Session Pane */}
            <TerminalPaneView
              session={activeSession}
              searchQuery={terminalSearchQuery}
              aiProposal={aiProposal}
              isDiagnosing={isDiagnosing}
              files={files}
              onOpenFileLink={handleOpenFileLink}
              onSubmitCommand={(cmd) => executeCommandInSession(activeSession, cmd)}
              onKillProcess={() => handleKillSessionProcess(activeSession)}
              onDiagnoseError={() => handleDiagnoseError(activeSession)}
              onInputChange={(val) => {
                setSessionInputVal(activeSession.id, val);
                handleCheckAiPrompt(val);
              }}
              onAcceptAiProposal={(cmd) => {
                setSessionInputVal(activeSession.id, cmd);
                setAiProposal(null);
                executeCommandInSession(activeSession, cmd);
              }}
              onCancelAiProposal={() => setAiProposal(null)}
            />

            {/* Secondary Split Pane (if active) */}
            {terminalSplitMode !== "none" && secondarySession && (
              <div
                className={`flex-1 flex flex-col bg-void ${
                  terminalSplitMode === "horizontal" ? "border-t border-grid" : "border-l border-grid"
                }`}
              >
                <div className="h-6 bg-surface border-b border-grid px-3 flex items-center justify-between text-[10px] font-mono text-muted select-none">
                  <span>Pane: {secondarySession.name}</span>
                  <button
                    onClick={() => setTerminalSplitMode("none")}
                    className="hover:text-signal"
                    title="Close split pane"
                  >
                    <X className="w-2.5 h-2.5" />
                  </button>
                </div>
                <TerminalPaneView
                  session={secondarySession}
                  searchQuery={terminalSearchQuery}
                  aiProposal={null}
                  isDiagnosing={false}
                  files={files}
                  onOpenFileLink={handleOpenFileLink}
                  onSubmitCommand={(cmd) => executeCommandInSession(secondarySession, cmd)}
                  onKillProcess={() => handleKillSessionProcess(secondarySession)}
                  onDiagnoseError={() => handleDiagnoseError(secondarySession)}
                  onInputChange={(val) => setSessionInputVal(secondarySession.id, val)}
                  onAcceptAiProposal={() => {}}
                  onCancelAiProposal={() => {}}
                />
              </div>
            )}
          </div>
        )}
      </div>
    </footer>
  );
}

// Sub-component: Individual Terminal Viewport Pane
interface TerminalPaneViewProps {
  session: TerminalSession;
  searchQuery: string;
  aiProposal: { command: string; explanation: string } | null;
  isDiagnosing: boolean;
  files: any[];
  onOpenFileLink: (path: string, line?: number, col?: number) => void;
  onSubmitCommand: (cmd?: string) => void;
  onKillProcess: () => void;
  onDiagnoseError: () => void;
  onInputChange: (val: string) => void;
  onAcceptAiProposal: (cmd: string) => void;
  onCancelAiProposal: () => void;
}

function TerminalPaneView({
  session,
  searchQuery,
  aiProposal,
  isDiagnosing,
  files,
  onOpenFileLink,
  onSubmitCommand,
  onKillProcess,
  onDiagnoseError,
  onInputChange,
  onAcceptAiProposal,
  onCancelAiProposal,
}: TerminalPaneViewProps) {
  const logsEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [session.lines]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    // Ctrl+C to abort running process
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "c") {
      e.preventDefault();
      onKillProcess();
      return;
    }

    // Up Arrow: History backward
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (session.history.length > 0) {
        const nextIdx =
          session.historyIndex === -1
            ? session.history.length - 1
            : Math.max(0, session.historyIndex - 1);
        session.historyIndex = nextIdx;
        onInputChange(session.history[nextIdx] || "");
      }
      return;
    }

    // Down Arrow: History forward
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (session.historyIndex !== -1) {
        const nextIdx = session.historyIndex + 1;
        if (nextIdx >= session.history.length) {
          session.historyIndex = -1;
          onInputChange("");
        } else {
          session.historyIndex = nextIdx;
          onInputChange(session.history[nextIdx]);
        }
      }
      return;
    }

    // Tab autocomplete
    if (e.key === "Tab") {
      e.preventDefault();
      const current = session.inputVal;
      const parts = current.split(" ");
      const lastToken = parts[parts.length - 1];
      if (lastToken) {
        const match = files.find(
          (f) =>
            f.name.startsWith(lastToken) ||
            f.name.toLowerCase().startsWith(lastToken.toLowerCase())
        );
        if (match) {
          parts[parts.length - 1] = match.name;
          onInputChange(parts.join(" "));
        }
      }
    }
  };

  const filteredLines = searchQuery
    ? session.lines.filter((l) => l.rawText.toLowerCase().includes(searchQuery.toLowerCase()))
    : session.lines;

  return (
    <div className="flex-1 p-3 font-mono text-[12px] flex flex-col overflow-hidden bg-void select-text">
      {/* Scrollable Output Stream */}
      <div className="flex-1 overflow-auto space-y-0.5">
        {filteredLines.map((line) => (
          <div key={line.id} className="leading-snug break-all">
            {line.spans.map((span, idx) => {
              const spanStyle: React.CSSProperties = {};
              if (span.color) spanStyle.color = span.color;
              if (span.bgColor) spanStyle.backgroundColor = span.bgColor;

              if (span.fileLink) {
                return (
                  <span
                    key={idx}
                    onClick={() =>
                      onOpenFileLink(
                        span.fileLink!.path,
                        span.fileLink!.line,
                        span.fileLink!.col
                      )
                    }
                    className="underline decoration-signal cursor-pointer hover:text-signal transition-colors font-medium"
                    title={`Jump to ${span.fileLink.path}:${span.fileLink.line || 1}`}
                    style={spanStyle}
                  >
                    {span.text}
                  </span>
                );
              }

              return (
                <span
                  key={idx}
                  style={spanStyle}
                  className={`
                    ${span.bold ? "font-bold" : ""}
                    ${span.dim ? "opacity-60" : ""}
                    ${span.underline ? "underline" : ""}
                  `}
                >
                  {span.text}
                </span>
              );
            })}
          </div>
        ))}

        {/* AUTONOMOUS ERROR DIAGNOSIS BANNER */}
        {session.lastExitCode !== null && session.lastExitCode !== 0 && (
          <div className="my-2 p-2.5 border border-accent2/40 bg-accent2/10 space-y-1.5 select-none">
            <div className="flex items-center justify-between text-[11px]">
              <div className="flex items-center gap-1.5 text-accent2 font-bold">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Process exited with code {session.lastExitCode}</span>
              </div>
              <button
                onClick={onDiagnoseError}
                disabled={isDiagnosing}
                className="px-2 py-0.5 border border-accent2 bg-void text-signal hover:bg-accent2 hover:text-white transition-colors text-[10px] uppercase font-bold flex items-center gap-1"
              >
                <Sparkles className="w-3 h-3 text-accent2" />
                <span>{isDiagnosing ? "Diagnosing..." : "Diagnose with @CruxAI"}</span>
              </button>
            </div>

            {session.lastDiagnosis && (
              <div className="pt-1 text-[11px] font-sans border-t border-accent2/20 text-muted space-y-1">
                <div className="text-signal font-medium">{session.lastDiagnosis.summary}</div>
                {session.lastDiagnosis.suggestedCommand && (
                  <div className="flex items-center gap-2 pt-1 font-mono text-[10px]">
                    <span className="text-muted">Fix:</span>
                    <code className="text-[#00FF00] bg-void px-1.5 py-0.5 border border-grid">
                      {session.lastDiagnosis.suggestedCommand}
                    </code>
                    <button
                      onClick={() => onSubmitCommand(session.lastDiagnosis!.suggestedCommand)}
                      className="px-2 py-0.5 border border-grid bg-void text-signal hover:border-signal uppercase text-[9px]"
                    >
                      Apply &amp; Run
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        <div ref={logsEndRef} />
      </div>

      {/* AI COMMAND GENERATION PREVIEW BANNER */}
      {aiProposal && (
        <div className="mb-1.5 p-2 border border-accent2 bg-surface text-[11px] space-y-1 select-none">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-accent2 font-bold">
              <Sparkles className="w-3 h-3" />
              <span>@CruxAI Command Proposal</span>
            </div>
            <button
              onClick={onCancelAiProposal}
              className="text-muted hover:text-signal text-[10px]"
            >
              [Esc to Cancel]
            </button>
          </div>
          <div className="text-muted">{aiProposal.explanation}</div>
          <div className="flex items-center gap-2 pt-1">
            <code className="flex-1 bg-void border border-grid p-1 text-[#00FF00] font-mono text-[11px]">
              {aiProposal.command}
            </code>
            <button
              onClick={() => onAcceptAiProposal(aiProposal.command)}
              className="px-2.5 py-1 border border-grid bg-signal text-void font-bold text-[10px] hover:opacity-90 transition-opacity"
            >
              Run ↵
            </button>
          </div>
        </div>
      )}

      {/* COMMAND INPUT PROMPT */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSubmitCommand();
        }}
        className="flex items-center gap-2 pt-1.5 border-t border-grid/60 shrink-0"
      >
        <span className="text-signal shrink-0 font-bold">crux-sh:~$</span>
        <input
          ref={inputRef}
          type="text"
          value={session.inputVal}
          onChange={(e) => onInputChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="type command (e.g. ls, crux status, ?? <query>)..."
          className="flex-1 bg-transparent border-none outline-none font-mono text-[12px] text-signal p-0 focus:ring-0 placeholder:text-muted/50"
        />
        {session.isStreaming ? (
          <span className="w-2 h-3 bg-[#00FF00] animate-pulse" />
        ) : (
          <span className="w-2 h-3 bg-signal animate-pulse" />
        )}
      </form>
    </div>
  );
}
