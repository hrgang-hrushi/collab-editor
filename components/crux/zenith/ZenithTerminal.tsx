"use client";

import React, { useState, useRef, useEffect, useCallback } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { TerminalSession, TerminalPeerInput } from "@/lib/types";
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
  Sparkles,
  Server,
  AlertTriangle,
  Play,
  StopCircle,
  CheckCircle,
  Check,
  History,
  Lock,
  Users,
  CornerDownLeft,
  ArrowRight,
  Settings,
  Cpu,
  RefreshCw,
} from "lucide-react";

function formatCwdPrompt(cwd?: string): string {
  if (!cwd) return "~";
  const userHome = "/Users/hrushikeshgangala";
  if (cwd === userHome) return "~";
  if (cwd.startsWith(userHome)) {
    const rel = "~" + cwd.slice(userHome.length);
    const parts = rel.split("/");
    return parts.length > 3 ? ".../" + parts.slice(-2).join("/") : rel;
  }
  const parts = cwd.split("/");
  return parts.length > 3 ? ".../" + parts.slice(-2).join("/") : cwd;
}

export default function ZenithTerminal() {
  const isTerminalOpen = useWorkspaceStore((state) => state.isTerminalOpen);
  const toggleTerminal = useWorkspaceStore((state) => state.toggleTerminal);
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const cursorPos = useWorkspaceStore((state) => state.cursorPos);
  const setCursorPos = useWorkspaceStore((state) => state.setCursorPos);
  const lastExecutionResult = useWorkspaceStore((state) => state.lastExecutionResult);
  const viewerLock = useWorkspaceStore((state) => state.viewerLock);
  const accessLevel = useWorkspaceStore((state) => state.accessLevel);
  const addSuggestion = useWorkspaceStore((state) => state.addSuggestion);

  // Store Terminal State
  const terminalSessions = useWorkspaceStore((state) => state.terminalSessions);
  const activeTerminalSessionId = useWorkspaceStore((state) => state.activeTerminalSessionId);
  const secondaryTerminalSessionId = useWorkspaceStore((state) => state.secondaryTerminalSessionId);
  const terminalSplitMode = useWorkspaceStore((state) => state.terminalSplitMode);
  const terminalHeight = useWorkspaceStore((state) => state.terminalHeight);
  const isTerminalMaximized = useWorkspaceStore((state) => state.isTerminalMaximized);
  const terminalSearchQuery = useWorkspaceStore((state) => state.terminalSearchQuery);
  const terminalTimeTravelIndex = useWorkspaceStore((state) => state.terminalTimeTravelIndex);

  // Store Actions
  const createTerminalSession = useWorkspaceStore((state) => state.createTerminalSession);
  const closeTerminalSession = useWorkspaceStore((state) => state.closeTerminalSession);
  const setActiveTerminalSessionId = useWorkspaceStore((state) => state.setActiveTerminalSessionId);
  const setSecondaryTerminalSessionId = useWorkspaceStore((state) => state.setSecondaryTerminalSessionId);
  const setTerminalSplitMode = useWorkspaceStore((state) => state.setTerminalSplitMode);
  const setTerminalHeight = useWorkspaceStore((state) => state.setTerminalHeight);
  const toggleTerminalMaximized = useWorkspaceStore((state) => state.toggleTerminalMaximized);
  const setTerminalSearchQuery = useWorkspaceStore((state) => state.setTerminalSearchQuery);
  const setTerminalTimeTravelIndex = useWorkspaceStore((state) => state.setTerminalTimeTravelIndex);
  const appendTerminalChunk = useWorkspaceStore((state) => state.appendTerminalChunk);
  const clearTerminalSession = useWorkspaceStore((state) => state.clearTerminalSession);
  const setSessionStreaming = useWorkspaceStore((state) => state.setSessionStreaming);
  const setSessionExitCode = useWorkspaceStore((state) => state.setSessionExitCode);
  const setSessionDiagnosis = useWorkspaceStore((state) => state.setSessionDiagnosis);
  const setSessionCwd = useWorkspaceStore((state) => state.setSessionCwd);
  const setSessionName = useWorkspaceStore((state) => state.setSessionName);
  const setSessionInputVal = useWorkspaceStore((state) => state.setSessionInputVal);
  const addSessionHistory = useWorkspaceStore((state) => state.addSessionHistory);
  const broadcastTerminalPeerInput = useWorkspaceStore((state) => state.broadcastTerminalPeerInput);
  const pendingTerminalCommand = useWorkspaceStore((state) => state.pendingTerminalCommand);
  const setPendingTerminalCommand = useWorkspaceStore((state) => state.setPendingTerminalCommand);
  const activeTerminalTab = useWorkspaceStore((state) => state.activeTerminalTab);
  const setActiveTerminalTab = useWorkspaceStore((state) => state.setActiveTerminalTab);
  const setLastExecutionResult = useWorkspaceStore((state) => state.setLastExecutionResult);

  // Discovered AI Tools & Orchestration
  const discoveredRuntimes = useWorkspaceStore((state) => state.discoveredRuntimes);
  const activeAiToolId = useWorkspaceStore((state) => state.activeAiToolId);
  const autoPickedAiToolId = useWorkspaceStore((state) => state.autoPickedAiToolId);
  const setAiToolSelection = useWorkspaceStore((state) => state.setAiToolSelection);
  const rescanAiTools = useWorkspaceStore((state) => state.rescanAiTools);
  const fetchDiscoveryReport = useWorkspaceStore((state) => state.fetchDiscoveryReport);

  // Local UI states
  const [activeTabType, setActiveTabType] = useState<"session" | "output">("session");
  const [isSearching, setIsSearching] = useState(false);
  const [isDraggingHeight, setIsDraggingHeight] = useState(false);
  const [isAiMenuOpen, setIsAiMenuOpen] = useState(false);
  const [aiProposal, setAiProposal] = useState<{
    command: string;
    explanation: string;
    contextSummary: string;
  } | null>(null);
  const [isAutoHealing, setIsAutoHealing] = useState(false);
  const [ghostFixMessage, setGhostFixMessage] = useState<string | null>(null);

  // Auto-Picked & Active AI Engine resolution
  const autoPickedTool =
    discoveredRuntimes.find((r) => r.isAutoPicked || r.id === autoPickedAiToolId || r.binaryName === "antigravity" || r.binaryName === "agy") ||
    discoveredRuntimes[0];
  const activeAiTool =
    activeAiToolId === "auto"
      ? autoPickedTool
      : discoveredRuntimes.find((r) => r.id === activeAiToolId || r.binaryName === activeAiToolId) ||
        autoPickedTool;

  // Auto-scan host tools on terminal mount if list is empty
  useEffect(() => {
    if (discoveredRuntimes.length === 0) {
      fetchDiscoveryReport();
    }
  }, [discoveredRuntimes.length, fetchDiscoveryReport]);

  const activeFile = files.find((f) => f.id === activeFileId) || files[0];
  const isReadOnly = viewerLock || accessLevel === "viewer";

  const activeSession =
    terminalSessions.find((s) => s.id === activeTerminalSessionId) || terminalSessions[0];
  const secondarySession =
    terminalSessions.find((s) => s.id === secondaryTerminalSessionId) ||
    terminalSessions.find((s) => s.id !== activeTerminalSessionId) ||
    null;

  const dragStartYRef = useRef(0);
  const dragStartHeightRef = useRef(0);
  const lastCommandExecutionRef = useRef<{ cmd: string; timestamp: number } | null>(null);

  // Drag-to-resize handlers
  const handleMouseDownResize = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsDraggingHeight(true);
    dragStartYRef.current = e.clientY;
    dragStartHeightRef.current = terminalHeight;
  };

  useEffect(() => {
    let rafId: number | null = null;
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDraggingHeight) return;
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(() => {
        const delta = dragStartYRef.current - e.clientY;
        const newHeight = Math.max(140, Math.min(window.innerHeight * 0.85, dragStartHeightRef.current + delta));
        setTerminalHeight(newHeight);
      });
    };

    const handleMouseUp = () => {
      if (rafId) cancelAnimationFrame(rafId);
      setIsDraggingHeight(false);
    };

    if (isDraggingHeight) {
      document.body.style.cursor = "ns-resize";
      document.body.style.userSelect = "none";
      window.addEventListener("mousemove", handleMouseMove);
      window.addEventListener("mouseup", handleMouseUp);
    } else {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    }
    return () => {
      if (rafId) cancelAnimationFrame(rafId);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isDraggingHeight, setTerminalHeight]);

  // Listen for external run commands (e.g. from RUN button or Cmd+Enter)
  useEffect(() => {
    const handleRunInTerminal = (e: any) => {
      const { command, sessionId } = e.detail || {};
      if (!command) return;
      const targetSession =
        (sessionId ? terminalSessions.find((s) => s.id === sessionId) : null) ||
        activeSession;
      if (targetSession) {
        setActiveTerminalSessionId(targetSession.id);
        setActiveTabType("session");
        executeCommandInSession(targetSession, command);
      }
    };

    window.addEventListener("crux:run-terminal" as any, handleRunInTerminal);
    return () => window.removeEventListener("crux:run-terminal" as any, handleRunInTerminal);
  }, [activeSession, terminalSessions]);

  // Execute pending run command queued from store (e.g. RUN button clicked while drawer was closed)
  useEffect(() => {
    if (pendingTerminalCommand && activeSession) {
      const cmd = pendingTerminalCommand;
      setPendingTerminalCommand(null);
      setActiveTabType("session");
      setActiveTerminalTab("terminal");
      executeCommandInSession(activeSession, cmd);
    }
  }, [pendingTerminalCommand, activeSession]);

  // Synchronize store tab state with local tab view
  useEffect(() => {
    if (activeTerminalTab === "output") {
      setActiveTabType("output");
    } else if (activeTerminalTab === "terminal" || activeTerminalTab === "repl") {
      setActiveTabType("session");
    }
  }, [activeTerminalTab]);

  // Jump to file and line when clicking a hyperlink (e.g. auth.ts:14)
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

  // 11.2 ZERO-CLICK AUTO-HEALING (THE "GHOST" FIX)
  const triggerAutoHealing = async (session: TerminalSession, exitCode: number) => {
    const lastLines = session.lines.slice(-15).map((l) => l.rawText).join("\n");

    // Do NOT trigger auto-healing for shell errors, command not found, or user cancellation
    if (
      exitCode === 127 ||
      exitCode === 130 ||
      exitCode === 143 ||
      lastLines.includes("command not found") ||
      lastLines.includes(": not found") ||
      lastLines.includes("No such file or directory")
    ) {
      return;
    }

    // Must have a recognizable language compilation or runtime exception signature
    const hasCodeErrorSignature =
      /(?:SyntaxError|TypeError|ReferenceError|CompileError|error:|cannot find symbol|reached end of file|unclosed|Exception in thread|Traceback|Compilation failed|build failed|fatal error|panic)/i.test(
        lastLines
      );

    // Extract failing file and line from last lines of terminal output
    const fileMatch = lastLines.match(
      /(?:([a-zA-Z0-9_.-]+\.(?:java|ts|tsx|js|jsx|py|rs|c|cpp|go|rb|php|html|css|json)))[:\s]+(?:line\s+)?(\d+)/i
    );

    if (!hasCodeErrorSignature && !fileMatch) {
      return;
    }

    let currentTarget = null;
    let targetLine = cursorPos.line;

    if (fileMatch) {
      const detectedName = fileMatch[1];
      targetLine = parseInt(fileMatch[2], 10) || cursorPos.line;
      currentTarget = files.find(
        (f) =>
          f.name.toLowerCase() === detectedName.toLowerCase() ||
          f.path.toLowerCase().endsWith(detectedName.toLowerCase())
      ) || null;
    } else if (hasCodeErrorSignature && activeFile) {
      // Only target active file if the error belongs to its language
      const ext = activeFile.name.split(".").pop()?.toLowerCase();
      const matchesLanguage =
        (ext === "java" && (lastLines.includes("java") || lastLines.includes("javac") || lastLines.includes("Exception"))) ||
        ((ext === "ts" || ext === "js") && (lastLines.includes("node") || lastLines.includes("bun") || lastLines.includes("TypeError") || lastLines.includes("SyntaxError"))) ||
        (ext === "py" && (lastLines.includes("python") || lastLines.includes("Traceback")));
      if (matchesLanguage) {
        currentTarget = activeFile;
      }
    }

    // If no real file in the workspace matched, do not propose a hallucinated fix
    if (!currentTarget) {
      return;
    }

    setIsAutoHealing(true);

    try {
      const res = await fetch("/api/terminal/ai", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "auto-heal",
          stderr: lastLines,
          exitCode,
          activeFileName: currentTarget?.name || fileMatch?.[1] || "stream_syncer.ts",
          activeFileContent: currentTarget?.content || "",
          cursorLine: targetLine,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        const fixLocation = data.fixProposedIn || `${currentTarget?.name || "Practice.java"}:${targetLine}`;

        // Section 11.2 Terminal Visual: Pulsing line
        const pulsingLog = `[@CruxAI] Analyzing non-zero exit... Fix proposed in ${fixLocation}\n`;
        appendTerminalChunk(session.id, `\x1b[31m${pulsingLog}\x1b[0m`);
        setGhostFixMessage(`Fix proposed in ${fixLocation}`);

        setSessionDiagnosis(session.id, {
          summary: data.summary,
          suggestedCommand: data.suggestedCommand,
          suggestedDiff: data.suggestedDiff?.description || data.suggestedDiff,
        });

        // If file content was automatically healed (e.g. unclosed braces balanced), update workspace store immediately!
        if (data.fixedContent && currentTarget) {
          useWorkspaceStore.getState().updateFileContent(currentTarget.id, data.fixedContent);
          appendTerminalChunk(
            session.id,
            `\x1b[32m[@CruxAI] Auto-healed unclosed syntax in ${currentTarget.name}. Buffer synced.\x1b[0m\n`
          );
        }

        // Push Ghost Fix directly into editor's Suggesting Mode diffs!
        if (data.suggestedDiff && currentTarget) {
          addSuggestion({
            fileId: currentTarget.id,
            author: {
              id: "user-2",
              name: "CruxAI",
              avatar: "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=100&auto=format&fit=crop&q=80",
              color: "#ff5757",
              role: "Copilot",
              uid: "CRX-0001-AI",
            },
            from: 0,
            to: currentTarget.content.length,
            originalText: data.suggestedDiff.originalText || "input.close();",
            suggestedText:
              data.suggestedDiff.suggestedText ||
              "input.close();\n    }\n}",
            description: data.suggestedDiff.description || "@CruxAI Auto-Healing Ghost Fix",
          });
        }
      }
    } catch {
      // ignore
    } finally {
      setIsAutoHealing(false);
    }
  };

  // 11.1 CONTEXT-AWARE PROMPTS: Reads active editor context automatically
  const handleCheckAiPrompt = async (val: string) => {
    if (val.startsWith("?? ") && val.length > 4) {
      const promptQuery = val.slice(3).trim();
      const currentTarget = activeFile || files[0];

      try {
        const res = await fetch("/api/terminal/ai", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action: "generate-command",
            prompt: promptQuery,
            activeFileName: currentTarget?.name || "stream_syncer.ts",
            activeFileContent: currentTarget?.content || "",
            cursorLine: cursorPos.line,
          }),
        });

        if (res.ok) {
          const data = await res.json();
          setAiProposal({
            command: data.command,
            explanation: data.explanation,
            contextSummary: data.contextSummary || `${currentTarget?.name}:${cursorPos.line}`,
          });
        }
      } catch {
        // ignore
      }
    } else {
      setAiProposal(null);
    }
  };

  // Execute command in session with executor attribution (Multiplayer CRDT)
  const executeCommandInSession = async (
    session: TerminalSession,
    cmdToRun?: string,
    executorName?: string,
    executorColor?: string
  ) => {
    if (isReadOnly) return;

    const state = useWorkspaceStore.getState();
    const currentSession =
      state.terminalSessions.find((s) => s.id === session.id) || session;

    const rawCmd = cmdToRun !== undefined ? cmdToRun : currentSession.inputVal;

    // Command deduplication guard: ignore exact duplicate programmatic runs within 350ms
    if (cmdToRun !== undefined) {
      const now = Date.now();
      const last = lastCommandExecutionRef.current;
      if (last && last.cmd === cmdToRun.trim() && now - last.timestamp < 350) {
        return;
      }
      lastCommandExecutionRef.current = { cmd: cmdToRun.trim(), timestamp: now };
    }

    // Reset input
    setSessionInputVal(currentSession.id, "");
    setAiProposal(null);
    setGhostFixMessage(null);

    // If process is already streaming, route ANY input (including empty Enter keypress) directly to process stdin!
    // If process is already streaming, route ANY input (including empty Enter keypress) directly to process stdin!
    if (currentSession.isStreaming && cmdToRun === undefined) {
      appendTerminalChunk(currentSession.id, `${rawCmd}\n`);
      const isTauri = typeof window !== "undefined" && Boolean((window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__);
      if (isTauri && currentSession.activePid) {
        try {
          const { invoke } = await import("@tauri-apps/api/core");
          await invoke("terminal_input", { pid: currentSession.activePid, input: rawCmd });
        } catch (err) {
          console.error("Failed to send native stdin:", err);
        }
        return;
      }
      try {
        await fetch("/api/terminal/input", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pid: currentSession.activePid, input: rawCmd }),
        });
      } catch (err) {
        console.error("Failed to send stdin to process:", err);
      }
      return;
    }

    const trimmed = rawCmd.trim();
    if (!trimmed) return;

    // If time-travel is active, snap back to present before running
    if (terminalTimeTravelIndex !== null) {
      setTerminalTimeTravelIndex(null);
    }

    if (trimmed === "clear") {
      clearTerminalSession(session.id);
      return;
    }

    if (trimmed === "help") {
      addSessionHistory(session.id, trimmed);
      appendTerminalChunk(
        session.id,
        [
          "\x1b[1;36mCRUX HYPERTERMINAL ENGINE v2.0-PROD\x1b[0m\n",
          "  \x1b[32mcrux tools\x1b[0m          Inspect Auto-Picked AI tools & capability matrix\n",
          "  \x1b[32mcrux pick <tool>\x1b[0m    Pin primary AI engine (auto, agy, claude, codex, opencode, cursor, ollama)\n",
          "  \x1b[32mcrux scan\x1b[0m           Re-scan host computer for newly installed AI coding tools\n",
          "  \x1b[32mcrux doctor\x1b[0m         Validate PTY subsystem, search PATHs, and tool health\n",
          "  \x1b[32mcrux status\x1b[0m         Daemon, IPC socket, and peer latency status\n",
          "  \x1b[32mcrux config\x1b[0m         Open AI Agent & API Key Configuration GUI\n",
          "  \x1b[32magy | claude | codex | opencode | ollama\x1b[0m  Launch interactive tool REPLs\n",
          "  \x1b[35m<natural prompt>\x1b[0m    Auto-routed to active orchestrated AI engine\n",
          "  \x1b[37m<any shell cmd>\x1b[0m     Live POSIX shell commands (git, npm, bun, python, cargo)\n\n",
        ].join("")
      );
      return;
    }

    const pickMatch = trimmed.match(/^crux\s+pick(?:\s+(.*))?$/i);
    if (pickMatch && pickMatch[1]) {
      const target = pickMatch[1].trim().toLowerCase();
      setAiToolSelection(target);
    }

    if (trimmed === "crux scan") {
      rescanAiTools();
    }

    if (trimmed === "crux config" || trimmed.startsWith("crux config")) {
      addSessionHistory(session.id, trimmed);
      const currentCwd = session.cwd || useWorkspaceStore.getState().terminalSessions.find((s) => s.id === session.id)?.cwd;
      appendTerminalChunk(
        session.id,
        `\x1b[36mcrux-sh:${formatCwdPrompt(currentCwd)}$\x1b[0m ${trimmed}\n\x1b[1;36m[CRUX AI KERNEL]\x1b[0m Opening Agent Runtime Configuration GUI...\n\x1b[90mConfigure API keys, model presets, or local daemons.\x1b[0m\n\n`
      );
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("crux:open-agent-config"));
      }
      return;
    }

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

    // Tag executor for remote multiplayer CRDT (e.g. [Sarah L.] npm run build)
    const currentCwd = session.cwd || useWorkspaceStore.getState().terminalSessions.find((s) => s.id === session.id)?.cwd;
    const executorTag = executorName ? `\x1b[36m[${executorName}]\x1b[0m ` : `\x1b[36mcrux-sh:${formatCwdPrompt(currentCwd)}$\x1b[0m `;
    // Flush dirty files before executing terminal commands
    try {
      const { saveFileToDisk } = await import("@/lib/fileUtils");
      const currentFiles = useWorkspaceStore.getState().files;
      const dirtyFiles = currentFiles.filter((f) => f.isDirty);
      if (dirtyFiles.length > 0) {
        await Promise.all(dirtyFiles.map((f) => saveFileToDisk(f)));
      }
    } catch {
      // ignore
    }

    const execStartTime = Date.now();
    const collectedStdout: string[] = [];
    const collectedStderr: string[] = [];
    const stripAnsi = (str: string) => str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");

    addSessionHistory(session.id, trimmed);
    appendTerminalChunk(session.id, `${executorTag}${trimmed}\n`);
    setSessionStreaming(session.id, true, null);
    setSessionExitCode(session.id, null);

    const isTauri = typeof window !== "undefined" && Boolean((window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__);

    // 1. NATIVE TAURI DESKTOP EXECUTION (Standalone mode)
    if (isTauri) {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const { listen } = await import("@tauri-apps/api/event");

        const pid = await invoke<number>("terminal_spawn", {
          command: trimmed,
          cwd: session.cwd || null,
        });

        setSessionStreaming(session.id, true, pid);

        let unlistenFn: (() => void) | null = null;
        unlistenFn = await listen<any>(`terminal-event-${pid}`, (event) => {
          const payload = event.payload;
          if (!payload) return;

          if (payload.type === "stdout" && payload.data) {
            appendTerminalChunk(session.id, payload.data, false);
            const clean = stripAnsi(payload.data);
            clean.split("\n").forEach((l) => { if (l.trim() || collectedStdout.length > 0) collectedStdout.push(l); });
          } else if (payload.type === "stderr" && payload.data) {
            appendTerminalChunk(session.id, payload.data, true);
            const clean = stripAnsi(payload.data);
            clean.split("\n").forEach((l) => { if (l.trim() || collectedStderr.length > 0) collectedStderr.push(l); });
          } else if (payload.type === "exit") {
            setSessionStreaming(session.id, false, null);
            const exitCode = payload.code ?? 0;
            setSessionExitCode(session.id, exitCode);

            setLastExecutionResult({
              stdout: collectedStdout,
              stderr: collectedStderr,
              durationMs: Date.now() - execStartTime,
              success: exitCode === 0,
              timestamp: Date.now(),
              fileName: activeFile?.name || (trimmed.split(" ")[1] || "terminal"),
            });

            if (exitCode !== 0 && exitCode !== 130) {
              triggerAutoHealing(session, exitCode);
            }

            if (unlistenFn) {
              unlistenFn();
              unlistenFn = null;
            }
          }
        });
        return;
      } catch (nativeErr: any) {
        appendTerminalChunk(session.id, `\x1b[31mNative execution failed: ${nativeErr?.message || nativeErr}\x1b[0m\n`, true);
        setSessionStreaming(session.id, false, null);
        setSessionExitCode(session.id, 1);
        setLastExecutionResult({
          stdout: collectedStdout,
          stderr: [`Native execution failed: ${nativeErr?.message || nativeErr}`],
          durationMs: Date.now() - execStartTime,
          success: false,
          timestamp: Date.now(),
          fileName: activeFile?.name || "terminal",
        });
        triggerAutoHealing(session, 1);
        return;
      }
    }

    // 2. HTTP SERVER-SENT EVENTS FALLBACK (Browser mode)
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
        setLastExecutionResult({
          stdout: collectedStdout,
          stderr: [`Execution failed with HTTP ${response.status}`],
          durationMs: Date.now() - execStartTime,
          success: false,
          timestamp: Date.now(),
          fileName: activeFile?.name || "terminal",
        });
        triggerAutoHealing(session, 1);
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
                if (trimmed === "agy" || trimmed === "antigravity") {
                  setSessionName(session.id, "agy");
                } else if (trimmed === "claude") {
                  setSessionName(session.id, "claude");
                } else if (trimmed === "codex" || trimmed === "codec") {
                  setSessionName(session.id, "codex");
                } else if (trimmed === "opencode" || trimmed === "open-code") {
                  setSessionName(session.id, "opencode");
                } else if (trimmed === "cursor") {
                  setSessionName(session.id, "cursor");
                } else if (trimmed === "ollama") {
                  setSessionName(session.id, "ollama");
                }
              } else if (event.type === "tool-pinned") {
                setAiToolSelection(event.toolId);
              } else if (event.type === "stdout") {
                appendTerminalChunk(session.id, event.data, false);
                const clean = stripAnsi(event.data);
                clean.split("\n").forEach((l) => { if (l.trim() || collectedStdout.length > 0) collectedStdout.push(l); });
              } else if (event.type === "stderr") {
                appendTerminalChunk(session.id, event.data, true);
                const clean = stripAnsi(event.data);
                clean.split("\n").forEach((l) => { if (l.trim() || collectedStderr.length > 0) collectedStderr.push(l); });
              } else if (event.type === "file-created") {
                useWorkspaceStore.getState().createFileInPath(event.filename, event.content);
                const currentFiles = useWorkspaceStore.getState().files;
                const found = currentFiles.find(
                  (f) => f.name === event.filename || f.path.endsWith(event.filename)
                );
                if (found) {
                  useWorkspaceStore.getState().setActiveFile(found.id);
                }
              } else if (event.type === "cwd") {
                setSessionCwd(session.id, event.cwd);
              } else if (event.type === "clear") {
                clearTerminalSession(session.id);
              } else if (event.type === "exit") {
                setSessionStreaming(session.id, false, null);
                setSessionExitCode(session.id, event.code);
                if (["agy", "claude", "codex", "opencode", "cursor", "ollama"].includes(session.name)) {
                  setSessionName(session.id, "crux-sh");
                }

                setLastExecutionResult({
                  stdout: collectedStdout,
                  stderr: collectedStderr,
                  durationMs: Date.now() - execStartTime,
                  success: event.code === 0,
                  timestamp: Date.now(),
                  fileName: activeFile?.name || (trimmed.split(" ")[1] || "terminal"),
                });

                // ZERO-CLICK AUTO-HEALING TRIGGER ON NON-ZERO EXIT!
                if (event.code !== 0 && event.code !== 130) {
                  triggerAutoHealing(session, event.code);
                }
              }
            } catch {
              // Parse error
            }
          }
        }
      }
    } catch (err: any) {
      appendTerminalChunk(session.id, `\x1b[31mNetwork error: ${err.message}\x1b[0m\n`, true);
      setSessionStreaming(session.id, false, null);
      setSessionExitCode(session.id, 1);
      setLastExecutionResult({
        stdout: collectedStdout,
        stderr: [`Network error: ${err.message}`],
        durationMs: Date.now() - execStartTime,
        success: false,
        timestamp: Date.now(),
        fileName: activeFile?.name || "terminal",
      });
      triggerAutoHealing(session, 1);
    }
  };

  // Kill running process (Ctrl+C)
  const handleKillSessionProcess = async (session: TerminalSession) => {
    if (!session.activePid) {
      appendTerminalChunk(session.id, "^C\n");
      setSessionStreaming(session.id, false, null);
      return;
    }

    const isTauri = typeof window !== "undefined" && Boolean((window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__);
    if (isTauri) {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("terminal_kill", { pid: session.activePid });
        appendTerminalChunk(session.id, `\x1b[33m^C [Process ${session.activePid} terminated]\x1b[0m\n`);
      } catch {
        // ignore
      } finally {
        setSessionStreaming(session.id, false, null);
        setSessionExitCode(session.id, 130);
      }
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

  // Simulate remote peer execution test
  const handleSimulateRemotePeer = (peerName: string, peerColor: string, cmd: string) => {
    executeCommandInSession(activeSession, cmd, peerName, peerColor);
  };

  if (!isTerminalOpen) return null;

  // Time-travel calculation
  const totalLines = activeSession.lines.length;
  const isTimeTraveling = terminalTimeTravelIndex !== null;
  const displayedLines = isTimeTraveling
    ? activeSession.lines.slice(0, Math.max(1, terminalTimeTravelIndex))
    : activeSession.lines;

  return (
    <footer
      style={{ height: isTerminalMaximized ? "85vh" : `${terminalHeight}px` }}
      className={`border-t border-grid bg-surface flex flex-col shrink-0 font-sans select-none relative overflow-hidden ${
        isDraggingHeight ? "transition-none select-none" : "transition-[height] duration-200 ease-[cubic-bezier(0.16,1,0.3,1)]"
      }`}
    >
      {/* DRAG RESIZE HANDLE */}
      <div
        onMouseDown={handleMouseDownResize}
        className="absolute top-0 left-0 right-0 h-1 cursor-ns-resize hover:bg-signal/50 z-30 transition-colors"
        title="Drag to resize terminal height"
      />

      {/* TOP HEADER / SESSION TABS BAR (LOCKED AT STRICT h-9 / 36px) */}
      <div className="flex h-9 border-b border-grid bg-void items-center justify-between shrink-0 select-none px-0">
        {/* Left: Session Tabs */}
        <div className="flex h-full items-center overflow-x-auto">
          {terminalSessions.map((session) => {
            const isActive = session.id === activeTerminalSessionId && activeTabType === "session";
            return (
              <div
                key={session.id}
                onClick={() => {
                  setActiveTerminalSessionId(session.id);
                  setActiveTabType("session");
                  setActiveTerminalTab("terminal");
                }}
                className={`px-3.5 h-full text-[11px] font-mono border-r border-grid uppercase tracking-wider transition-colors flex items-center gap-2 cursor-pointer shrink-0 ${
                  isActive
                    ? "text-signal bg-void font-medium"
                    : "text-muted hover:text-signal bg-surface"
                }`}
              >
                <div className="flex items-center gap-1.5">
                  {session.isStreaming ? (
                    <span className="w-1.5 h-1.5 rounded-none bg-white animate-ping" />
                  ) : session.lastExitCode !== null && session.lastExitCode !== 0 ? (
                    <span className="w-1.5 h-1.5 rounded-none bg-[#888888]" />
                  ) : (
                    <span className="w-1.5 h-1.5 rounded-none bg-[#444444]" />
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

          {/* Tab: Output (V8 Sandbox Result) */}
          <button
            onClick={() => {
              setActiveTabType("output");
              setActiveTerminalTab("output");
            }}
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

        {/* Center: SECTION 13 TERMINAL TIME-TRAVEL SLIDER (STARK 1px #222222 LINE) */}
        {activeTabType === "session" && totalLines > 2 && (
          <div className="flex items-center gap-2 px-4 h-full border-r border-l border-grid bg-void flex-1 max-w-xs select-none">
            <History
              className={`w-3 h-3 shrink-0 ${
                isTimeTraveling ? "text-accent2 animate-pulse" : "text-muted"
              }`}
            />
            <span className="text-[10px] font-mono text-muted uppercase shrink-0">Rewind</span>
            <input
              data-testid="terminal-timetravel-slider"
              type="range"
              min={1}
              max={totalLines}
              value={terminalTimeTravelIndex !== null ? terminalTimeTravelIndex : totalLines}
              onChange={(e) => {
                const val = parseInt(e.target.value, 10);
                if (val >= totalLines) {
                  setTerminalTimeTravelIndex(null);
                } else {
                  setTerminalTimeTravelIndex(val);
                }
              }}
              className="w-full h-[1px] bg-grid accent-signal cursor-pointer"
              title="Drag backward to rewind terminal buffer (Time-Travel)"
            />
            <span className="text-[10px] font-mono text-muted shrink-0 w-8 text-right">
              {terminalTimeTravelIndex !== null ? `T-${totalLines - terminalTimeTravelIndex}` : "NOW"}
            </span>
          </div>
        )}

        {/* Right: Multiplayer Peers, Split, Search, Maximize & Close Controls */}
        <div className="flex items-center gap-2 px-3 text-muted shrink-0">
          {/* Section 12.1 Multiplayer Peers Indicator */}
          <div className="hidden sm:flex items-center gap-1.5 pr-2 border-r border-grid">
            <span
              className="w-2 h-2 bg-[#38b6ff] cursor-pointer"
              onClick={() => handleSimulateRemotePeer("Sarah L.", "#38b6ff", "crux build")}
              title="Remote Peer: Sarah Lin (Click to simulate remote execution)"
            />
            <span
              className="w-2 h-2 bg-[#ff914d] cursor-pointer"
              onClick={() => handleSimulateRemotePeer("Marcus Vance", "#ff914d", "git status --short")}
              title="Remote Peer: Marcus Vance (Click to simulate remote execution)"
            />
          </div>

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

          {/* Kill Running Process Button */}
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

          {/* AI Engine Auto-Pick Orchestration HUD Dropdown */}
          <div className="relative">
            <button
              onClick={() => setIsAiMenuOpen(!isAiMenuOpen)}
              className="px-2 py-0.5 border border-grid bg-void text-white hover:border-white transition-none text-[10px] font-mono flex items-center gap-1.5 shrink-0 cursor-pointer uppercase tracking-wider"
              title="Orchestrated AI Coding Tool Selector & Auto-Pick Engine"
            >
              <Sparkles className="w-3 h-3 text-white shrink-0" />
              <span>
                {activeAiToolId === "auto"
                  ? `[AI: ⚡ AUTO // ${(autoPickedTool?.name || "AGY").split("(")[0].trim()}]`
                  : `[AI: 📌 ${(activeAiTool?.name || activeAiToolId).split("(")[0].trim()}]`}
              </span>
              <ChevronDown className="w-3 h-3 text-white ml-0.5 shrink-0" />
            </button>

            {isAiMenuOpen && (
              <div className="absolute right-0 top-7 w-80 bg-[#000000] border border-[#222222] z-50 p-2 shadow-none font-mono text-[11px] select-none">
                <div className="text-[10px] text-[#888888] uppercase tracking-wider px-2 py-1 border-b border-[#222222] flex items-center justify-between">
                  <span>AI Tools Orchestrator</span>
                  <span className="text-white font-bold">{discoveredRuntimes.filter((r) => r.available).length} Detected</span>
                </div>

                <div className="py-1 space-y-0.5 max-h-72 overflow-y-auto no-scrollbar">
                  {/* Option 1: Auto-Pick */}
                  <button
                    onClick={() => {
                      setAiToolSelection("auto");
                      setIsAiMenuOpen(false);
                      appendTerminalChunk(
                        activeSession.id,
                        `\x1b[32m[CRUX ORCHESTRATION] Primary AI Engine reset to AUTO-PICK (Recommended).\x1b[0m\n`
                      );
                    }}
                    className={`w-full text-left px-2 py-1.5 flex flex-col transition-none cursor-pointer border ${
                      activeAiToolId === "auto"
                        ? "bg-[#FFFFFF] text-[#000000] border-[#FFFFFF] font-bold"
                        : "bg-transparent text-white border-transparent hover:bg-[#222222]"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-1.5">
                        <span>⚡ AUTO-PICK (Optimal)</span>
                      </span>
                      <span className="text-[9px] uppercase px-1 border border-current">Recommended</span>
                    </div>
                    <span
                      className={`text-[9px] ${
                        activeAiToolId === "auto" ? "text-black/80" : "text-[#888888]"
                      } pt-0.5 truncate`}
                    >
                      {autoPickedTool
                        ? `Routes to: ${autoPickedTool.name} [Affinity: ${autoPickedTool.affinityScore || 95}pts]`
                        : "Auto-selects optimal engine by workspace contracts"}
                    </span>
                  </button>

                  <div className="my-1 border-t border-[#222222]" />

                  {/* Discovered Tools List */}
                  {discoveredRuntimes
                    .filter((r) => r.available && (r.provider || r.category === "ai"))
                    .map((tool) => {
                      const isSelected = activeAiToolId === tool.id || activeAiToolId === tool.binaryName;
                      const isWinner = tool.id === autoPickedTool?.id || tool.binaryName === autoPickedTool?.binaryName;

                      return (
                        <button
                          key={tool.id}
                          onClick={() => {
                            setAiToolSelection(tool.binaryName || tool.id);
                            setIsAiMenuOpen(false);
                            appendTerminalChunk(
                              activeSession.id,
                              `\x1b[32m[CRUX ORCHESTRATION] Primary AI Engine pinned to: ${tool.name}\x1b[0m\n`
                            );
                          }}
                          className={`w-full text-left px-2 py-1.5 flex flex-col transition-none cursor-pointer border ${
                            isSelected
                              ? "bg-[#FFFFFF] text-[#000000] border-[#FFFFFF] font-bold"
                              : "bg-transparent text-white border-transparent hover:bg-[#222222]"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="flex items-center gap-1.5">
                              <span>●</span>
                              <span className="truncate">{tool.name}</span>
                            </span>
                            <span className="text-[9px] text-[#888888] font-mono shrink-0 ml-1">
                              {isWinner ? "[AUTO]" : `${tool.latencyMs || 0}ms`}
                            </span>
                          </div>
                          <span
                            className={`text-[9px] ${
                              isSelected ? "text-black/70" : "text-[#666666]"
                            } truncate`}
                          >
                            {tool.binaryPath || tool.status}
                          </span>
                        </button>
                      );
                    })}
                </div>

                <div className="pt-2 border-t border-[#222222] flex items-center justify-between">
                  <button
                    onClick={async () => {
                      await rescanAiTools();
                      appendTerminalChunk(
                        activeSession.id,
                        `\x1b[32m[CRUX DISCOVERY] Host computer re-scan complete. All AI tools refreshed.\x1b[0m\n`
                      );
                    }}
                    className="px-2 py-0.5 border border-[#333333] bg-[#111111] text-[#CCCCCC] hover:bg-[#FFFFFF] hover:text-[#000000] text-[10px] transition-none cursor-pointer uppercase font-bold"
                  >
                    [↻ RE-SCAN]
                  </button>
                  <button
                    onClick={() => {
                      setIsAiMenuOpen(false);
                      executeCommandInSession(activeSession, "crux tools");
                    }}
                    className="px-2 py-0.5 text-[#888888] hover:text-white text-[10px] transition-none cursor-pointer uppercase font-bold"
                  >
                    [VIEW MATRIX]
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* AI Config Modal Button */}
          <button
            onClick={() => {
              if (typeof window !== "undefined") {
                window.dispatchEvent(new CustomEvent("crux:open-agent-config"));
              }
            }}
            title="Configure AI Agents & API Keys (crux config)"
            className="px-2 py-0.5 border border-grid bg-void text-[#CCCCCC] hover:text-white hover:border-white transition-none text-[10px] font-mono flex items-center gap-1 shrink-0"
          >
            <Settings className="w-3 h-3 text-white" />
            <span>AI CONFIG</span>
          </button>

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

      {/* SECTION 13 TIME-TRAVEL ACTIVE BANNER */}
      {isTimeTraveling && (
        <div className="bg-[#1A0505] border-b border-[#FF453A]/40 px-4 py-1 flex items-center justify-between text-[11px] font-mono text-accent2 shrink-0 select-none">
          <div className="flex items-center gap-2">
            <History className="w-3.5 h-3.5 text-accent2 animate-pulse" />
            <span className="font-bold tracking-wider">
              TIME-TRAVEL ACTIVE: Viewing historical buffer snapshot (T-{totalLines - terminalTimeTravelIndex!})
            </span>
          </div>
          <button
            onClick={() => setTerminalTimeTravelIndex(null)}
            className="px-2 py-0.5 border border-accent2/60 bg-void text-accent2 hover:bg-accent2 hover:text-white transition-colors text-[10px] uppercase font-bold"
          >
            Jump to Present ↵
          </button>
        </div>
      )}

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

      {/* VIEWPORT AREA: SHIFTS TO #1A0505 WHEN TIME-TRAVEL SCRUBBING */}
      <div
        style={{ backgroundColor: isTimeTraveling ? "#1A0505" : "#000000" }}
        className="flex-1 overflow-hidden flex min-h-0 transition-colors duration-150"
      >
        {activeTabType === "output" ? (
          /* V8 SANDBOX OUTPUT VIEW */
          <div className="flex-1 p-4 font-mono text-[12px] overflow-auto select-text space-y-2">
            {lastExecutionResult ? (
              <>
                <div className="flex items-center justify-between pb-1.5 border-b border-grid/60">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 border ${
                        lastExecutionResult.success
                          ? "border-white text-white bg-transparent"
                          : "border-[#444444] text-[#888888] bg-transparent"
                      }`}
                    >
                      {lastExecutionResult.success ? (
                        <span className="inline-flex items-center gap-1 font-mono">
                          <Check className="w-3 h-3 inline" /> EXIT 0
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 font-mono">
                          <X className="w-3 h-3 inline" /> EXIT 1
                        </span>
                      )}
                    </span>
                    <span className="text-white font-mono text-[11px] font-bold">
                      {lastExecutionResult.fileName || "buffer"}
                    </span>
                  </div>
                  <span className="text-[#888888] font-mono text-[11px]">
                    {lastExecutionResult.durationMs?.toFixed(2)}ms
                  </span>
                </div>

                {lastExecutionResult.stdout && lastExecutionResult.stdout.length > 0 && (
                  <div className="space-y-0.5 font-mono text-[12px]">
                    {lastExecutionResult.stdout.map((out, idx) => (
                      <div key={idx} className="text-white whitespace-pre-wrap">
                        {out}
                      </div>
                    ))}
                  </div>
                )}

                {lastExecutionResult.stderr && lastExecutionResult.stderr.length > 0 && (
                  <div className="space-y-0.5 font-mono text-[12px]">
                    {lastExecutionResult.stderr.map((err, idx) => (
                      <div key={idx} className="text-[#AAAAAA] whitespace-pre-wrap">
                        {err}
                      </div>
                    ))}
                  </div>
                )}

                {lastExecutionResult.returnValue !== undefined && (
                  <div className="text-[#888888] font-mono text-[11px]">
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
          /* TERMINAL SESSIONS VIEW (Single or Split Panes) */
          <div
            className={`flex-1 flex min-h-0 overflow-hidden ${
              terminalSplitMode === "horizontal" ? "flex-col" : "flex-row"
            }`}
          >
            {/* Primary Session Pane */}
            <TerminalPaneView
              session={activeSession}
              lines={displayedLines}
              isTimeTraveling={isTimeTraveling}
              searchQuery={terminalSearchQuery}
              aiProposal={aiProposal}
              isAutoHealing={isAutoHealing}
              ghostFixMessage={ghostFixMessage}
              isReadOnly={isReadOnly}
              activeFileName={activeFile?.name || "stream_syncer.ts"}
              cursorLine={cursorPos.line}
              files={files}
              onOpenFileLink={handleOpenFileLink}
              onSubmitCommand={(cmd) => executeCommandInSession(activeSession, cmd)}
              onKillProcess={() => handleKillSessionProcess(activeSession)}
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
              onTriggerAutoHeal={() => triggerAutoHealing(activeSession, 1)}
              discoveredRuntimes={discoveredRuntimes}
              activeAiToolId={activeAiToolId}
              autoPickedAiToolId={autoPickedAiToolId}
              onSelectTool={setAiToolSelection}
            />

            {/* Secondary Split Pane (if active) */}
            {terminalSplitMode !== "none" && secondarySession && (
              <div
                className={`flex-1 flex flex-col ${
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
                  lines={secondarySession.lines}
                  isTimeTraveling={false}
                  searchQuery={terminalSearchQuery}
                  aiProposal={null}
                  isAutoHealing={false}
                  ghostFixMessage={null}
                  isReadOnly={isReadOnly}
                  activeFileName={activeFile?.name || "stream_syncer.ts"}
                  cursorLine={cursorPos.line}
                  files={files}
                  onOpenFileLink={handleOpenFileLink}
                  onSubmitCommand={(cmd) => executeCommandInSession(secondarySession, cmd)}
                  onKillProcess={() => handleKillSessionProcess(secondarySession)}
                  onInputChange={(val) => setSessionInputVal(secondarySession.id, val)}
                  onAcceptAiProposal={() => {}}
                  onCancelAiProposal={() => {}}
                  onTriggerAutoHeal={() => {}}
                  discoveredRuntimes={discoveredRuntimes}
                  activeAiToolId={activeAiToolId}
                  autoPickedAiToolId={autoPickedAiToolId}
                  onSelectTool={setAiToolSelection}
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
  lines: AnsiLine[];
  isTimeTraveling: boolean;
  searchQuery: string;
  aiProposal: { command: string; explanation: string; contextSummary: string } | null;
  isAutoHealing: boolean;
  ghostFixMessage: string | null;
  isReadOnly: boolean;
  activeFileName: string;
  cursorLine: number;
  files: any[];
  onOpenFileLink: (path: string, line?: number, col?: number) => void;
  onSubmitCommand: (cmd?: string) => void;
  onKillProcess: () => void;
  onInputChange: (val: string) => void;
  onAcceptAiProposal: (cmd: string) => void;
  onCancelAiProposal: () => void;
  onTriggerAutoHeal: () => void;
  discoveredRuntimes?: any[];
  activeAiToolId?: string;
  autoPickedAiToolId?: string;
  onSelectTool?: (toolId: string) => void;
}

function TerminalPaneView({
  session,
  lines,
  isTimeTraveling,
  searchQuery,
  aiProposal,
  isAutoHealing,
  ghostFixMessage,
  isReadOnly,
  activeFileName,
  cursorLine,
  files,
  onOpenFileLink,
  onSubmitCommand,
  onKillProcess,
  onInputChange,
  onAcceptAiProposal,
  onCancelAiProposal,
  onTriggerAutoHeal,
  discoveredRuntimes = [],
  activeAiToolId = "auto",
  autoPickedAiToolId = "antigravity-agy",
  onSelectTool,
}: TerminalPaneViewProps) {
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const isScrolledToBottomRef = useRef(true);

  // Track user scroll position: if user scrolled up to read history, don't force scroll down
  const handleScroll = useCallback(() => {
    if (!scrollContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollContainerRef.current;
    isScrolledToBottomRef.current = scrollHeight - scrollTop - clientHeight < 60;
  }, []);

  // Butter-smooth hardware-accelerated auto-scroll via requestAnimationFrame
  useEffect(() => {
    if (!isTimeTraveling && isScrolledToBottomRef.current && scrollContainerRef.current) {
      requestAnimationFrame(() => {
        if (scrollContainerRef.current) {
          scrollContainerRef.current.scrollTop = scrollContainerRef.current.scrollHeight;
        }
      });
    }
  }, [lines, isTimeTraveling]);

  useEffect(() => {
    if (session.isStreaming) {
      inputRef.current?.focus();
    }
  }, [session.isStreaming, lines.length]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    // Ctrl+C to abort running process (preserve Cmd+C for clipboard copy on macOS)
    if (e.ctrlKey && !e.metaKey && e.key.toLowerCase() === "c") {
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
    ? lines.filter((l) => l.rawText.toLowerCase().includes(searchQuery.toLowerCase()))
    : lines;

  return (
    <div
      onClick={() => inputRef.current?.focus()}
      className="flex-1 p-3 font-mono text-[12px] flex flex-col min-h-0 select-text cursor-text"
    >
      {/* Scrollable Output Stream — min-h-0 + overflow-y-auto lets flex child scroll */}
      <div
        ref={scrollContainerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto space-y-0.5 min-h-0 select-text scrollbar-thin scrollbar-thumb-grid/50"
      >
        {filteredLines.map((line) => {
          const isAgent = line.executorName?.toLowerCase().includes("ai");
          return (
            <div
              key={line.id}
              className={`leading-snug break-all ${
                isAgent ? "pl-3 border-l border-[#222222]" : ""
              }`}
            >
              {line.executorName && (
                <span className="font-bold mr-1.5 text-white font-mono">
                  {isAgent ? (
                    "[@CruxAI]"
                  ) : (
                    <>
                      [{line.executorName}]
                      <span className="inline-block w-1.5 h-1.5 bg-white animate-hard-blink ml-1.5 mr-1 align-middle" />
                      <span className="text-[10px] text-white animate-hard-blink">[LIVE]</span>
                    </>
                  )}
                </span>
              )}

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
        );
      })}

        {/* SECTION 11.2 ZERO-CLICK AUTO-HEALING BANNER (ABSOLUTE FLATNESS: PURE #000000, 1px #FF453A BORDER) */}
        {session.lastExitCode !== null && session.lastExitCode !== 0 && (
          <div className="my-2 p-3 border border-[#FF453A] bg-[#000000] space-y-2 select-none">
            <div className="flex items-center justify-between text-[11px]">
              <div className="flex items-center gap-2 text-accent2 font-bold">
                <AlertTriangle className="w-3.5 h-3.5 text-accent2 shrink-0" />
                <span className="animate-pulse">
                  [@CruxAI] Analyzing non-zero exit ({session.lastExitCode})...{" "}
                  {ghostFixMessage || `Fix proposed in ${activeFileName}:${cursorLine}`}
                </span>
              </div>
              <button
                onClick={onTriggerAutoHeal}
                disabled={isAutoHealing}
                className="px-2 py-0.5 border border-[#FF453A] bg-[#000000] text-signal hover:bg-[#FF453A] hover:text-white transition-colors text-[10px] uppercase font-bold flex items-center gap-1"
              >
                <Sparkles className="w-3 h-3 text-accent2" />
                <span>{isAutoHealing ? "Healing..." : "Re-Diagnose"}</span>
              </button>
            </div>

            {session.lastDiagnosis && (
              <div className="pt-1.5 text-[11px] font-sans border-t border-[#FF453A]/30 text-muted space-y-1.5">
                <div className="text-signal font-medium">{session.lastDiagnosis.summary}</div>
                {session.lastDiagnosis.suggestedCommand && (
                  <div className="flex items-center gap-2 pt-1 font-mono text-[10px]">
                    <span className="text-muted">Command Fix:</span>
                    <code className="text-[#00FF00] bg-[#0A0A0A] px-1.5 py-0.5 border border-grid">
                      {session.lastDiagnosis.suggestedCommand}
                    </code>
                    <button
                      onClick={() => onSubmitCommand(session.lastDiagnosis!.suggestedCommand)}
                      className="px-2 py-0.5 border border-grid bg-void text-signal hover:border-signal uppercase text-[9px] font-medium"
                    >
                      Apply &amp; Run ↵
                    </button>
                  </div>
                )}
                {session.lastDiagnosis.suggestedDiff && (
                  <div className="text-[10px] text-white pt-0.5 font-mono flex items-center gap-1">
                    <Check className="w-3 h-3 text-white inline" />
                    <span>Ghost Fix proposed directly into Suggesting Mode diff in editor.</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* SECTION 11.1 CONTEXT-AWARE AI COMMAND PROPOSAL (FLAT, #007AFF CRUX BLUE LEFT BORDER, STARK WHITE [RUN]) */}
      {aiProposal && (
        <div className="mb-2 p-2.5 border-t border-r border-b border-grid border-l-2 border-l-[#007AFF] bg-[#000000] text-[11px] space-y-1.5 select-none">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-signal font-bold">
              <Sparkles className="w-3.5 h-3.5 text-[#007AFF]" />
              <span>@CruxAI Command Synthesizer</span>
              <span className="px-1.5 py-0.2 text-[9px] font-mono border border-grid bg-[#0A0A0A] text-[#007AFF]">
                Context: {aiProposal.contextSummary}
              </span>
            </div>
            <button
              onClick={onCancelAiProposal}
              className="text-muted hover:text-signal text-[10px]"
            >
              [Esc to Cancel]
            </button>
          </div>
          <div className="text-muted font-sans text-[11px]">{aiProposal.explanation}</div>
          <div className="flex items-center gap-2 pt-1">
            <code className="flex-1 bg-[#0A0A0A] border border-grid p-1.5 text-[#00FF00] font-mono text-[11px]">
              {aiProposal.command}
            </code>
            <button
              onClick={() => onAcceptAiProposal(aiProposal.command)}
              className="px-3 py-1 bg-white text-black hover:bg-neutral-200 font-bold text-[10px] uppercase transition-colors shrink-0"
            >
              Run ↵
            </button>
          </div>
        </div>
      )}

      {/* SECTION 12.2 READ-ONLY OBSERVER MODE PROMPT REPLACEMENT */}
      {isReadOnly ? (
        <div className="flex items-center justify-between p-2 border-t border-grid bg-[#0A0A0A] text-[#777] font-mono text-[11px] select-none shrink-0">
          <div className="flex items-center gap-2 text-accent2">
            <Lock className="w-3.5 h-3.5 text-accent2 shrink-0" />
            <span className="font-semibold tracking-wider uppercase">
              [READ-ONLY: Observing Host — Terminal Input Suspended by Host]
            </span>
          </div>
          <span className="text-muted text-[10px]">Connected (0.08ms)</span>
        </div>
      ) : (
        /* INTERACTIVE PROMPT WITH MULTIPLAYER PEER CURSORS */
        <div className="shrink-0 flex flex-col border-t border-grid/60 bg-void/30">
          {!session.isStreaming && !isReadOnly && (
            <div className="flex items-center gap-1.5 px-1 pt-1.5 pb-1 overflow-x-auto no-scrollbar shrink-0 text-[10px] font-mono select-none">
              <span className="text-[#666666] uppercase tracking-wider shrink-0 mr-0.5">[AI TOOLS]:</span>
              <button
                type="button"
                onClick={() => onSelectTool?.("auto")}
                className={`px-1.5 py-0.5 border transition-none cursor-pointer shrink-0 font-bold ${
                  activeAiToolId === "auto"
                    ? "border-white bg-white text-black"
                    : "border-[#333333] bg-[#111111] text-[#CCCCCC] hover:bg-white hover:text-black"
                }`}
                title="Intelligent Auto-Pick based on workspace contracts"
              >
                ⚡ AUTO
              </button>
              {discoveredRuntimes
                .filter((r) => r.available && (r.provider || r.category === "ai"))
                .slice(0, 6)
                .map((t) => {
                  const isPinned = activeAiToolId === t.id || activeAiToolId === t.binaryName;
                  const bName = t.binaryName || t.id.replace(/^(ollama|claude|codex|opencode|cursor|antigravity)-/i, "");
                  return (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => onSubmitCommand(bName)}
                      className={`px-1.5 py-0.5 border transition-none cursor-pointer shrink-0 ${
                        isPinned
                          ? "border-white bg-[#222222] text-white font-bold"
                          : "border-[#222222] bg-[#111111] text-[#CCCCCC] hover:bg-white hover:text-black"
                      }`}
                      title={`Launch ${t.name} (Latency: ${t.latencyMs || 0}ms)`}
                    >
                      ● {bName}
                    </button>
                  );
                })}
              <span className="text-[#333333] shrink-0">|</span>
              <button
                type="button"
                onClick={() => onSubmitCommand("crux tools")}
                className="px-1.5 py-0.5 border border-[#222222] bg-[#111111] text-[#CCCCCC] hover:bg-white hover:text-black transition-none cursor-pointer shrink-0"
              >
                crux tools
              </button>
              <button
                type="button"
                onClick={() => onSubmitCommand("crux doctor")}
                className="px-1.5 py-0.5 border border-[#222222] bg-[#111111] text-[#CCCCCC] hover:bg-white hover:text-black transition-none cursor-pointer shrink-0"
              >
                crux doctor
              </button>
              <button
                type="button"
                onClick={() => onSubmitCommand("git status")}
                className="px-1.5 py-0.5 border border-[#222222] bg-[#111111] text-[#CCCCCC] hover:bg-white hover:text-black transition-none cursor-pointer shrink-0"
              >
                git status
              </button>
            </div>
          )}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              onSubmitCommand();
            }}
            className="flex items-center gap-2 pt-1 pb-1 relative"
          >
            {session.isStreaming ? (
              <div className="flex items-center gap-1.5 shrink-0 text-white">
                <span className="w-1.5 h-1.5 rounded-none bg-white animate-pulse" />
                <span className="font-mono text-[12px] font-bold tracking-wider">
                  {session.name?.toLowerCase().includes("claude") ? (
                    <span className="text-white">claude ❯</span>
                  ) : session.name?.toLowerCase().includes("agy") ? (
                    <span className="text-white">agy ❯</span>
                  ) : session.name?.toLowerCase().includes("codex") ? (
                    <span className="text-white">codex ❯</span>
                  ) : session.name?.toLowerCase().includes("opencode") ? (
                    <span className="text-white">opencode ❯</span>
                  ) : session.name?.toLowerCase().includes("cursor") ? (
                    <span className="text-white">cursor ❯</span>
                  ) : session.name?.toLowerCase().includes("ollama") ? (
                    <span className="text-white">ollama ❯</span>
                  ) : (
                    <span>&gt; stdin:</span>
                  )}
                </span>
              </div>
            ) : (
              <span className="text-signal shrink-0 font-bold font-mono text-[12px]">
                crux-sh:{formatCwdPrompt(session.cwd)}$
              </span>
            )}
          <div className="flex-1 relative flex items-center">
            <input
              data-testid="terminal-prompt-input"
              ref={inputRef}
              type="text"
              value={session.inputVal}
              onChange={(e) => onInputChange(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={
                session.isStreaming
                  ? session.name?.toLowerCase().includes("claude")
                    ? "Enter instruction for @Claude (or 'exit')..."
                    : session.name?.toLowerCase().includes("agy")
                    ? "Enter task or instruction for @AntiGravity (or 'exit')..."
                    : "Type input and press Enter to send to process (stdin)..."
                  : "type command (e.g. agy, lets build a task manager, crux status, ls)..."
              }
              className="w-full bg-transparent border-none outline-none font-mono text-[12px] text-signal p-0 focus:ring-0 placeholder:text-muted/40 transition-colors"
            />

            {/* SECTION 12.1 MULTIPLAYER PEER CURSORS IN PROMPT */}
            {Object.values(session.peerInputs || {}).map((peer) => (
              <div
                key={peer.userId}
                className="relative flex items-center ml-2"
                title={`${peer.userName} active in terminal`}
              >
                <div
                  style={{ backgroundColor: peer.userColor }}
                  className="w-[2px] h-3.5 animate-pulse"
                />
                <div
                  style={{ color: peer.userColor, borderColor: peer.userColor }}
                  className="absolute -top-5 left-0 px-1 py-0.2 text-[8px] font-mono border bg-void whitespace-nowrap z-20"
                >
                  {peer.userName}
                </div>
              </div>
            ))}
          </div>

          {session.isStreaming ? (
            <span className="w-2 h-3 bg-[#00FF00] animate-pulse" />
          ) : (
            <span className="w-2 h-3 bg-signal animate-pulse" />
          )}
        </form>
      </div>
      )}
    </div>
  );
}
