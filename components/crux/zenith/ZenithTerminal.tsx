"use client";

import React, { useState, useRef, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import {
  Terminal,
  Activity,
  ChevronDown,
  ChevronUp,
  Bot,
  Trash2,
  Play,
  Pause,
  CornerDownLeft,
  Code2,
  Check,
  RotateCcw,
  Plus,
  Volume2,
  VolumeX,
} from "lucide-react";
import { triggerHaptic, toggleHaptics, isHapticsEnabled } from "@/lib/haptics";

interface CommandHistory {
  cmd: string;
  output?: string[];
  type?: "info" | "ok" | "err" | "warn";
  exitCode?: number;
}

export interface TerminalSession {
  id: string;
  name: string;
  cwd: string;
  history: CommandHistory[];
}

export default function ZenithTerminal() {
  const isCollapsed = !useWorkspaceStore((state) => state.isTerminalOpen);
  const toggleCollapse = useWorkspaceStore((state) => state.toggleTerminal);
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const projectName = useWorkspaceStore((state) => state.projectName);
  const activeTerminalTab = useWorkspaceStore((state) => state.activeTerminalTab);
  const setActiveTerminalTab = useWorkspaceStore((state) => state.setActiveTerminalTab);
  const runActiveFile = useWorkspaceStore((state) => state.runActiveFile);
  const runFileById = useWorkspaceStore((state) => state.runFileById);
  const lastExecutionResult = useWorkspaceStore((state) => state.lastExecutionResult);
  const createFileInPath = useWorkspaceStore((state) => state.createFileInPath);
  const deletePath = useWorkspaceStore((state) => state.deletePath);
  const terminalCwd = useWorkspaceStore((state) => state.terminalCwd);
  const setTerminalCwd = useWorkspaceStore((state) => state.setTerminalCwd);
  const gitCommits = useWorkspaceStore((state) => state.gitCommits);
  const addGitCommit = useWorkspaceStore((state) => state.addGitCommit);
  const updateFileContent = useWorkspaceStore((state) => state.updateFileContent);

  const [terminalHeight, setTerminalHeight] = useState(210);
  const [isResizing, setIsResizing] = useState(false);
  const [inputVal, setInputVal] = useState("");
  const [isExecuting, setIsExecuting] = useState(false);
  const [historyIndex, setHistoryIndex] = useState<number | null>(null);

  // Multi-session state
  const [sessions, setSessions] = useState<TerminalSession[]>([
    {
      id: "term-1",
      name: "bash: 1",
      cwd: "",
      history: [
        {
          cmd: "crux status",
          output: [
            "● Crux Daemon: v1.2.0-prod on unix:///var/run/crux.sock (IPC: 0.08ms)",
            "● Hardware: Apple Silicon Metal Compute Engine (128 tok/s)",
            "● Buffer Mesh: Zero-copy shared memory CRDT ring buffer [ACTIVE]",
            "● Connected Peers: Sarah Lin (12.4ms), @CruxAI (0.02ms local), Marcus Vance (18.1ms)",
          ],
          type: "ok",
          exitCode: 0,
        },
      ],
    },
  ]);
  const [activeSessionId, setActiveSessionId] = useState<string>("term-1");

  const currentSession = sessions.find((s) => s.id === activeSessionId) || sessions[0];
  const history = currentSession?.history || [];

  const setHistory = (updater: CommandHistory[] | ((prev: CommandHistory[]) => CommandHistory[])) => {
    setSessions((prevSessions) =>
      prevSessions.map((s) => {
        if (s.id === activeSessionId) {
          const newHist = typeof updater === "function" ? updater(s.history) : updater;
          return { ...s, history: newHist };
        }
        return s;
      })
    );
  };

  const createNewSession = () => {
    triggerHaptic("toggle");
    const newId = `term-${Date.now()}`;
    const newName = `bash: ${sessions.length + 1}`;
    const newSession: TerminalSession = {
      id: newId,
      name: newName,
      cwd: terminalCwd,
      history: [
        {
          cmd: "welcome",
          output: [`Crux Virtual Shell [${newName}] ready. Type 'help' for available commands.`],
          type: "info",
          exitCode: 0,
        },
      ],
    };
    setSessions((prev) => [...prev, newSession]);
    setActiveSessionId(newId);
  };

  const closeSession = (sessionId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    triggerHaptic("tap");
    if (sessions.length <= 1) return;
    const remaining = sessions.filter((s) => s.id !== sessionId);
    setSessions(remaining);
    if (activeSessionId === sessionId) {
      setActiveSessionId(remaining[0].id);
    }
  };

  // REPL state
  const [replInput, setReplInput] = useState("");
  const [replHistory, setReplHistory] = useState<Array<{ expr: string; result?: string; isError?: boolean }>>([
    { expr: "Math.sqrt(144)", result: "12" },
    { expr: `files.map(f => f.name)`, result: `[ ${files.map((f) => `"${f.name}"`).join(", ")} ]` },
  ]);

  // AI chat history
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiHistory, setAiHistory] = useState<
    Array<{ role: "user" | "assistant"; text: string; time: string }>
  >([
    {
      role: "assistant",
      text: "CruxAI Speculative Copilot ready. I can inspect your workspace files, optimize CRDT sync routines, or generate reactive spatial modules.",
      time: "20:25",
    },
  ]);

  // Daemon streaming logs
  const [isDaemonStreaming, setIsDaemonStreaming] = useState(true);
  const [daemonLogs, setDaemonLogs] = useState<
    Array<{ time: string; src: string; msg: string; type: "ok" | "info" | "warn" | "ai" }>
  >([
    { time: "20:24:01.002", src: "daemon:7447", msg: "Zero-copy shared memory ring buffer active", type: "ok" },
    { time: "20:24:01.120", src: "engine:metal", msg: "Speculative KV-cache aligned at 0x7ffee000", type: "info" },
    { time: "20:24:02.450", src: "mesh:webrtc", msg: "Peer authenticated: Sarah Lin (latency 12.4ms)", type: "ok" },
    { time: "20:24:03.880", src: "crdt:syncer", msg: "Inbound remote state vector: stream_syncer.ts", type: "warn" },
    { time: "20:24:04.102", src: "agent:cruxai", msg: "Synthesizing speculative verification branch (128 tok/s)", type: "ai" },
  ]);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const aiEndRef = useRef<HTMLDivElement>(null);
  const replEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Periodic daemon log simulator if streaming
  useEffect(() => {
    if (!isDaemonStreaming) return;
    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = now.toTimeString().split(" ")[0] + "." + String(now.getMilliseconds()).padStart(3, "0");
      const sampleEvents = [
        { src: "mesh:webrtc", msg: "Heartbeat ack received from Sarah Lin (11.8ms)", type: "ok" as const },
        { src: "engine:metal", msg: "Metal kernel dispatch completed in 0.04ms", type: "info" as const },
        { src: "crdt:vector", msg: "Clock synchronized with @CruxAI (lamport: 489)", type: "info" as const },
        { src: "daemon:7447", msg: "Buffer pool utilization 3.2% (12MB/512MB)", type: "ok" as const },
      ];
      const randomEvent = sampleEvents[Math.floor(Math.random() * sampleEvents.length)];
      setDaemonLogs((prev) => [...prev.slice(-40), { time: timeStr, ...randomEvent }]);
    }, 4500);
    return () => clearInterval(interval);
  }, [isDaemonStreaming]);

  // Terminal drag resize handler
  const handleResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
    const startY = e.clientY;
    const startHeight = terminalHeight;

    const onMouseMove = (moveEvent: MouseEvent) => {
      const deltaY = startY - moveEvent.clientY;
      const nextHeight = Math.min(Math.max(startHeight + deltaY, 130), 600);
      setTerminalHeight(nextHeight);
    };

    const onMouseUp = () => {
      setIsResizing(false);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };

    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
  };

  // Auto scroll to bottom
  useEffect(() => {
    if (activeTerminalTab === "terminal") {
      terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
    } else if (activeTerminalTab === "ai") {
      aiEndRef.current?.scrollIntoView({ behavior: "smooth" });
    } else if (activeTerminalTab === "repl") {
      replEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [history, aiHistory, replHistory, activeTerminalTab]);

  // Execute terminal command
  const executeCommand = async (cmdString: string) => {
    const trimmed = cmdString.trim();
    if (!trimmed) return;

    triggerHaptic("run");

    if (trimmed.toLowerCase() === "clear") {
      setHistory([]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    const parts = trimmed.split(" ").filter(Boolean);
    const cmd = parts[0].toLowerCase();
    const arg = parts.slice(1).join(" ");

    // 0. HAPTICS
    if (cmd === "haptics") {
      const sub = arg.trim().toLowerCase();
      let enabled = isHapticsEnabled();
      if (sub === "on") {
        enabled = true;
      } else if (sub === "off") {
        enabled = false;
      } else {
        enabled = !enabled;
      }
      toggleHaptics();
      triggerHaptic("toggle");
      setHistory((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: [`Tactile micro-acoustics & haptics: ${enabled ? "ENABLED [ACTIVE]" : "MUTED"}`],
          type: "ok",
          exitCode: 0,
        },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 0. TEST RUNNER
    if (cmd === "test" || (cmd === "npm" && arg === "test")) {
      const testFiles = files.filter((f) => f.name.includes(".test.") || f.name.includes(".spec."));
      const testNames = testFiles.length > 0 ? testFiles.map((f) => f.name) : ["stream_syncer.test.ts", "auth.test.ts"];
      triggerHaptic("success");
      setHistory((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: [
            `RUN  v1.0.0 Crux Speculative Vitest Runner`,
            ``,
            ...testNames.flatMap((t) => [
              `✓ ${t} > lock coherence under simultaneous mutation (0.04ms)`,
              `✓ ${t} > reject corrupted cryptokeys without poisoning CRDT buffer (0.08ms)`,
              `✓ ${t} > benchmark zero-copy IPC throughput under 1ms threshold (0.02ms)`,
            ]),
            ``,
            `Test Files  ${testNames.length} passed (${testNames.length})`,
            `Tests       ${testNames.length * 3} passed (${testNames.length * 3})`,
            `Duration    14ms (transform 4ms, setup 1ms, collect 3ms, tests 6ms)`,
          ],
          type: "ok",
          exitCode: 0,
        },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 1. HELP
    if (cmd === "help") {
      triggerHaptic("click");
      setHistory((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: [
            "Crux Studio Virtual Shell Commands:",
            "  ls [dir]               List files & folders in directory",
            "  cd <dir>               Change directory (e.g. cd src, cd ..)",
            "  pwd                    Print current working directory",
            "  cat <file>             Print file contents with line formatting",
            "  node <file> / run      Execute JavaScript/TypeScript in sandbox",
            "  test / npm test        Run automated speculative unit test suite",
            "  touch <file>           Create a new file",
            "  mkdir <folder>         Create a new virtual folder",
            "  rm [-r] <path>         Remove file or folder",
            "  echo 'text' > <file>   Write text directly to a file",
            "  grep <query> [file]    Search text in files",
            "  git status             Check working tree and modified files",
            "  git diff               Show diffs of modified buffers",
            "  git commit -m 'msg'    Commit modified files to git history",
            "  git log                View recent commits",
            "  haptics [on|off]       Toggle tactile acoustics & haptic clicks",
            "  crux status            Inspect daemon socket & hardware engine",
            "  clear                  Clear terminal screen",
            "  <any host command>     Run host bash/zsh command via daemon",
          ],
          type: "info",
          exitCode: 0,
        },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 2. PWD
    if (cmd === "pwd") {
      const displayPath = `~/` + (projectName ? `${projectName}` : "workspace") + (terminalCwd ? `/${terminalCwd}` : "");
      setHistory((prev) => [
        ...prev,
        { cmd: trimmed, output: [displayPath], type: "info", exitCode: 0 },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 3. CD
    if (cmd === "cd") {
      const target = arg.trim();
      if (!target || target === "/" || target === "~") {
        setTerminalCwd("");
      } else if (target === "..") {
        const parts = terminalCwd.split("/").filter(Boolean);
        parts.pop();
        setTerminalCwd(parts.join("/"));
      } else {
        const nextCwd = terminalCwd ? `${terminalCwd}/${target}` : target;
        // Check if any file starts with this folder prefix
        const exists = files.some((f) => f.path.startsWith(`${nextCwd}/`) || f.path === nextCwd);
        if (exists) {
          setTerminalCwd(nextCwd);
        } else {
          setHistory((prev) => [
            ...prev,
            { cmd: trimmed, output: [`cd: no such directory: ${target}`], type: "err", exitCode: 1 },
          ]);
          setInputVal("");
          setHistoryIndex(null);
          return;
        }
      }
      setHistory((prev) => [
        ...prev,
        { cmd: trimmed, output: [`Directory: ~/${projectName}${terminalCwd ? `/${terminalCwd}` : ""}`], type: "ok", exitCode: 0 },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 4. LS / DIR
    if (cmd === "ls" || cmd === "dir") {
      const currentPrefix = terminalCwd ? `${terminalCwd}/` : "";
      const folders = new Set<string>();
      const currentFiles: Array<{ name: string; size: number; status?: string }> = [];

      files.forEach((f) => {
        if (currentPrefix && !f.path.startsWith(currentPrefix)) return;
        const relative = currentPrefix ? f.path.slice(currentPrefix.length) : f.path;
        const parts = relative.split("/").filter(Boolean);
        if (parts.length > 1) {
          folders.add(parts[0]);
        } else {
          currentFiles.push({
            name: f.name,
            size: new Blob([f.content]).size,
            status: f.status,
          });
        }
      });

      const outputLines: string[] = [];
      Array.from(folders).sort().forEach((folder) => {
        outputLines.push(`  📁 [DIR]  ${folder}/`);
      });
      currentFiles.sort((a, b) => a.name.localeCompare(b.name)).forEach((f) => {
        const sizeStr = `${f.size} B`.padStart(8);
        const modStr = f.status === "modified" ? " [modified]" : "";
        outputLines.push(`  📄 ${sizeStr}  ${f.name}${modStr}`);
      });

      if (outputLines.length === 0) {
        outputLines.push("  (empty directory)");
      }

      setHistory((prev) => [
        ...prev,
        { cmd: trimmed, output: outputLines, type: "info", exitCode: 0 },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 5. CAT
    if (cmd === "cat") {
      if (!arg) {
        setHistory((prev) => [
          ...prev,
          { cmd: trimmed, output: ["usage: cat <filename>"], type: "err", exitCode: 1 },
        ]);
        setInputVal("");
        setHistoryIndex(null);
        return;
      }
      const targetName = arg.trim();
      const currentPath = terminalCwd ? `${terminalCwd}/${targetName}` : targetName;
      const found = files.find(
        (f) =>
          f.name.toLowerCase() === targetName.toLowerCase() ||
          f.path.toLowerCase() === targetName.toLowerCase() ||
          f.path.toLowerCase() === currentPath.toLowerCase() ||
          f.id === targetName
      );

      if (found) {
        setHistory((prev) => [
          ...prev,
          {
            cmd: trimmed,
            output: found.content.split("\n"),
            type: "ok",
            exitCode: 0,
          },
        ]);
      } else {
        setHistory((prev) => [
          ...prev,
          { cmd: trimmed, output: [`cat: ${targetName}: No such file`], type: "err", exitCode: 1 },
        ]);
      }
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 6. NODE / RUN
    if (cmd === "node" || cmd === "run") {
      setIsExecuting(true);
      let targetFile = files.find((f) => f.id === activeFileId) || files[0];
      if (arg) {
        const match = files.find(
          (f) =>
            f.name.toLowerCase() === arg.trim().toLowerCase() ||
            f.path.toLowerCase() === arg.trim().toLowerCase()
        );
        if (match) targetFile = match;
      }

      if (!targetFile) {
        setHistory((prev) => [
          ...prev,
          { cmd: trimmed, output: ["No file available to execute."], type: "err", exitCode: 1 },
        ]);
        setIsExecuting(false);
        setInputVal("");
        setHistoryIndex(null);
        return;
      }

      const res = await runFileById(targetFile.id);
      const outLines: string[] = [];
      if (res?.stdout) outLines.push(...res.stdout);
      if (res?.stderr) outLines.push(...res.stderr.map((e) => `[Error] ${e}`));
      if (res?.returnValue) outLines.push(`=> ${res.returnValue}`);
      outLines.push(`✓ Execution completed in ${res?.durationMs || 0}ms`);

      setHistory((prev) => [
        ...prev,
        { cmd: trimmed, output: outLines, type: res?.success ? "ok" : "err", exitCode: res?.success ? 0 : 1 },
      ]);
      setIsExecuting(false);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 7. TOUCH
    if (cmd === "touch") {
      if (!arg) {
        setHistory((prev) => [
          ...prev,
          { cmd: trimmed, output: ["usage: touch <filename>"], type: "err", exitCode: 1 },
        ]);
      } else {
        const targetPath = terminalCwd ? `${terminalCwd}/${arg.trim()}` : arg.trim();
        createFileInPath(targetPath);
        setHistory((prev) => [
          ...prev,
          { cmd: trimmed, output: [`Created file: ${targetPath}`], type: "ok", exitCode: 0 },
        ]);
      }
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 8. RM
    if (cmd === "rm") {
      const cleanArg = arg.replace("-r", "").replace("-rf", "").trim();
      if (!cleanArg) {
        setHistory((prev) => [
          ...prev,
          { cmd: trimmed, output: ["usage: rm [-r] <path>"], type: "err", exitCode: 1 },
        ]);
      } else {
        const targetPath = terminalCwd ? `${terminalCwd}/${cleanArg}` : cleanArg;
        deletePath(targetPath);
        setHistory((prev) => [
          ...prev,
          { cmd: trimmed, output: [`Removed: ${targetPath}`], type: "ok", exitCode: 0 },
        ]);
      }
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 9. GIT STATUS / DIFF / COMMIT / LOG
    if (trimmed === "git status") {
      const modifiedFiles = files.filter((f) => f.status === "modified");
      const lines = [
        `On branch main`,
        `Your branch is up to date with 'origin/main'.`,
        ``,
      ];
      if (modifiedFiles.length > 0) {
        lines.push(`Changes not staged for commit:`);
        lines.push(`  (use "git commit -m <msg>" to commit changes)`);
        modifiedFiles.forEach((f) => {
          lines.push(`\tmodified:   ${f.path}`);
        });
      } else {
        lines.push(`nothing to commit, working tree clean`);
      }
      lines.push(``);
      lines.push(`Connected peers: 3 | CRDT clock: in-sync`);

      setHistory((prev) => [
        ...prev,
        { cmd: trimmed, output: lines, type: "ok", exitCode: 0 },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    if (trimmed === "git diff") {
      const modifiedFiles = files.filter((f) => f.status === "modified");
      const lines: string[] = [];
      if (modifiedFiles.length === 0) {
        lines.push("No changes in working tree.");
      } else {
        modifiedFiles.forEach((f) => {
          lines.push(`diff --git a/${f.path} b/${f.path}`);
          lines.push(`--- a/${f.path}`);
          lines.push(`+++ b/${f.path}`);
          lines.push(`@@ -1,5 +1,6 @@`);
          lines.push(`+ // modified buffer content (${f.content.length} bytes)`);
        });
      }
      setHistory((prev) => [
        ...prev,
        { cmd: trimmed, output: lines, type: "info", exitCode: 0 },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    if (trimmed.startsWith("git commit")) {
      const match = trimmed.match(/-m\s+["'](.*?)["']/);
      const msg = match ? match[1] : "chore: commit buffer modifications";
      addGitCommit(msg);
      setHistory((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: [`[main ${Math.random().toString(36).slice(2, 9)}] ${msg}`, `✓ All buffers committed clean.`],
          type: "ok",
          exitCode: 0,
        },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    if (trimmed === "git log") {
      const lines: string[] = [];
      gitCommits.slice(0, 5).forEach((c) => {
        lines.push(`commit ${c.id}`);
        lines.push(`Author: ${c.author}`);
        lines.push(`Date:   ${new Date(c.timestamp).toLocaleString()}`);
        lines.push(`    ${c.message}`);
        lines.push(``);
      });
      setHistory((prev) => [
        ...prev,
        { cmd: trimmed, output: lines, type: "info", exitCode: 0 },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 10. ECHO
    if (cmd === "echo") {
      if (arg.includes(">")) {
        const [textPart, filePart] = arg.split(">");
        const cleanText = textPart.trim().replace(/^["']|["']$/g, "");
        const targetFile = filePart.trim();
        const fullPath = terminalCwd ? `${terminalCwd}/${targetFile}` : targetFile;
        const existing = files.find((f) => f.path === fullPath || f.name === targetFile);
        if (existing) {
          updateFileContent(existing.id, cleanText);
        } else {
          createFileInPath(fullPath, cleanText);
        }
        setHistory((prev) => [
          ...prev,
          { cmd: trimmed, output: [`Wrote to ${fullPath}`], type: "ok", exitCode: 0 },
        ]);
      } else {
        setHistory((prev) => [
          ...prev,
          { cmd: trimmed, output: [arg.replace(/^["']|["']$/g, "")], type: "ok", exitCode: 0 },
        ]);
      }
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // 11. GREP
    if (cmd === "grep") {
      const query = arg.trim().toLowerCase();
      const matches: string[] = [];
      files.forEach((f) => {
        const lines = f.content.split("\n");
        lines.forEach((line, idx) => {
          if (line.toLowerCase().includes(query)) {
            matches.push(`${f.path}:${idx + 1}: ${line.trim()}`);
          }
        });
      });
      setHistory((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: matches.length > 0 ? matches : [`grep: no matches found for "${query}"`],
          type: matches.length > 0 ? "info" : "warn",
          exitCode: 0,
        },
      ]);
      setInputVal("");
      setHistoryIndex(null);
      return;
    }

    // Fallback: Execute via backend API route
    setIsExecuting(true);
    try {
      const res = await fetch("/api/terminal", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: trimmed }),
      });
      const data = await res.json();

      let lines: string[] = [];
      if (data.stdout) lines = lines.concat(data.stdout.trim().split("\n"));
      if (data.stderr) lines = lines.concat(data.stderr.trim().split("\n"));

      setHistory((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: lines.length > 0 ? lines : ["(empty output)"],
          type: data.exitCode === 0 ? "ok" : "err",
          exitCode: data.exitCode,
        },
      ]);
    } catch (err: any) {
      setHistory((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: [`Error executing command: ${err?.message || "Unknown error"}`],
          type: "err",
          exitCode: 1,
        },
      ]);
    } finally {
      setIsExecuting(false);
      setInputVal("");
      setHistoryIndex(null);
    }
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeCommand(inputVal);
  };

  // Keyboard navigation for history (Up/Down) & Tab auto-completion
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (history.length === 0) return;
      const nextIdx = historyIndex === null ? history.length - 1 : Math.max(historyIndex - 1, 0);
      setHistoryIndex(nextIdx);
      setInputVal(history[nextIdx].cmd);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex === null) return;
      const nextIdx = historyIndex + 1;
      if (nextIdx >= history.length) {
        setHistoryIndex(null);
        setInputVal("");
      } else {
        setHistoryIndex(nextIdx);
        setInputVal(history[nextIdx].cmd);
      }
    } else if (e.key === "Tab") {
      e.preventDefault();
      const currentToken = inputVal.trim().split(" ").pop() || "";
      if (!currentToken) return;

      // Match filenames
      const candidateFiles = files
        .map((f) => f.name)
        .filter((n) => n.toLowerCase().startsWith(currentToken.toLowerCase()));
      // Match common commands
      const candidateCommands = ["status", "build", "peers", "clear", "help", "node", "cat", "touch", "grep"]
        .filter((c) => c.startsWith(currentToken.toLowerCase()));

      const match = candidateFiles[0] || candidateCommands[0];
      if (match) {
        const parts = inputVal.split(" ");
        parts[parts.length - 1] = match;
        setInputVal(parts.join(" "));
      }
    }
  };

  // REPL evaluation handler
  const handleReplSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!replInput.trim()) return;
    const expr = replInput.trim();

    try {
      // Evaluate in safe function scope
      const evalFn = new Function("files", "projectName", `return (${expr});`);
      const result = evalFn(files, projectName);
      setReplHistory((prev) => [
        ...prev,
        {
          expr,
          result: typeof result === "object" ? JSON.stringify(result, null, 2) : String(result),
          isError: false,
        },
      ]);
    } catch (err: any) {
      setReplHistory((prev) => [
        ...prev,
        { expr, result: err?.message || String(err), isError: true },
      ]);
    }
    setReplInput("");
  };

  // AI submit handler
  const handleAiSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!aiPrompt.trim()) return;
    const userText = aiPrompt.trim();
    const nowStr = new Date().toTimeString().split(" ")[0].slice(0, 5);

    setAiHistory((prev) => [...prev, { role: "user", text: userText, time: nowStr }]);
    setAiPrompt("");

    setTimeout(() => {
      let reply = "";
      if (userText.toLowerCase().includes("wire") || userText.toLowerCase().includes("flow")) {
        reply = `I analyzed your architecture graph (${files.length} nodes). Flow latency is 0.08ms. Sarah Lin is streaming mutations on 'stream_syncer.ts' with zero unmerged diffs.`;
      } else if (userText.toLowerCase().includes("test") || userText.toLowerCase().includes("build")) {
        reply = `Workspace AST typecheck completed. All contracts match. Click "Run" or type 'node <file>' in terminal to execute code.`;
      } else {
        reply = `Crux Copilot completed AST inference for query: "${userText}". Active context: ${files.map((f) => f.name).join(", ")}.`;
      }
      setAiHistory((prev) => [
        ...prev,
        { role: "assistant", text: reply, time: new Date().toTimeString().split(" ")[0].slice(0, 5) },
      ]);
    }, 600);
  };

  if (isCollapsed) {
    return (
      <div
        onClick={toggleCollapse}
        className="h-7 px-3 flex items-center justify-between border-t border-[#222222] bg-[#0A0A0A] cursor-pointer select-none text-xs text-[#8a8f98] hover:text-[#f7f8f8] transition-colors shrink-0 font-sans"
      >
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-[#5e6ad2]" />
          <span className="font-semibold text-[10px] text-[#f7f8f8] uppercase tracking-wider">
            TERMINAL &amp; DAEMON
          </span>
          <span className="text-[10px] text-[#27a644]">● 0.08ms IPC Online</span>
        </div>
        <div className="flex items-center gap-1 text-[10px] text-[#62666d]">
          <span>Expand (⌘J)</span>
          <ChevronUp className="w-3 h-3" />
        </div>
      </div>
    );
  }

  return (
    <div
      style={{ height: `${terminalHeight}px` }}
      className="w-full flex flex-col border-t border-[#222222] bg-[#0A0A0A] select-none shrink-0 font-sans relative transition-none"
    >
      {/* Draggable Resizer Bar */}
      <div
        onMouseDown={handleResizeStart}
        className={`h-1.5 w-full cursor-ns-resize hover:bg-[#5e6ad2]/50 transition-colors flex items-center justify-center ${
          isResizing ? "bg-[#5e6ad2]" : "bg-transparent"
        }`}
        title="Drag up or down to resize terminal"
      >
        <div className="w-8 h-[1px] bg-[#333333] pointer-events-none" />
      </div>

      {/* Terminal Title Bar / Segmented Tabs */}
      <div className="h-7 px-2 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A] shrink-0">
        <div className="flex items-center gap-0.5 text-xs">
          {/* Terminal / Bash */}
          <button
            onClick={() => setActiveTerminalTab("terminal")}
            className={`flex items-center gap-1.5 px-2.5 h-6 transition-colors text-[11px] ${
              activeTerminalTab === "terminal"
                ? "bg-[#141516] text-[#f7f8f8] border-b-2 border-b-[#5e6ad2]"
                : "text-[#8a8f98] hover:text-[#f7f8f8]"
            }`}
          >
            <Terminal className="w-3 h-3 text-[#5e6ad2]" />
            <span>Terminal</span>
          </button>

          {/* Output Tab */}
          <button
            onClick={() => setActiveTerminalTab("output")}
            className={`flex items-center gap-1.5 px-2.5 h-6 transition-colors text-[11px] ${
              activeTerminalTab === "output"
                ? "bg-[#141516] text-[#f7f8f8] border-b-2 border-b-[#27a644]"
                : "text-[#8a8f98] hover:text-[#f7f8f8]"
            }`}
          >
            <Code2 className="w-3 h-3 text-[#27a644]" />
            <span>Output</span>
            {lastExecutionResult && (
              <span className={`w-1.5 h-1.5 rounded-full ${lastExecutionResult.success ? "bg-[#27a644]" : "bg-[#e5484d]"}`} />
            )}
          </button>

          {/* REPL Tab */}
          <button
            onClick={() => setActiveTerminalTab("repl")}
            className={`flex items-center gap-1.5 px-2.5 h-6 transition-colors text-[11px] ${
              activeTerminalTab === "repl"
                ? "bg-[#141516] text-[#f7f8f8] border-b-2 border-b-[#f59e0b]"
                : "text-[#8a8f98] hover:text-[#f7f8f8]"
            }`}
          >
            <span>Node REPL</span>
          </button>

          {/* Daemon IPC */}
          <button
            onClick={() => setActiveTerminalTab("daemon")}
            className={`flex items-center gap-1.5 px-2.5 h-6 transition-colors text-[11px] ${
              activeTerminalTab === "daemon"
                ? "bg-[#141516] text-[#f7f8f8] border-b-2 border-b-[#5e6ad2]"
                : "text-[#8a8f98] hover:text-[#f7f8f8]"
            }`}
          >
            <Activity className="w-3 h-3 text-[#8a8f98]" />
            <span className="hidden sm:inline">Daemon IPC</span>
            <span className="w-1.5 h-1.5 bg-[#27a644]" />
          </button>

          {/* CruxAI Copilot */}
          <button
            onClick={() => setActiveTerminalTab("ai")}
            className={`flex items-center gap-1.5 px-2.5 h-6 transition-colors text-[11px] ${
              activeTerminalTab === "ai"
                ? "bg-[#141516] text-[#f7f8f8] border-b-2 border-b-[#8b5cf6]"
                : "text-[#8a8f98] hover:text-[#f7f8f8]"
            }`}
          >
            <Bot className="w-3 h-3 text-[#8b5cf6]" />
            <span>@CruxAI</span>
          </button>
        </div>

        {/* Action controls */}
        <div className="flex items-center gap-1 text-[#8a8f98]">
          {activeTerminalTab === "daemon" && (
            <button
              onClick={() => setIsDaemonStreaming(!isDaemonStreaming)}
              title={isDaemonStreaming ? "Pause Stream" : "Resume Stream"}
              className="p-1 hover:text-[#f7f8f8] hover:bg-[#141516] transition-colors"
            >
              {isDaemonStreaming ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
            </button>
          )}

          <button
            onClick={() => {
              if (activeTerminalTab === "terminal") setHistory([]);
              else if (activeTerminalTab === "daemon") setDaemonLogs([]);
              else if (activeTerminalTab === "repl") setReplHistory([]);
              else setAiHistory([]);
            }}
            title="Clear scrollback"
            className="p-1 hover:text-[#f7f8f8] hover:bg-[#141516] transition-colors"
          >
            <Trash2 className="w-3 h-3" />
          </button>

          <button
            onClick={toggleCollapse}
            title="Collapse terminal (⌘J)"
            className="p-1 hover:text-[#f7f8f8] hover:bg-[#141516] transition-colors"
          >
            <ChevronDown className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Terminal Content Stream */}
      <div className="flex-1 p-2.5 text-xs overflow-y-auto space-y-1 select-text bg-black font-mono">
        {/* TAB 1: Real Interactive Terminal */}
        {activeTerminalTab === "terminal" && (
          <div className="space-y-1.5">
            {/* Terminal Sessions & Quick action chips */}
            <div className="flex items-center justify-between pb-1 border-b border-[#1f2022] text-[10px] text-[#62666d] overflow-x-auto gap-2">
              {/* Left: Active Terminal Sessions Tabs */}
              <div className="flex items-center gap-1 shrink-0">
                {sessions.map((sess) => {
                  const isCurrent = sess.id === activeSessionId;
                  return (
                    <div
                      key={sess.id}
                      onClick={() => {
                        triggerHaptic("tap");
                        setActiveSessionId(sess.id);
                      }}
                      className={`group flex items-center gap-1.5 px-2 py-0.5 border cursor-pointer transition-colors ${
                        isCurrent
                          ? "bg-[#141516] text-[#f7f8f8] border-[#5e6ad2]/60 font-medium"
                          : "bg-black text-[#8a8f98] hover:text-white border-[#222222]"
                      }`}
                    >
                      <Terminal className="w-2.5 h-2.5 text-[#5e6ad2]" />
                      <span>{sess.name}</span>
                      {sessions.length > 1 && (
                        <button
                          onClick={(e) => closeSession(sess.id, e)}
                          className="opacity-0 group-hover:opacity-100 hover:text-[#e5484d] text-[#62666d] ml-0.5"
                          title="Close Session"
                        >
                          ×
                        </button>
                      )}
                    </div>
                  );
                })}

                {/* + New Session */}
                <button
                  onClick={createNewSession}
                  title="New Terminal Session"
                  className="px-1.5 py-0.5 bg-[#141516] hover:bg-[#191a1b] text-[#8a8f98] hover:text-[#5e6ad2] border border-[#222222] transition-colors"
                >
                  <Plus className="w-3 h-3" />
                </button>
              </div>

              {/* Right: Quick action chips */}
              <div className="flex items-center gap-1.5 shrink-0">
                <span>Quick:</span>
                <button
                  onClick={() => executeCommand("run")}
                  className="px-1.5 py-0.5 bg-[#27a644]/10 hover:bg-[#27a644]/20 text-[#27a644] border border-[#27a644]/30 transition-colors font-semibold"
                >
                  ▶ run
                </button>
                <button
                  onClick={() => executeCommand("test")}
                  className="px-1.5 py-0.5 bg-[#5e6ad2]/10 hover:bg-[#5e6ad2]/20 text-[#5e6ad2] border border-[#5e6ad2]/30 transition-colors"
                >
                  test
                </button>
                <button
                  onClick={() => executeCommand("ls")}
                  className="px-1.5 py-0.5 bg-[#141516] hover:bg-[#191a1b] text-[#8a8f98] hover:text-[#f7f8f8] border border-[#222222] transition-colors"
                >
                  ls
                </button>
                <button
                  onClick={() => executeCommand("git status")}
                  className="px-1.5 py-0.5 bg-[#141516] hover:bg-[#191a1b] text-[#8a8f98] hover:text-[#f7f8f8] border border-[#222222] transition-colors"
                >
                  git status
                </button>
                <button
                  onClick={() => executeCommand("crux status")}
                  className="px-1.5 py-0.5 bg-[#141516] hover:bg-[#191a1b] text-[#5e6ad2] hover:text-[#8b5cf6] border border-[#222222] transition-colors"
                >
                  crux status
                </button>
                <button
                  onClick={() => executeCommand("clear")}
                  className="px-1.5 py-0.5 bg-[#141516] hover:bg-[#191a1b] text-[#8a8f98] hover:text-[#f7f8f8] border border-[#222222] transition-colors"
                >
                  clear
                </button>
              </div>
            </div>

            {/* Scrollback History */}
            {history.map((h, i) => (
              <div key={i} className="space-y-0.5 text-[11px]">
                <div className="flex items-center gap-1.5 text-[#f7f8f8]">
                  <span className="text-[#5e6ad2]">crux</span>
                  <span className="text-[#62666d]">:</span>
                  <span className="text-[#8a8f98]">
                    ~/{projectName}
                    {terminalCwd ? `/${terminalCwd}` : ""}
                  </span>
                  <span className="text-[#27a644]">$</span>
                  <span className="text-white font-medium">{h.cmd}</span>
                  {h.exitCode !== undefined && h.exitCode !== 0 && (
                    <span className="text-[9px] px-1 bg-[#e5484d]/10 text-[#e5484d] border border-[#e5484d]/30">
                      exit {h.exitCode}
                    </span>
                  )}
                </div>
                {h.output && (
                  <div className="pl-3 space-y-0.5 text-[#8a8f98] whitespace-pre-wrap">
                    {h.output.map((line, li) => (
                      <div
                        key={li}
                        className={
                          h.type === "err"
                            ? "text-[#e5484d]"
                            : h.type === "warn"
                            ? "text-[#d0d6e0]"
                            : h.type === "ok"
                            ? "text-[#27a644]"
                            : "text-[#8a8f98]"
                        }
                      >
                        {line}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}

            {/* Live Command Line */}
            <form onSubmit={handleFormSubmit} className="flex items-center gap-1.5 pt-1 text-[11px]">
              <span className="text-[#5e6ad2]">crux</span>
              <span className="text-[#62666d]">:</span>
              <span className="text-[#8a8f98]">
                ~/{projectName}
                {terminalCwd ? `/${terminalCwd}` : ""}
              </span>
              <span className="text-[#27a644]">$</span>
              <input
                ref={inputRef}
                type="text"
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={isExecuting}
                placeholder={isExecuting ? "Executing command..." : "type command (e.g. ls, node main.ts, git status)..."}
                className="flex-1 bg-transparent text-white focus:outline-none placeholder-[#62666d] font-mono text-[11px]"
              />
              {isExecuting && (
                <span className="text-[10px] text-[#5e6ad2] animate-pulse">
                  ● running
                </span>
              )}
            </form>
            <div ref={terminalEndRef} />
          </div>
        )}

        {/* TAB 2: Output Tab */}
        {activeTerminalTab === "output" && (
          <div className="space-y-2 text-[11px]">
            {lastExecutionResult ? (
              <div className="space-y-2">
                <div className="flex items-center justify-between pb-1.5 border-b border-[#222222] text-[10px]">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-1.5 py-0.2 border text-[9px] font-semibold uppercase ${
                        lastExecutionResult.success
                          ? "bg-[#27a644]/15 text-[#27a644] border-[#27a644]/40"
                          : "bg-[#e5484d]/15 text-[#e5484d] border-[#e5484d]/40"
                      }`}
                    >
                      {lastExecutionResult.success ? "Success" : "Error"}
                    </span>
                    <span className="text-white font-medium">{lastExecutionResult.fileName}</span>
                  </div>
                  <span className="text-[#62666d]">Execution: {lastExecutionResult.durationMs}ms</span>
                </div>

                {lastExecutionResult.stdout.length > 0 && (
                  <div className="space-y-0.5">
                    <div className="text-[10px] uppercase text-[#62666d]">Standard Output:</div>
                    <div className="p-2 bg-[#0A0A0A] border border-[#222222] text-[#f7f8f8] space-y-0.5 whitespace-pre-wrap">
                      {lastExecutionResult.stdout.map((line, idx) => (
                        <div key={idx} className="text-[#f7f8f8]">{line}</div>
                      ))}
                    </div>
                  </div>
                )}

                {lastExecutionResult.stderr.length > 0 && (
                  <div className="space-y-0.5">
                    <div className="text-[10px] uppercase text-[#e5484d]">Standard Error:</div>
                    <div className="p-2 bg-[#0A0A0A] border border-[#e5484d]/30 text-[#e5484d] space-y-0.5 whitespace-pre-wrap">
                      {lastExecutionResult.stderr.map((line, idx) => (
                        <div key={idx}>{line}</div>
                      ))}
                    </div>
                  </div>
                )}

                {lastExecutionResult.returnValue !== undefined && (
                  <div className="text-[11px] text-[#5e6ad2]">
                    <span className="text-[#62666d]">Evaluated Result: </span>
                    <span className="font-semibold text-[#f7f8f8]">{lastExecutionResult.returnValue}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-4 flex flex-col items-center justify-center text-[#62666d] space-y-2">
                <Code2 className="w-6 h-6 text-[#333333]" />
                <span>No execution output yet. Click ▶ Run in the editor header or type &apos;run&apos;.</span>
              </div>
            )}
          </div>
        )}

        {/* TAB 3: Interactive Node REPL */}
        {activeTerminalTab === "repl" && (
          <div className="space-y-1.5 text-[11px]">
            <div className="text-[10px] text-[#62666d] pb-1 border-b border-[#1f2022]">
              Node.js In-Memory REPL. Variables <code>files</code> and <code>projectName</code> are accessible in scope.
            </div>

            {replHistory.map((item, idx) => (
              <div key={idx} className="space-y-0.5">
                <div className="flex items-center gap-1.5 text-[#5e6ad2]">
                  <span>&gt;</span>
                  <span className="text-white">{item.expr}</span>
                </div>
                {item.result && (
                  <div className={`pl-3 ${item.isError ? "text-[#e5484d]" : "text-[#27a644]"}`}>
                    {item.result}
                  </div>
                )}
              </div>
            ))}

            <form onSubmit={handleReplSubmit} className="flex items-center gap-1.5 pt-1">
              <span className="text-[#5e6ad2]">&gt;</span>
              <input
                type="text"
                value={replInput}
                onChange={(e) => setReplInput(e.target.value)}
                placeholder="evaluate JavaScript expression..."
                className="flex-1 bg-transparent text-white focus:outline-none placeholder-[#62666d] font-mono text-[11px]"
              />
            </form>
            <div ref={replEndRef} />
          </div>
        )}

        {/* TAB 4: Daemon IPC Logs */}
        {activeTerminalTab === "daemon" && (
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[10px] text-[#62666d] pb-1 border-b border-[#1f2022]">
              <div className="flex items-center gap-2">
                <span className="text-[#27a644]">● 0.08ms Ring Buffer</span>
                <span>Metal Acceleration (128 tok/s)</span>
              </div>
              <span className="text-[#8a8f98]">{daemonLogs.length} events logged</span>
            </div>

            {daemonLogs.map((log, idx) => (
              <div key={idx} className="flex items-start gap-2 leading-relaxed text-[11px]">
                <span className="text-[#62666d] select-none shrink-0">{log.time}</span>
                <span
                  className={`text-[9px] px-1 py-0.2 font-mono shrink-0 border ${
                    log.type === "ok"
                      ? "bg-[#27a644]/10 text-[#27a644] border-[#27a644]/30"
                      : log.type === "warn"
                      ? "bg-[#d0d6e0]/10 text-[#d0d6e0] border-[#d0d6e0]/30"
                      : log.type === "ai"
                      ? "bg-[#5e6ad2]/10 text-[#5e6ad2] border-[#5e6ad2]/30"
                      : "bg-[#141516] text-[#8a8f98] border-[#222222]"
                  }`}
                >
                  {log.src}
                </span>
                <span className="text-[#d0d6e0]">{log.msg}</span>
              </div>
            ))}
          </div>
        )}

        {/* TAB 5: @CruxAI Copilot */}
        {activeTerminalTab === "ai" && (
          <div className="space-y-2 text-[11px]">
            <div className="p-2 bg-[#0A0A0A] border border-[#222222] flex items-center justify-between text-[10px]">
              <div className="flex items-center gap-1.5 text-[#8b5cf6]">
                <Bot className="w-3.5 h-3.5" />
                <span className="font-semibold">@CruxAI Speculative Agent</span>
              </div>
              <span className="text-[#27a644]">Model: Apple Metal 128 tok/s</span>
            </div>

            {aiHistory.map((item, idx) => (
              <div
                key={idx}
                className={`p-2 border ${
                  item.role === "assistant"
                    ? "bg-[#0A0A0A] border-[#222222] text-[#f7f8f8]"
                    : "bg-[#141516] border-[#5e6ad2]/30 text-[#8a8f98]"
                }`}
              >
                <div className="flex items-center justify-between text-[9px] text-[#62666d] mb-1">
                  <span className={item.role === "assistant" ? "text-[#8b5cf6]" : "text-[#5e6ad2]"}>
                    {item.role === "assistant" ? "@CruxAI" : "You"}
                  </span>
                  <span>{item.time}</span>
                </div>
                <div className="leading-relaxed">{item.text}</div>
              </div>
            ))}

            <form onSubmit={handleAiSubmit} className="flex items-center gap-1.5 pt-1">
              <input
                type="text"
                value={aiPrompt}
                onChange={(e) => setAiPrompt(e.target.value)}
                placeholder="Ask CruxAI about code, refactoring, or CRDT pipeline..."
                className="flex-1 bg-black border border-[#222222] px-2 py-1 text-white focus:outline-none focus:border-[#8b5cf6] font-mono text-[11px]"
              />
              <button
                type="submit"
                disabled={!aiPrompt.trim()}
                className="px-2.5 py-1 bg-[#5e6ad2] hover:bg-[#6c78e6] text-white text-[11px] disabled:opacity-50 transition-colors flex items-center gap-1"
              >
                <CornerDownLeft className="w-3 h-3" />
                <span>Send</span>
              </button>
            </form>
            <div ref={aiEndRef} />
          </div>
        )}
      </div>
    </div>
  );
}
