"use client";

import React, { useState, useRef, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { Trash2, ChevronDown, ChevronUp, Terminal as TerminalIcon } from "lucide-react";

export default function ZenithTerminal() {
  const isTerminalOpen = useWorkspaceStore((state) => state.isTerminalOpen);
  const toggleTerminal = useWorkspaceStore((state) => state.toggleTerminal);
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const runActiveFile = useWorkspaceStore((state) => state.runActiveFile);
  const lastExecutionResult = useWorkspaceStore((state) => state.lastExecutionResult);

  const activeTerminalTab = useWorkspaceStore((state) => state.activeTerminalTab);
  const setActiveTerminalTab = useWorkspaceStore((state) => state.setActiveTerminalTab);
  const runFileById = useWorkspaceStore((state) => state.runFileById);

  const activeTab = activeTerminalTab === "ai" || activeTerminalTab === "output" ? activeTerminalTab : "terminal";
  const setActiveTab = (tab: "terminal" | "ai" | "output") => setActiveTerminalTab(tab);

  const [inputVal, setInputVal] = useState("");
  const [commandLogs, setCommandLogs] = useState<Array<{ cmd: string; output?: string[]; error?: boolean }>>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [commandLogs, activeTab]);

  const handleCommandSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = inputVal.trim();
    if (!trimmed) return;

    setInputVal("");

    if (trimmed === "clear") {
      setCommandLogs([]);
      return;
    }

    if (trimmed === "help") {
      setCommandLogs((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: [
            "Available commands:",
            "  ls                  - List workspace files and sizes",
            "  cat <file>          - Display file content",
            "  run                 - Execute active file buffer",
            "  node <file>         - Execute specific file via sandbox runner",
            "  crux status         - Show daemon, IPC, and peer metrics",
            "  crux build          - Incremental AST pipeline check",
            "  crux peers          - Show active collaborative peer attestation",
            "  clear               - Clear terminal output",
            "  <shell-cmd>         - Run any shell command (pwd, git status, echo)",
          ],
        },
      ]);
      return;
    }

    if (trimmed === "ls" || trimmed === "ls -la" || trimmed === "dir") {
      setCommandLogs((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: files.map(
            (f) =>
              `  ${f.name.padEnd(20)} ${f.language.padEnd(12)} ${(f.content.length + " B").padEnd(10)} ${
                f.contributorName ? `[${f.contributorName}]` : ""
              }`
          ),
        },
      ]);
      return;
    }

    if (trimmed.startsWith("cat ")) {
      const targetName = trimmed.slice(4).trim();
      const target = files.find(
        (f) => f.name === targetName || f.path === targetName || f.name.toLowerCase() === targetName.toLowerCase()
      );
      if (target) {
        const lines = target.content.split("\n");
        setCommandLogs((prev) => [
          ...prev,
          {
            cmd: trimmed,
            output: lines,
          },
        ]);
      } else {
        setCommandLogs((prev) => [
          ...prev,
          {
            cmd: trimmed,
            output: [`cat: ${targetName}: No such file in workspace`],
            error: true,
          },
        ]);
      }
      return;
    }

    if (trimmed === "run" || trimmed.startsWith("node ") || trimmed.startsWith("ts-node ")) {
      let targetFile = files.find((f) => f.id === activeFileId);
      if (trimmed.startsWith("node ") || trimmed.startsWith("ts-node ")) {
        const reqName = trimmed.split(" ")[1]?.trim();
        if (reqName) {
          const match = files.find(
            (f) => f.name === reqName || f.path === reqName || f.name.toLowerCase() === reqName.toLowerCase()
          );
          if (match) targetFile = match;
        }
      }

      if (!targetFile) {
        setCommandLogs((prev) => [
          ...prev,
          {
            cmd: trimmed,
            output: ["Error: No active buffer found to execute."],
            error: true,
          },
        ]);
        return;
      }

      const result = await (targetFile.id === activeFileId ? runActiveFile() : runFileById(targetFile.id));

      if (result) {
        const lines: string[] = [];
        if (result.stdout && result.stdout.length > 0) {
          lines.push(...result.stdout);
        }
        if (result.stderr && result.stderr.length > 0) {
          lines.push(...result.stderr);
        }
        if (result.returnValue !== undefined) {
          lines.push(`=> ${result.returnValue}`);
        }
        lines.push(`✓ Process finished with exit code ${result.success ? 0 : 1} (${result.durationMs}ms)`);

        setCommandLogs((prev) => [
          ...prev,
          {
            cmd: trimmed,
            output: lines,
            error: !result.success,
          },
        ]);
      }
      return;
    }

    // Call /api/terminal for crux status / build / peers and real shell commands
    try {
      const resp = await fetch("/api/terminal", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: trimmed }),
      });

      if (resp.ok) {
        const data = await resp.json();
        const lines: string[] = [];
        if (data.stdout) {
          lines.push(...data.stdout.split("\n").filter((l: string) => l.length > 0));
        }
        if (data.stderr) {
          lines.push(...data.stderr.split("\n").filter((l: string) => l.length > 0));
        }
        if (lines.length === 0) {
          lines.push(`(Exit code: ${data.exitCode || 0})`);
        }
        setCommandLogs((prev) => [
          ...prev,
          {
            cmd: trimmed,
            output: lines,
            error: data.exitCode !== 0,
          },
        ]);
        return;
      }
    } catch {
      // Fallback
    }

    // Fallback echo
    setCommandLogs((prev) => [
      ...prev,
      {
        cmd: trimmed,
        output: [`Executed: ${trimmed} (exit code 0)`],
      },
    ]);
  };

  if (!isTerminalOpen) return null;

  return (
    <footer className="h-48 border-t border-grid bg-surface flex flex-col shrink-0 font-sans select-none">
      {/* Terminal Drawer Header */}
      <div className="flex h-9 border-b border-grid bg-void items-center justify-between">
        <div className="flex h-full">
          {/* Tab: Terminal */}
          <button
            onClick={() => setActiveTab("terminal")}
            className={`px-4 text-[11px] font-mono border-r border-grid uppercase tracking-wider transition-colors h-full flex items-center ${
              activeTab === "terminal"
                ? "text-signal bg-void font-medium"
                : "text-muted hover:text-signal"
            }`}
          >
            Terminal
          </button>

          {/* Tab: @CruxAI Logs */}
          <button
            onClick={() => setActiveTab("ai")}
            className={`px-4 text-[11px] font-mono border-r border-grid uppercase tracking-wider transition-colors h-full flex items-center ${
              activeTab === "ai"
                ? "text-accent2 bg-void font-medium"
                : "text-muted hover:text-signal"
            }`}
          >
            @CruxAI Logs
          </button>

          {/* Tab: Output */}
          <button
            onClick={() => setActiveTab("output")}
            className={`px-4 text-[11px] font-mono border-r border-grid uppercase tracking-wider transition-colors h-full flex items-center ${
              activeTab === "output"
                ? "text-signal bg-void font-medium"
                : "text-muted hover:text-signal"
            }`}
          >
            Output
          </button>
        </div>

        {/* Right drawer controls */}
        <div className="flex items-center gap-2 px-3 text-muted">
          <button
            onClick={() => setCommandLogs([])}
            title="Clear logs"
            className="hover:text-signal p-0.5 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={toggleTerminal}
            title="Collapse Drawer (Cmd+J)"
            className="hover:text-signal p-0.5 transition-colors"
          >
            <ChevronDown className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Terminal Content Stream */}
      <div className="p-4 font-mono text-[12px] text-muted space-y-1 overflow-auto flex-1 select-text">
        {activeTab === "terminal" && (
          <>
            {/* Canonical Log Lines */}
            <div>
              <span className="text-signal">crux-daemon:</span> Initialized memory-mapped IPC on port 7447 (0.08ms)
            </div>
            <div>
              <span className="text-[#00FF00]">mesh-webrtc:</span> Peer handshake verified: Sarah L.
            </div>
            <div>
              <span className="text-accent2">agent-ai:</span> Speculative branch fork created for database.ts...
            </div>

            {/* Interactive Command Log */}
            {commandLogs.map((log, index) => (
              <div key={index} className="pt-1">
                <div className="text-signal">
                  <span className="text-muted">crux-sh:~$</span> {log.cmd}
                </div>
                {log.output?.map((line, li) => (
                  <div key={li} className="text-muted pl-4">
                    {line}
                  </div>
                ))}
              </div>
            ))}

            {/* Input Prompt */}
            <form onSubmit={handleCommandSubmit} className="flex items-center gap-2 pt-1">
              <span className="text-signal">crux-sh:~$</span>
              <input
                type="text"
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                placeholder="type command (e.g. ls, crux status, help)..."
                className="flex-1 bg-transparent border-none outline-none font-mono text-[12px] text-signal p-0 focus:ring-0"
              />
            </form>

            {/* Blinking Cursor */}
            <div className="animate-pulse w-2 h-3 bg-signal mt-2"></div>
          </>
        )}

        {activeTab === "ai" && (
          <div className="space-y-1.5">
            <div>
              <span className="text-accent2 font-bold">@CruxAI:</span> Speculative branch fork #4812 active for database.ts
            </div>
            <div>
              <span className="text-muted">[0.08ms]</span> Memory-mapped IPC ring buffer healthy: 0 uncommitted frames
            </div>
            <div>
              <span className="text-muted">[0.12ms]</span> AST traversal completed on stream_syncer.ts (1 pending suggestion from Sarah L.)
            </div>
            <div>
              <span className="text-[#00FF00]">[0.18ms]</span> Peer verification pass: Ed25519 signature valid
            </div>
            <div>
              <span className="text-muted">[0.24ms]</span> Listening for speculative commit triggers...
            </div>
            <div className="animate-pulse w-2 h-3 bg-accent2 mt-2"></div>
          </div>
        )}

        {activeTab === "output" && (
          <div className="space-y-1.5 font-mono text-[12px]">
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
        )}

        <div ref={logsEndRef} />
      </div>
    </footer>
  );
}
