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

  const [activeTab, setActiveTab] = useState<"terminal" | "ai" | "output">("terminal");
  const [inputVal, setInputVal] = useState("");
  const [commandLogs, setCommandLogs] = useState<Array<{ cmd: string; output?: string[]; error?: boolean }>>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [commandLogs, activeTab]);

  const handleCommandSubmit = (e: React.FormEvent) => {
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
            "  crux status         - Show daemon and peer status",
            "  ls                  - List workspace files",
            "  run                 - Execute active file buffer",
            "  node <file>         - Run file via V8 runtime",
            "  clear               - Clear terminal output",
          ],
        },
      ]);
      return;
    }

    if (trimmed === "ls") {
      setCommandLogs((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: files.map((f) => `  ${f.name}  (${f.path || f.name})`),
        },
      ]);
      return;
    }

    if (trimmed === "crux status") {
      setCommandLogs((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: [
            "● Crux Daemon: v1.2.0-prod on unix:///var/run/crux.sock (IPC: 0.08ms)",
            "● Hardware: Apple Silicon Metal Compute Engine (128 tok/s)",
            "● Buffer Mesh: Zero-copy shared memory CRDT ring buffer [ACTIVE]",
            "● Connected Peers: Sarah Lin (12.4ms), @CruxAI (0.02ms local), Marcus Vance (18.1ms)",
          ],
        },
      ]);
      return;
    }

    if (trimmed === "run" || trimmed.startsWith("node ")) {
      runActiveFile();
      setCommandLogs((prev) => [
        ...prev,
        {
          cmd: trimmed,
          output: [
            `[Process started with PID ${Math.floor(1000 + Math.random() * 9000)}]`,
            `Compiling TypeScript AST with esbuild target ESNext...`,
            `Execution completed in 0.08ms with exit code 0.`,
          ],
        },
      ]);
      return;
    }

    // Default echo
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
          <div className="space-y-1">
            {lastExecutionResult ? (
              <>
                <div className="text-signal font-bold">
                  Execution Output ({lastExecutionResult.durationMs?.toFixed(2)}ms):
                </div>
                {lastExecutionResult.stdout?.map((out, idx) => (
                  <div key={idx} className="text-[#00FF00]">
                    {out}
                  </div>
                ))}
                {lastExecutionResult.stderr?.map((err, idx) => (
                  <div key={idx} className="text-accent2">
                    {err}
                  </div>
                ))}
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
