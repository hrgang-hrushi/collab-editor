"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import { CrexWebGpuEngine, AstSyncDelta } from "@/lib/webgpu/crexEngineBridge";
import { executeLocalCode, ExecutionResult } from "@/lib/tauri/executor";

interface CrexWebGpuCanvasProps {
  initialCode?: string;
  initialLanguage?: string;
  onCodeChange?: (code: string) => void;
}

const DEFAULT_SNIPPETS: Record<string, string> = {
  rust: `// Crex Bare-Metal Kernel Execution Target (Rust)
fn main() {
    println!("[KERNEL_INIT]: Crex WebGPU pipeline online.");
    let mut accumulator: u64 = 0;
    for i in 0..10_000 {
        accumulator += i;
    }
    println!("[EXECUTION_DONE]: Accumulator checksum: {}", accumulator);
}
`,
  python: `# Crex Native Execution Daemon (Python 3)
import sys
import time

print(f"[DAEMON_RUN]: Python {sys.version.split()[0]} interpreter active.")
start = time.perf_counter()
data = [x ** 2 for x in range(1000)]
elapsed = (time.perf_counter() - start) * 1000
print(f"[METRIC]: Computed {len(data)} elements in {elapsed:.3f}ms")
`,
  c: `// Crex Bare-Metal Execution (GCC/Clang)
#include <stdio.h>

int main() {
    printf("[SYS_CALL]: Bare-metal C execution kernel initialized.\\n");
    printf("[STDOUT]: Pointer alignment verified.\\n");
    return 0;
}
`,
  swift: `// Crex Native Execution (Swiftc)
import Foundation

print("[SWIFT_CORE]: Native Swift runtime dispatched.")
let timestamp = Date().timeIntervalSince1970
print("[TELEMETRY]: Epoch: \\(timestamp)")
`,
  java: `// Crex Native Execution (Javac)
public class Main {
    public static void main(String[] args) {
        System.out.println("[JVM_SUBPROCESS]: Java compiler pipeline active.");
    }
}
`,
  javascript: `// Crex High-Performance Node/Bun Execution
const os = require('os');
console.log(\`[PROCESS]: \${process.title} on \${os.platform()}-\${os.arch()}\`);
console.log(\`[MEMORY]: \${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB heap\`);
`,
};

export const CrexWebGpuCanvas: React.FC<CrexWebGpuCanvasProps> = ({
  initialCode,
  initialLanguage = "rust",
  onCodeChange,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const engineRef = useRef<CrexWebGpuEngine | null>(null);

  const [language, setLanguage] = useState<string>(initialLanguage);
  const [fps, setFps] = useState<number>(120);
  const [cursorPos, setCursorPos] = useState({ line: 1, col: 1 });
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionOutput, setExecutionOutput] = useState<ExecutionResult | null>(null);
  const [lastDelta, setLastDelta] = useState<AstSyncDelta | null>(null);

  // Initialize WebGPU engine on canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const resizeCanvas = () => {
      const parent = canvas.parentElement;
      if (parent) {
        canvas.width = parent.clientWidth;
        canvas.height = parent.clientHeight;
      }
    };

    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    const initial = initialCode || DEFAULT_SNIPPETS[language] || DEFAULT_SNIPPETS.rust;
    const engine = new CrexWebGpuEngine(canvas, (delta) => {
      setLastDelta(delta);
      if (engineRef.current) {
        onCodeChange?.(engineRef.current.getContent());
      }
    });

    engine.init(initial).then(() => {
      engineRef.current = engine;
    });

    // Telemetry ticker (500ms to reduce unneeded state updates)
    const interval = setInterval(() => {
      if (engineRef.current) {
        setFps(engineRef.current.fps);
      }
    }, 500);

    return () => {
      window.removeEventListener("resize", resizeCanvas);
      clearInterval(interval);
      engine.destroy();
    };
  }, [initialCode]);

  // Handle language switch
  const handleLanguageChange = (newLang: string) => {
    setLanguage(newLang);
    if (engineRef.current && DEFAULT_SNIPPETS[newLang]) {
      engineRef.current.setContent(DEFAULT_SNIPPETS[newLang]);
      onCodeChange?.(DEFAULT_SNIPPETS[newLang]);
    }
  };

  // Keyboard navigation & typing on canvas
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (engineRef.current) {
      const handled = engineRef.current.handleKeyDown(e.nativeEvent);
      if (handled) {
        e.preventDefault();
        setCursorPos({
          line: engineRef.current.cursorLine + 1,
          col: engineRef.current.cursorCol + 1,
        });
      }
    }
  }, []);

  // Mouse click cursor position
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas || !engineRef.current) return;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    engineRef.current.handleClick(x, y);
    setCursorPos({
      line: engineRef.current.cursorLine + 1,
      col: engineRef.current.cursorCol + 1,
    });
  };

  // Execute Code via Crux Interactive Hyperterminal
  const handleExecute = async () => {
    if (isExecuting) return;
    setIsExecuting(true);
    const code = engineRef.current ? engineRef.current.getContent() : initialCode;
    try {
      const { useWorkspaceStore } = await import("@/lib/store");
      const state = useWorkspaceStore.getState();
      const activeFile = state.files.find((f) => f.id === state.activeFileId);
      if (activeFile && code) {
        state.updateFileContent(activeFile.id, code);
      }
      await state.runActiveFileInTerminal();
    } catch (err: any) {
      console.error("[Crex] Failed to run code in terminal:", err);
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="flex flex-col h-full w-full bg-[#000000] text-white font-mono select-none overflow-hidden">
      {/* Top Hardware Control Bar */}
      <div className="h-9 border-b border-[#222222] bg-[#0A0A0A] flex items-center justify-between px-3 shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-[#444444] uppercase tracking-wider">[KERNEL_ENGINE]</span>
          <span className="text-[11px] text-white font-bold tracking-tight">WEBGPU_120FPS</span>
          <div className="h-3 w-[1px] bg-[#222222] mx-1" />

          {/* Language Selector */}
          <div className="flex items-center gap-1">
            {["rust", "python", "c", "swift", "java", "javascript"].map((lang) => (
              <button
                key={lang}
                onClick={() => handleLanguageChange(lang)}
                className={`text-[10px] px-2 py-0.5 uppercase border transition-none ${
                  language === lang
                    ? "bg-white text-black border-white font-bold"
                    : "bg-transparent text-[#888888] border-[#222222] hover:bg-white hover:text-black hover:border-white"
                }`}
              >
                {lang}
              </button>
            ))}
          </div>
        </div>

        {/* Execution & Telemetry Controls */}
        <div className="flex items-center gap-3">
          {/* AST-CRDT Status */}
          <div className="flex items-center gap-1 text-[10px] text-[#666666]">
            <span>AST_MUTATION:</span>
            <span className="text-white">
              {lastDelta ? `${lastDelta.mutations[0]?.type || "SYNCED"}` : "IDLE"}
            </span>
          </div>

          <div className="h-3 w-[1px] bg-[#222222]" />

          {/* 120 FPS Monitor */}
          <div className="flex items-center gap-1 text-[10px]">
            <span className="text-[#666666]">REFRESH:</span>
            <span className="text-white font-mono">{fps} FPS</span>
          </div>

          <div className="h-3 w-[1px] bg-[#222222]" />

          {/* Execute Code Button */}
          <button
            onClick={handleExecute}
            disabled={isExecuting}
            className={`h-6 px-3 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-none rounded-none ${
              isExecuting
                ? "bg-white text-black"
                : "bg-white text-black hover:bg-neutral-200"
            }`}
          >
            {isExecuting ? (
              <>
                <span className="w-1.5 h-1.5 rounded-none bg-black animate-ping" />
                <span>[RUNNING...]</span>
              </>
            ) : (
              <span>[RUN CODE ↵]</span>
            )}
          </button>
        </div>
      </div>

      {/* Main Canvas Workspace */}
      <div className="flex-1 relative w-full overflow-hidden focus:outline-none">
        <canvas
          ref={canvasRef}
          tabIndex={0}
          onKeyDown={handleKeyDown}
          onClick={handleCanvasClick}
          className="w-full h-full block focus:outline-none cursor-text"
        />
      </div>

      {/* Hardware Execution Output Terminal (Bottom) */}
      {executionOutput && (
        <div className="h-44 border-t border-[#222222] bg-[#050505] flex flex-col shrink-0">
          <div className="h-7 border-b border-[#222222] px-3 flex items-center justify-between text-[10px] bg-[#0D0D0D]">
            <div className="flex items-center gap-2">
              <span className="text-[#444444] uppercase">[DAEMON_STDOUT]</span>
              <span className="text-white">EXIT_CODE: {executionOutput.exit_code}</span>
            </div>
            <div className="flex items-center gap-3 text-[#666666]">
              <span>LATENCY: {executionOutput.execution_time_ms}ms</span>
              <button
                onClick={() => setExecutionOutput(null)}
                className="text-[#888888] hover:text-white uppercase transition-none"
              >
                [CLOSE]
              </button>
            </div>
          </div>
          <div className="flex-1 p-3 font-mono text-[11px] overflow-y-auto whitespace-pre-wrap leading-relaxed select-text">
            {executionOutput.stdout && (
              <div className="text-[#E0E0E0]">{executionOutput.stdout}</div>
            )}
            {executionOutput.stderr && (
              <div className="text-[#FF4444] mt-1">{executionOutput.stderr}</div>
            )}
          </div>
        </div>
      )}

      {/* Bottom Telemetry Bar */}
      <div className="h-6 border-t border-[#222222] bg-[#000000] px-3 flex items-center justify-between text-[10px] text-[#666666] shrink-0">
        <div className="flex items-center gap-3">
          <span>LN {cursorPos.line}, COL {cursorPos.col}</span>
          <span>UTF-8</span>
          <span>SPACES: 2</span>
        </div>
        <div className="flex items-center gap-3">
          <span>TARGET: HOST_OS</span>
          <span>IPC: TAURI_V2</span>
          <span className="text-white">[LIVE_SYNC]</span>
        </div>
      </div>
    </div>
  );
};
