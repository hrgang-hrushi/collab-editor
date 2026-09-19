"use client";

import React, { useEffect, useRef, useState } from "react";
import { WebGPUCanvasEditor } from "@/lib/engine/webgpuCanvas";

interface CrexCanvasEditorProps {
  initialCode?: string;
  language?: string;
  onChange?: (code: string) => void;
  onRun?: () => void;
}

export default function CrexCanvasEditor({
  initialCode = "",
  language = "rust",
  onChange,
  onRun,
}: CrexCanvasEditorProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const editorRef = useRef<WebGPUCanvasEditor | null>(null);

  const [cursorPos, setCursorPos] = useState({ line: 1, col: 1 });
  const [telemetry, setTelemetry] = useState({
    fps: 120,
    nodeCount: 0,
    backend: "Direct Hardware 2D",
  });

  useEffect(() => {
    if (!canvasRef.current) return;

    const editor = new WebGPUCanvasEditor({
      canvas: canvasRef.current,
      initialCode: initialCode,
      language: language,
      onChange: (code) => {
        if (onChange) onChange(code);
      },
      onCursorChange: (line, col) => {
        setCursorPos({ line: line + 1, col: col + 1 });
      },
      onTelemetry: (fps, nodeCount, backend) => {
        setTelemetry({ fps, nodeCount, backend });
      },
    });

    editorRef.current = editor;

    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        if (onRun) onRun();
      }
    };

    window.addEventListener("keydown", handleKeyDown);

    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      editor.destroy();
    };
  }, []);

  // Update editor code when active file changes externally
  useEffect(() => {
    if (editorRef.current && initialCode !== undefined) {
      if (editorRef.current.getCode() !== initialCode) {
        editorRef.current.setCode(initialCode);
      }
    }
  }, [initialCode]);

  useEffect(() => {
    if (editorRef.current) {
      editorRef.current.language = language;
    }
  }, [language]);

  return (
    <div className="flex-1 flex flex-col h-full bg-[#000000] text-white select-none overflow-hidden">
      {/* Editor Surface: Direct WebGPU HTML Canvas */}
      <div className="flex-1 relative w-full h-full overflow-hidden">
        <canvas
          ref={canvasRef}
          id="crex-canvas"
          className="absolute inset-0 w-full h-full block outline-none cursor-text"
        />
      </div>

      {/* Hardware Telemetry Bar */}
      <div className="h-6 bg-[#000000] border-t border-[#222222] px-3 flex items-center justify-between text-[10px] font-mono text-[#444444] z-10">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-1.5">
            <span className="inline-block w-1.5 h-1.5 bg-[#FFFFFF] animate-pulse" />
            <span className="text-[#FFFFFF]">
              [{telemetry.backend.toUpperCase()} // {telemetry.fps} FPS]
            </span>
          </div>
          <span>[AST-CRDT NODES: {telemetry.nodeCount}]</span>
          <span>[PIPELINE: DIRECT-TO-CANVAS // NO-DOM]</span>
        </div>

        <div className="flex items-center space-x-4">
          <span className="text-[#FFFFFF]">
            LN {cursorPos.line}, COL {cursorPos.col}
          </span>
          <span className="uppercase text-[#FFFFFF]">[{language}]</span>
          <span>[UTF-8]</span>
        </div>
      </div>
    </div>
  );
}
