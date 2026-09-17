"use client";

import React, { useRef, useState, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import EditorNode from "./EditorNode";
import ConnectorLayer from "./ConnectorLayer";
import CursorLayer from "../multiplayer/CursorLayer";
import { Move, Layers, X, Sparkles } from "lucide-react";

export default function InfiniteCanvas() {
  const containerRef = useRef<HTMLDivElement>(null);

  const files = useWorkspaceStore((state) => state.files);
  const canvasTransform = useWorkspaceStore((state) => state.canvasTransform);
  const setCanvasTransform = useWorkspaceStore((state) => state.setCanvasTransform);
  const mode = useWorkspaceStore((state) => state.mode);
  const setMode = useWorkspaceStore((state) => state.setMode);
  const isConnecting = useWorkspaceStore((state) => state.isConnectingNodes);
  const cancelConnection = useWorkspaceStore((state) => state.cancelConnection);

  const [isPanning, setIsPanning] = useState(false);
  const [spacePressed, setSpacePressed] = useState(false);
  const panStartRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null);

  // Track spacebar for pan tool
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.code === "Space" && !spacePressed && (e.target as HTMLElement).tagName !== "INPUT" && (e.target as HTMLElement).tagName !== "TEXTAREA") {
        setSpacePressed(true);
      }
    };
    const handleKeyUp = (e: KeyboardEvent) => {
      if (e.code === "Space") {
        setSpacePressed(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("keyup", handleKeyUp);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("keyup", handleKeyUp);
    };
  }, [spacePressed]);

  // Handle Mouse Wheel Zoom (centered around mouse cursor)
  const handleWheel = (e: React.WheelEvent) => {
    if (e.ctrlKey || e.metaKey || mode === "canvas") {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
      const newZoom = Math.min(Math.max(canvasTransform.zoom * zoomFactor, 0.28), 1.8);

      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return;

      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      // Adjust pan to zoom toward mouse position
      const newPanX = mouseX - (mouseX - canvasTransform.panX) * (newZoom / canvasTransform.zoom);
      const newPanY = mouseY - (mouseY - canvasTransform.panY) * (newZoom / canvasTransform.zoom);

      setCanvasTransform({
        panX: Math.round(newPanX),
        panY: Math.round(newPanY),
        zoom: Number(newZoom.toFixed(2)),
      });
    } else {
      // Normal two-finger trackpad scroll pans canvas
      setCanvasTransform({
        panX: canvasTransform.panX - e.deltaX,
        panY: canvasTransform.panY - e.deltaY,
        zoom: canvasTransform.zoom,
      });
    }
  };

  // Canvas background drag to pan
  const handleMouseDown = (e: React.MouseEvent) => {
    // Only pan if clicking canvas background or spacebar is held or middle click
    if (e.button === 1 || spacePressed || e.target === containerRef.current || (e.target as HTMLElement).id === "canvas-plane") {
      setIsPanning(true);
      panStartRef.current = {
        x: e.clientX,
        y: e.clientY,
        panX: canvasTransform.panX,
        panY: canvasTransform.panY,
      };
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning && panStartRef.current) {
      const dx = e.clientX - panStartRef.current.x;
      const dy = e.clientY - panStartRef.current.y;
      setCanvasTransform({
        panX: Math.round(panStartRef.current.panX + dx),
        panY: Math.round(panStartRef.current.panY + dy),
        zoom: canvasTransform.zoom,
      });
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    panStartRef.current = null;
  };

  return (
    <div
      ref={containerRef}
      onWheel={handleWheel}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      className={`relative w-screen h-screen overflow-hidden bg-void-950 canvas-dot-grid ${
        spacePressed || isPanning ? "cursor-grab active:cursor-grabbing" : "cursor-default"
      }`}
    >
      {/* Transformed Spatial World Plane */}
      <div
        id="canvas-plane"
        className="absolute top-0 left-0 w-full h-full origin-top-left transition-transform duration-75 ease-out"
        style={{
          transform: `translate3d(${canvasTransform.panX}px, ${canvasTransform.panY}px, 0) scale(${canvasTransform.zoom})`,
          willChange: "transform",
        }}
      >
        {/* SVG Cubic Bezier Connector Layer */}
        <ConnectorLayer />

        {/* Floating Spatial Code Cards */}
        {files.map((file) => (
          <EditorNode key={file.id} file={file} />
        ))}

        {/* 120Hz Liquid Spring-interpolated Multiplayer Cursors */}
        <CursorLayer />
      </div>

      {/* Floating Canvas Mode / Connection Helper Banner */}
      {(mode === "canvas" || isConnecting) && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 flex items-center gap-3 px-4 py-2.5 rounded-2xl glass-panel-elevated border border-collab-purple/40 shadow-2xl text-xs text-slate-200 animate-in slide-in-from-bottom-3">
          <div className="flex items-center gap-2">
            <span className="p-1 rounded-lg bg-collab-purple/20 text-collab-purple">
              <Layers className="w-4 h-4" />
            </span>
            <span className="font-semibold text-white font-sans">
              {isConnecting
                ? "Connecting Mode: Click any file node to complete the architectural relationship arrow."
                : "Canvas Mode: Zoom out to see multiple files open spatially. Draw arrows between them to explain architecture."}
            </span>
          </div>

          {isConnecting ? (
            <button
              onClick={cancelConnection}
              className="flex items-center gap-1 px-2 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-slate-300 text-xs transition"
            >
              <X className="w-3.5 h-3.5" />
              <span>Cancel</span>
            </button>
          ) : (
            <button
              onClick={() => setMode("edit")}
              className="px-2.5 py-1 rounded-lg bg-collab-purple hover:bg-purple-500 text-white font-medium text-xs transition shadow-sm"
            >
              Exit Canvas
            </button>
          )}
        </div>
      )}

      {/* Suggesting Mode Active Floating Banner */}
      {mode === "suggest" && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 flex items-center gap-3 px-4 py-2 rounded-2xl glass-panel-elevated border border-emerald-500/40 shadow-2xl text-xs text-slate-200 animate-in slide-in-from-bottom-3">
          <Sparkles className="w-4 h-4 text-emerald-400" />
          <span>
            <strong className="text-emerald-300">Suggesting Mode Active:</strong> Edits appear as inline diffs for the file owner to accept or reject.
          </span>
          <button
            onClick={() => setMode("edit")}
            className="px-2.5 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-slate-300 text-xs transition"
          >
            Switch to Direct Edit
          </button>
        </div>
      )}
    </div>
  );
}
