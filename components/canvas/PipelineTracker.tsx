"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import {
  Activity,
  Pause,
  Play,
  Crosshair,
  ChevronDown,
  X,
  ArrowRight,
} from "lucide-react";

export default function PipelineTracker() {
  const edges = useWorkspaceStore((state) => state.edges);
  const files = useWorkspaceStore((state) => state.files);
  const flowSpeedFactor = useWorkspaceStore((state) => state.flowSpeedFactor);
  const setFlowSpeedFactor = useWorkspaceStore((state) => state.setFlowSpeedFactor);
  const isFlowPaused = useWorkspaceStore((state) => state.isFlowPaused);
  const toggleFlowPause = useWorkspaceStore((state) => state.toggleFlowPause);
  const focusedEdgeId = useWorkspaceStore((state) => state.focusedEdgeId);
  const setFocusedEdgeId = useWorkspaceStore((state) => state.setFocusedEdgeId);
  const isPipelineTrackerOpen = useWorkspaceStore((state) => state.isPipelineTrackerOpen);
  const togglePipelineTracker = useWorkspaceStore((state) => state.togglePipelineTracker);
  const setCanvasTransform = useWorkspaceStore((state) => state.setCanvasTransform);

  const [filterContributor, setFilterContributor] = useState<string>("all");
  const [inspectedEdgeId, setInspectedEdgeId] = useState<string | null>(null);

  // Focus and center canvas on a specific wire and its nodes
  const handleFocusWire = (edgeId: string) => {
    const edge = edges.find((e) => e.id === edgeId);
    if (!edge) return;

    setFocusedEdgeId(edgeId);

    const sourceFile = files.find((f) => f.id === edge.sourceNodeId);
    const targetFile = files.find((f) => f.id === edge.targetNodeId);
    if (!sourceFile || !targetFile) return;

    const sX = Number.isFinite(sourceFile.x) ? sourceFile.x : 60;
    const sY = Number.isFinite(sourceFile.y) ? sourceFile.y : 60;
    const tX = Number.isFinite(targetFile.x) ? targetFile.x : 600;
    const tY = Number.isFinite(targetFile.y) ? targetFile.y : 60;
    const tW = Number.isFinite(targetFile.width) ? targetFile.width : 500;
    const tH = Number.isFinite(targetFile.height) ? targetFile.height : 400;

    const midX = (sX + tX + tW) / 2;
    const midY = (sY + tY + tH) / 2;

    const viewportWidth = typeof window !== "undefined" ? window.innerWidth : 1440;
    const viewportHeight = typeof window !== "undefined" ? window.innerHeight : 900;
    const targetZoom = 0.62;

    const panX = Math.round(viewportWidth / 2 - midX * targetZoom);
    const panY = Math.round(viewportHeight / 2 - midY * targetZoom);

    setCanvasTransform({
      panX,
      panY,
      zoom: targetZoom,
    });
  };

  const getEdgeContributor = (edge: typeof edges[0]) => {
    if (edge.color === "#38b6ff" || edge.color === "#06b6d4") return { name: "Sarah Lin", color: "#38b6ff" };
    if (edge.color === "#FF453A" || edge.color === "#ff5757" || edge.color === "#8b5cf6") return { name: "CruxAI", color: "#FF453A" };
    if (edge.color === "#ff914d" || edge.color === "#888888" || edge.color === "#f59e0b") return { name: "Marcus Vance", color: "#ff914d" };
    if (edge.color === "#00E5FF" || edge.color === "#00FF00" || edge.color === "#10b981") return { name: "Contracts", color: "#00E5FF" };
    return { name: "Principal", color: "#007AFF" };
  };

  const filteredEdges = edges.filter((edge) => {
    if (filterContributor === "all") return true;
    const author = getEdgeContributor(edge);
    const source = files.find((f) => f.id === edge.sourceNodeId);
    const target = files.find((f) => f.id === edge.targetNodeId);
    return (
      author.name.toLowerCase().includes(filterContributor.toLowerCase()) ||
      source?.name.toLowerCase().includes(filterContributor.toLowerCase()) ||
      target?.name.toLowerCase().includes(filterContributor.toLowerCase()) ||
      edge.label?.toLowerCase().includes(filterContributor.toLowerCase())
    );
  });

  if (!isPipelineTrackerOpen) {
    return (
      <div className="absolute bottom-4 left-4 z-40">
        <button
          onClick={togglePipelineTracker}
          className="flex items-center gap-2 px-3 py-1.5 bg-[#0A0A0A] hover:bg-[#222222] border border-[#222222] rounded-none shadow-[4px_4px_0px_#222222] text-xs font-sans text-[#888888] hover:text-white select-none transition-colors"
          title="Open Code Flow Pipeline Tracker"
        >
          <Activity className="w-3.5 h-3.5 text-[#007AFF]" />
          <span className="font-semibold text-white uppercase text-[10px] tracking-wider">Connections</span>
          <span className="px-1.5 py-0.2 rounded-none bg-black border border-[#222222] text-[10px] font-mono text-white">
            {edges.length} active
          </span>
          <span className="w-1.5 h-1.5 rounded-none bg-[#007AFF]" />
        </button>
      </div>
    );
  }

  return (
    <div className="absolute bottom-4 left-4 z-40 w-[420px] max-w-[calc(100vw-32px)] max-h-[500px] flex flex-col bg-[#0A0A0A] border border-[#222222] rounded-none select-none text-xs font-sans text-[#888888] shadow-[4px_4px_0px_#222222] overflow-hidden">
      {/* Tracker Header */}
      <div className="h-9 px-3 border-b border-[#222222] flex items-center justify-between bg-[#0A0A0A] shrink-0">
        <div className="flex items-center gap-2">
          <Activity className="w-3.5 h-3.5 text-[#007AFF]" />
          <span className="font-semibold text-[10px] uppercase tracking-widest text-white">
            Connections
          </span>
          <span className="text-[#222222]">·</span>
          <div className="flex items-center gap-1 px-1.5 py-0.5 rounded-none bg-black border border-[#222222]">
            <span
              className={`w-1.5 h-1.5 rounded-none ${
                isFlowPaused ? "bg-[#888888]" : "bg-[#007AFF]"
              }`}
            />
            <span className="text-[10px] font-mono text-[#888888]">
              {isFlowPaused ? "PAUSED" : "LIVE"}
            </span>
          </div>
        </div>

        {/* Speed Controls & Minimize */}
        <div className="flex items-center gap-1">
          {/* Pause / Play Toggle */}
          <button
            onClick={toggleFlowPause}
            title={isFlowPaused ? "Resume Flow" : "Pause Flow"}
            className={`flex items-center gap-1 px-2 py-0.5 rounded-none border border-[#222222] text-[10px] transition-colors ${
              isFlowPaused
                ? "bg-[#222222] text-white font-medium"
                : "bg-black text-[#888888] hover:text-white"
            }`}
          >
            {isFlowPaused ? (
              <>
                <Play className="w-2.5 h-2.5 fill-current" />
                <span>Resume</span>
              </>
            ) : (
              <>
                <Pause className="w-2.5 h-2.5" />
                <span>Pause</span>
              </>
            )}
          </button>

          {/* Speed Multiplier Pill */}
          <div className="flex items-center rounded-none border border-[#222222] bg-black p-0.5 text-[10px]">
            <button
              onClick={() => setFlowSpeedFactor(0.5)}
              title="Slow Pace (~15s)"
              className={`px-1.5 py-0.5 rounded transition-colors ${
                flowSpeedFactor === 0.5
                  ? "bg-[#333333] text-white font-medium"
                  : "text-[#858585] hover:text-white"
              }`}
            >
              0.5x
            </button>
            <button
              onClick={() => setFlowSpeedFactor(1)}
              title="Normal Pace (~7.5s)"
              className={`px-1.5 py-0.5 rounded-none transition-colors ${
                flowSpeedFactor === 1
                  ? "bg-[#222222] text-white font-medium"
                  : "text-[#888888] hover:text-white"
              }`}
            >
              1x
            </button>
          </div>

          <button
            onClick={togglePipelineTracker}
            title="Minimize Tracker"
            className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] transition-colors ml-0.5"
          >
            <ChevronDown className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Filter Tabs & Reset Focus */}
      <div className="px-3 py-1.5 border-b border-[#222222] bg-[#0A0A0A] flex items-center justify-between gap-1 overflow-x-auto shrink-0 text-xs">
        <div className="flex items-center gap-1">
          {["all", "Sarah", "CruxAI", "Marcus", "Contracts"].map((tab) => (
            <button
              key={tab}
              onClick={() => setFilterContributor(tab)}
              className={`px-2 py-0.5 rounded-none uppercase text-[10px] tracking-wider transition-colors ${
                filterContributor === tab
                  ? "bg-white text-black font-semibold"
                  : "bg-black text-[#888888] hover:text-white border border-[#222222]"
              }`}
            >
              {tab === "all" ? `All (${edges.length})` : tab}
            </button>
          ))}
        </div>

        {focusedEdgeId && (
          <button
            onClick={() => setFocusedEdgeId(null)}
            className="flex items-center gap-1 text-[10px] text-[#888888] hover:text-white px-1.5 py-0.5 rounded-none border border-[#222222] bg-black transition-colors shrink-0"
          >
            <X className="w-3 h-3" />
            <span>Reset</span>
          </button>
        )}
      </div>

      {/* Active Code Flows Scrollable List */}
      <div className="flex-1 overflow-y-auto p-2 space-y-1.5 max-h-[360px] bg-[#0A0A0A]">
        {filteredEdges.map((edge) => {
          const source = files.find((f) => f.id === edge.sourceNodeId);
          const target = files.find((f) => f.id === edge.targetNodeId);
          const isFocused = focusedEdgeId === edge.id;
          const isInspected = inspectedEdgeId === edge.id;
          const edgeColor = edge.color || "#007AFF";

          return (
            <div
              key={edge.id}
              onMouseEnter={() => setFocusedEdgeId(edge.id)}
              onMouseLeave={() => {
                if (!isInspected) setFocusedEdgeId(null);
              }}
              className={`p-2.5 rounded-none bg-black border transition-colors ${
                isFocused
                  ? "border-[#007AFF]"
                  : "border-[#222222] hover:border-[#333333]"
              }`}
              style={{
                borderLeftWidth: "2px",
                borderLeftColor: edgeColor,
              }}
            >
              {/* Card Header: Source -> Target & Contributor Tag */}
              <div className="flex items-center justify-between text-xs mb-1">
                <div className="flex items-center gap-1.5 font-medium">
                  <span className="text-white font-mono">{source?.name || edge.sourceNodeId}</span>
                  <ArrowRight className="w-3 h-3 text-[#888888]" />
                  <span className="text-white font-mono">{target?.name || edge.targetNodeId}</span>
                </div>

                <div className="flex items-center gap-1.5">
                  <span className="px-1.5 py-0.2 rounded-none text-[9px] bg-[#0A0A0A] border border-[#222222] text-[#888888] font-mono">
                    {getEdgeContributor(edge).name}
                  </span>
                  <button
                    onClick={() => handleFocusWire(edge.id)}
                    title="Pan & Center on this wire on canvas"
                    className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] transition-colors"
                  >
                    <Crosshair className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {/* Code Change Snippet */}
              <div className="flex items-center justify-between gap-2 p-1.5 rounded-none bg-[#0A0A0A] border border-[#222222] my-1">
                <div className="flex items-center gap-1.5 truncate">
                  <span className="text-white font-bold text-xs leading-none">+</span>
                  <code
                    className="text-xs font-mono truncate"
                    style={{ color: edgeColor }}
                  >
                    {edge.changeCode?.startsWith("+ ") ? edge.changeCode.slice(2) : edge.changeCode || edge.codeSymbol}
                  </code>
                </div>
                <span className="text-[10px] text-[#888888] shrink-0 font-mono flex items-center gap-1">
                  {edge.sourceLine ? `L${edge.sourceLine}` : ""}
                  <ArrowRight className="w-2.5 h-2.5 text-[#666666]" />
                  {edge.targetLine ? `L${edge.targetLine}` : ""}
                </span>
              </div>

              {/* Description */}
              {edge.payloadDescription && (
                <div className="text-[11px] text-[#888888] line-clamp-1 leading-normal mb-1 font-sans">
                  {edge.payloadDescription}
                </div>
              )}

              {/* Expanded Diff Preview when clicked */}
              {isInspected && (
                <div className="mt-1.5 p-2 rounded-none bg-black border border-[#222222] text-[10px] font-mono space-y-1">
                  <div className="text-[#888888] text-[9px] pb-1 border-b border-[#222222] flex justify-between">
                    <span>DIFF</span>
                    <span>{source?.name}:{edge.sourceLine}</span>
                  </div>
                  {edge.originalSnippet && (
                    <div className="text-[#FF453A] bg-[#FF453A]/10 border-l-2 border-[#FF453A] px-1.5 py-0.5 rounded-none truncate">
                      {edge.originalSnippet}
                    </div>
                  )}
                  <div className="text-[#00FF00] bg-[#00FF00]/10 border-l-2 border-[#00FF00] px-1.5 py-0.5 rounded-none truncate">
                    {edge.changeCode || edge.codeSymbol}
                  </div>
                </div>
              )}

              {/* Card Footer */}
              <div className="flex items-center justify-between text-[10px] text-[#888888] pt-1 border-t border-[#222222]">
                <div className="flex items-center gap-2">
                  <span className="text-[#007AFF]">● 0.08ms</span>
                  <span>{edge.flowSpeed || "7.2s"} pace</span>
                </div>

                <div className="flex items-center gap-2 font-mono">
                  <button
                    onClick={() =>
                      setInspectedEdgeId(isInspected ? null : edge.id)
                    }
                    className="hover:text-white transition-colors"
                  >
                    {isInspected ? "Hide Diff" : "Inspect Diff"}
                  </button>
                  <span>·</span>
                  <button
                    onClick={() => handleFocusWire(edge.id)}
                    className="text-[#007AFF] hover:underline"
                  >
                    Track Wire
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Tracker Footer Status Bar */}
      <div className="h-7 px-3 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[10px] text-[#888888] shrink-0 font-mono">
        <span>Click &apos;Track Wire&apos; to center wire on canvas</span>
        <kbd className="text-[9px] bg-black text-[#888888] px-1 py-0.5 rounded-none border border-[#222222]">Space + Drag</kbd>
      </div>
    </div>
  );
}
