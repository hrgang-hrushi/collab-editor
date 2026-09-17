"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import {
  Activity,
  Pause,
  Play,
  Crosshair,
  ChevronDown,
  ChevronUp,
  Code2,
  CheckCircle2,
  X,
  Gauge,
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

    // Calculate midpoint between source and target
    const midX = (sourceFile.x + targetFile.x + targetFile.width) / 2;
    const midY = (sourceFile.y + targetFile.y + targetFile.height) / 2;

    // Center in viewport (target zoom 0.65)
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
    if (edge.color === "#06b6d4") return { name: "Sarah Lin", color: "#06b6d4" };
    if (edge.color === "#8b5cf6") return { name: "CruxAI", color: "#8b5cf6" };
    if (edge.color === "#f59e0b") return { name: "Marcus Vance", color: "#f59e0b" };
    if (edge.color === "#10b981") return { name: "Contracts", color: "#10b981" };
    return { name: "Principal", color: "#5e6ad2" };
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
          className="flex items-center gap-2 px-3 py-1.5 bg-[#0A0A0A] hover:bg-[#141516] border border-[#222222] hover:border-[#333333] text-xs font-mono text-[#f7f8f8] select-none transition-colors"
          title="Open Code Flow Pipeline Tracker"
        >
          <Activity className="w-3.5 h-3.5 text-[#5e6ad2]" />
          <span className="font-medium">Live Code Flows</span>
          <span className="px-1.5 py-0.2 bg-[#141516] border border-[#222222] text-[10px] text-[#27a644]">
            {edges.length} active
          </span>
          <span className="w-1.5 h-1.5 rounded-full bg-[#27a644] animate-pulse" />
        </button>
      </div>
    );
  }

  return (
    <div className="absolute bottom-4 left-4 z-40 w-[420px] max-w-[calc(100vw-32px)] max-h-[520px] flex flex-col bg-[#0A0A0A] border border-[#222222] select-none text-xs font-mono text-[#f7f8f8] shadow-none">
      {/* Tracker Header */}
      <div className="h-9 px-3 border-b border-[#222222] flex items-center justify-between bg-[#000000] shrink-0">
        <div className="flex items-center gap-2">
          <Activity className="w-3.5 h-3.5 text-[#5e6ad2]" />
          <span className="font-semibold text-[11px] tracking-wide uppercase text-[#f7f8f8]">
            Code Flow Pipeline
          </span>
          <span className="text-[10px] text-[#62666d]">·</span>
          <div className="flex items-center gap-1.5">
            <span
              className={`w-1.5 h-1.5 ${
                isFlowPaused ? "bg-[#f59e0b]" : "bg-[#27a644] animate-pulse"
              }`}
            />
            <span
              className={`text-[10px] font-medium ${
                isFlowPaused ? "text-[#f59e0b]" : "text-[#27a644]"
              }`}
            >
              {isFlowPaused ? "PAUSED" : "STREAMING"}
            </span>
          </div>
        </div>

        {/* Speed Controls & Minimize */}
        <div className="flex items-center gap-1">
          {/* Pause / Play Toggle */}
          <button
            onClick={toggleFlowPause}
            title={isFlowPaused ? "Resume Flow (Play)" : "Pause Flow to Inspect (Freeze in place)"}
            className={`flex items-center gap-1 px-1.5 py-0.5 border text-[10px] font-mono transition-colors ${
              isFlowPaused
                ? "bg-[#f59e0b]/20 border-[#f59e0b] text-[#f59e0b]"
                : "bg-[#141516] border-[#222222] text-[#8a8f98] hover:text-[#f7f8f8]"
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
          <div className="flex items-center border border-[#222222] bg-[#141516] text-[10px]">
            <button
              onClick={() => setFlowSpeedFactor(0.5)}
              title="Slow Pace (~15s) - Ideal for reviewing"
              className={`px-1.5 py-0.5 transition-colors ${
                flowSpeedFactor === 0.5
                  ? "bg-[#5e6ad2] text-white font-bold"
                  : "text-[#8a8f98] hover:text-[#f7f8f8]"
              }`}
            >
              0.5x
            </button>
            <div className="w-[1px] h-3 bg-[#222222]" />
            <button
              onClick={() => setFlowSpeedFactor(1)}
              title="Normal Pace (~7.5s)"
              className={`px-1.5 py-0.5 transition-colors ${
                flowSpeedFactor === 1
                  ? "bg-[#5e6ad2] text-white font-bold"
                  : "text-[#8a8f98] hover:text-[#f7f8f8]"
              }`}
            >
              1x
            </button>
          </div>

          <button
            onClick={togglePipelineTracker}
            title="Minimize Tracker"
            className="p-1 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] transition-colors ml-1"
          >
            <ChevronDown className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Filter Tabs & Reset Focus */}
      <div className="px-2.5 py-1.5 border-b border-[#222222] bg-[#0A0A0A] flex items-center justify-between gap-1 overflow-x-auto shrink-0 text-[10px]">
        <div className="flex items-center gap-1">
          {["all", "Sarah", "CruxAI", "Marcus", "Contracts"].map((tab) => (
            <button
              key={tab}
              onClick={() => setFilterContributor(tab)}
              className={`px-1.5 py-0.5 border capitalize transition-colors ${
                filterContributor === tab
                  ? "border-[#5e6ad2] bg-[#141516] text-[#f7f8f8]"
                  : "border-transparent text-[#8a8f98] hover:text-[#f7f8f8]"
              }`}
            >
              {tab === "all" ? `All (${edges.length})` : tab}
            </button>
          ))}
        </div>

        {focusedEdgeId && (
          <button
            onClick={() => setFocusedEdgeId(null)}
            className="flex items-center gap-1 text-[9px] text-[#5e6ad2] hover:text-white px-1 py-0.5 border border-[#5e6ad2]/50 hover:bg-[#5e6ad2]/20 transition-colors shrink-0"
          >
            <X className="w-2.5 h-2.5" />
            <span>Reset Focus</span>
          </button>
        )}
      </div>

      {/* Active Code Flows Scrollable List */}
      <div className="flex-1 overflow-y-auto p-2 space-y-1.5 max-h-[360px]">
        {filteredEdges.map((edge) => {
          const source = files.find((f) => f.id === edge.sourceNodeId);
          const target = files.find((f) => f.id === edge.targetNodeId);
          const isFocused = focusedEdgeId === edge.id;
          const isInspected = inspectedEdgeId === edge.id;
          const edgeColor = edge.color || "#5e6ad2";

          return (
            <div
              key={edge.id}
              onMouseEnter={() => setFocusedEdgeId(edge.id)}
              onMouseLeave={() => {
                if (!isInspected) setFocusedEdgeId(null);
              }}
              className={`p-2 bg-[#000000] border transition-colors ${
                isFocused
                  ? "border-[#5e6ad2] bg-[#0A0A0A]"
                  : "border-[#222222] hover:border-[#333333]"
              }`}
              style={{
                borderLeftWidth: "3px",
                borderLeftColor: edgeColor,
              }}
            >
              {/* Card Header: Source ➔ Target & Contributor Tag */}
              <div className="flex items-center justify-between text-[10px] mb-1">
                <div className="flex items-center gap-1.5 font-medium">
                  <span className="text-[#f7f8f8]">{source?.name || edge.sourceNodeId}</span>
                  <ArrowRight className="w-2.5 h-2.5 text-[#62666d]" />
                  <span className="text-[#8a8f98]">{target?.name || edge.targetNodeId}</span>
                </div>

                <div className="flex items-center gap-1.5">
                  <span
                    className="px-1 py-0.2 text-[8.5px] border font-medium"
                    style={{
                      borderColor: `${edgeColor}40`,
                      color: edgeColor,
                      backgroundColor: `${edgeColor}10`,
                    }}
                  >
                    {getEdgeContributor(edge).name}
                  </span>
                  <button
                    onClick={() => handleFocusWire(edge.id)}
                    title="Pan & Center on this wire on canvas"
                    className="p-0.5 text-[#8a8f98] hover:text-[#5e6ad2] hover:bg-[#141516] transition-colors"
                  >
                    <Crosshair className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {/* Code Change Snippet */}
              <div className="flex items-center justify-between gap-2 p-1.5 bg-[#0A0A0A] border border-[#1a1a1a] my-1">
                <div className="flex items-center gap-1.5 truncate">
                  <span className="text-[#27a644] font-bold text-[11px] leading-none">+</span>
                  <code
                    className="text-[10px] font-mono font-medium truncate"
                    style={{ color: edgeColor }}
                  >
                    {edge.changeCode?.startsWith("+ ") ? edge.changeCode.slice(2) : edge.changeCode || edge.codeSymbol}
                  </code>
                </div>
                <span className="text-[9px] text-[#62666d] shrink-0">
                  {edge.sourceLine ? `L${edge.sourceLine}` : ""} ➔ {edge.targetLine ? `L${edge.targetLine}` : ""}
                </span>
              </div>

              {/* Description */}
              {edge.payloadDescription && (
                <div className="text-[9px] text-[#8a8f98] line-clamp-1 leading-relaxed mb-1">
                  {edge.payloadDescription}
                </div>
              )}

              {/* Expanded Diff Preview when clicked */}
              {isInspected && (
                <div className="mt-1.5 p-1.5 bg-[#050505] border border-[#222222] text-[9px] font-mono space-y-0.5">
                  <div className="text-[#62666d] text-[8px] pb-0.5 border-b border-[#1a1a1a] flex justify-between">
                    <span>ARCHITECTURAL DIFF</span>
                    <span>{source?.name}:{edge.sourceLine}</span>
                  </div>
                  {edge.originalSnippet && (
                    <div className="text-[#e5484d] bg-[#e5484d]/10 px-1 py-0.5 truncate">
                      {edge.originalSnippet}
                    </div>
                  )}
                  <div className="text-[#27a644] bg-[#27a644]/10 px-1 py-0.5 truncate">
                    {edge.changeCode || edge.codeSymbol}
                  </div>
                </div>
              )}

              {/* Card Footer: Telemetry & Actions */}
              <div className="flex items-center justify-between text-[8.5px] text-[#62666d] pt-1 border-t border-[#141516]">
                <div className="flex items-center gap-2">
                  <span className="text-[#27a644]">● 0.08ms</span>
                  <span>{edge.flowSpeed || "7.2s"} pace</span>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() =>
                      setInspectedEdgeId(isInspected ? null : edge.id)
                    }
                    className="hover:text-[#f7f8f8] transition-colors"
                  >
                    {isInspected ? "Hide Diff" : "Inspect Diff"}
                  </button>
                  <span>·</span>
                  <button
                    onClick={() => handleFocusWire(edge.id)}
                    className="text-[#5e6ad2] hover:underline"
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
      <div className="h-6 px-3 border-t border-[#222222] bg-[#000000] flex items-center justify-between text-[9px] text-[#62666d] shrink-0">
        <span>Click 'Track Wire' or hover to lock highlight</span>
        <span>Space + Drag to Pan</span>
      </div>
    </div>
  );
}
