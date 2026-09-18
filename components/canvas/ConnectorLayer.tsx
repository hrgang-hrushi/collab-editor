"use client";

import React, { useState, useRef, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { FileNode } from "@/lib/types";
import { Trash2 } from "lucide-react";

export default function ConnectorLayer() {
  const files = useWorkspaceStore((state) => state.files);
  const edges = useWorkspaceStore((state) => state.edges);
  const removeEdge = useWorkspaceStore((state) => state.removeEdge);
  const flowSpeedFactor = useWorkspaceStore((state) => state.flowSpeedFactor);
  const isFlowPaused = useWorkspaceStore((state) => state.isFlowPaused);
  const focusedEdgeId = useWorkspaceStore((state) => state.focusedEdgeId);
  const setFocusedEdgeId = useWorkspaceStore((state) => state.setFocusedEdgeId);

  const [hoveredEdgeId, setHoveredEdgeId] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  // SVG SMIL Animation Pause & Resume
  useEffect(() => {
    if (!svgRef.current) return;
    try {
      if (isFlowPaused) {
        svgRef.current.pauseAnimations();
      } else {
        svgRef.current.unpauseAnimations();
      }
    } catch {
      // Fallback for browsers with restricted SMIL DOM
    }
  }, [isFlowPaused]);

  const getWirePathAndMid = (source: FileNode, target: FileNode) => {
    const isTargetBelow = target.y >= source.y + source.height * 0.4;
    const isTargetAbove = source.y >= target.y + target.height * 0.4;
    const horizontalOverlap =
      Math.max(source.x, target.x) <
      Math.min(source.x + source.width, target.x + target.width);

    if (horizontalOverlap && isTargetBelow) {
      const p1 = {
        x: source.x + source.width * 0.5,
        y: source.y + source.height,
      };
      const p2 = {
        x: target.x + target.width * 0.5,
        y: target.y,
      };
      const dy = Math.max(Math.abs(p2.y - p1.y) * 0.4, 30);
      const pathData = `M ${p1.x} ${p1.y} C ${p1.x} ${p1.y + dy}, ${p2.x} ${p2.y - dy}, ${p2.x} ${p2.y}`;
      return { p1, p2, pathData, midX: (p1.x + p2.x) / 2, midY: (p1.y + p2.y) / 2, isVertical: true };
    }

    if (horizontalOverlap && isTargetAbove) {
      const p1 = {
        x: source.x + source.width * 0.5,
        y: source.y,
      };
      const p2 = {
        x: target.x + target.width * 0.5,
        y: target.y + target.height,
      };
      const dy = Math.max(Math.abs(p2.y - p1.y) * 0.4, 30);
      const pathData = `M ${p1.x} ${p1.y} C ${p1.x} ${p1.y - dy}, ${p2.x} ${p2.y + dy}, ${p2.x} ${p2.y}`;
      return { p1, p2, pathData, midX: (p1.x + p2.x) / 2, midY: (p1.y + p2.y) / 2, isVertical: true };
    }

    const isTargetToRight = target.x > source.x + source.width * 0.3;
    const p1 = {
      x: isTargetToRight ? source.x + source.width : source.x,
      y: source.y + Math.min(source.height, 300) * 0.5,
    };
    const p2 = {
      x: isTargetToRight ? target.x : target.x + target.width,
      y: target.y + Math.min(target.height, 300) * 0.5,
    };
    const dx = Math.max(Math.abs(p2.x - p1.x) * 0.5, 60);
    const pathData = `M ${p1.x} ${p1.y} C ${p1.x + dx} ${p1.y}, ${p2.x - dx} ${p2.y}, ${p2.x} ${p2.y}`;
    return { p1, p2, pathData, midX: (p1.x + p2.x) / 2, midY: (p1.y + p2.y) / 2, isVertical: false };
  };

  return (
    <svg
      ref={svgRef}
      className="absolute inset-0 w-[6000px] h-[6000px] pointer-events-none z-0 overflow-visible"
    >
      <defs>
        {edges.map((edge) => {
          const color = edge.color || "#4a7c9d";
          return (
            <marker
              key={`marker-${edge.id}`}
              id={`wire-arrow-${edge.id}`}
              viewBox="0 0 10 10"
              refX="6"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill={color} />
            </marker>
          );
        })}
      </defs>

      {edges.map((edge) => {
        const sourceFile = files.find((f) => f.id === edge.sourceNodeId);
        const targetFile = files.find((f) => f.id === edge.targetNodeId);
        if (!sourceFile || !targetFile) return null;

        const { p1, p2, pathData, midX, midY, isVertical } = getWirePathAndMid(sourceFile, targetFile);
        const color = edge.color || "#4a7c9d";

        // Dynamic Flow Speed Calculation based on speed factor
        const baseSpeed = parseFloat(edge.flowSpeed || "7.2s");
        const speedMultiplier = flowSpeedFactor || 1;
        const effectiveFlowSpeed = (baseSpeed / speedMultiplier).toFixed(1) + "s";
        const halfSpeedNum = (baseSpeed / speedMultiplier / 2).toFixed(1) + "s";

        const isHovered = hoveredEdgeId === edge.id;
        const isFocused = focusedEdgeId === edge.id;
        const hasFocus = focusedEdgeId !== null;

        const wireOpacity = hasFocus
          ? isFocused
            ? 1
            : 0.2
          : isHovered
          ? 1
          : 0.75;
        const wireWidth = isFocused || isHovered ? "2.5" : "1.75";

        const changePayload = edge.changeCode || edge.codeSymbol || "+ code";
        const payloadDisplay = changePayload.startsWith("+ ") ? changePayload.slice(2) : changePayload;
        const badgeWidth = Math.max(payloadDisplay.length * 7 + 40, 140);
        const halfWidth = badgeWidth / 2;

        return (
          <g
            key={edge.id}
            className="pointer-events-auto cursor-pointer transition-opacity duration-200"
            style={{ opacity: wireOpacity }}
            onMouseEnter={() => setHoveredEdgeId(edge.id)}
            onMouseLeave={() => setHoveredEdgeId(null)}
          >
            {/* Wider transparent path for hover detection */}
            <path
              d={pathData}
              fill="none"
              stroke="transparent"
              strokeWidth="28"
            />

            {/* Static Hairline Base Wire */}
            <path
              d={pathData}
              fill="none"
              stroke="rgba(255, 255, 255, 0.1)"
              strokeWidth="1"
            />

            {/* Flowing Dashed Signal Stream */}
            <path
              d={pathData}
              fill="none"
              stroke={color}
              strokeWidth={wireWidth}
              strokeDasharray="4 8"
              markerEnd={`url(#wire-arrow-${edge.id})`}
              className="animate-wire-flow transition-opacity duration-200"
            />

            {/* Source Anchor Pulse Point */}
            <circle
              cx={p1.x}
              cy={p1.y}
              r="3"
              fill="#07080b"
              stroke={color}
              strokeWidth="2"
            />

            {/* Target Anchor Arrival Point */}
            <circle
              cx={p2.x}
              cy={p2.y}
              r="3"
              fill={color}
              stroke="#07080b"
              strokeWidth="1.5"
            />

            {/* TRAVELING CODE CHANGE BADGE & FLOWING PAYLOAD */}
            <g>
              <animateMotion
                key={`motion-${edge.id}-${effectiveFlowSpeed}`}
                path={pathData}
                dur={effectiveFlowSpeed}
                repeatCount="indefinite"
              />
              <animate
                key={`opacity-${edge.id}-${effectiveFlowSpeed}`}
                attributeName="opacity"
                values="0;1;1;1;0"
                keyTimes="0;0.08;0.5;0.92;1"
                dur={effectiveFlowSpeed}
                repeatCount="indefinite"
              />

              {/* Pulse Anchor Circle directly on the wire */}
              <circle cx="0" cy="0" r="4" fill={color} stroke="#07080b" strokeWidth="2" />

              {/* Hairline connector tick linking wire to badge */}
              <line x1="0" y1="0" x2="0" y2="-12" stroke={color} strokeWidth="1" strokeDasharray="1 1" />

              {/* Flowing Code Change Pill - Sharp, Flat Surface */}
              <g transform="translate(0, -24)">
                <rect
                  x={-halfWidth}
                  y="-11"
                  width={badgeWidth}
                  height="22"
                  rx="0"
                  ry="0"
                  fill="#000000"
                  stroke="#222222"
                  strokeWidth="1"
                />
                {/* Contributor color accent stripe on left */}
                <rect
                  x={-halfWidth}
                  y="-11"
                  width="2"
                  height="22"
                  rx="0"
                  ry="0"
                  fill={color}
                />
                {/* Diff '+' indicator */}
                <text
                  x={-halfWidth + 8}
                  y="4"
                  fill="#FFFFFF"
                  fontSize="10"
                  fontFamily="monospace"
                  fontWeight="bold"
                >
                  +
                </text>
                {/* Code snippet text flowing from source to target */}
                <text
                  x={-halfWidth + 18}
                  y="4"
                  fill="#FFFFFF"
                  fontSize="9.5"
                  fontFamily="monospace"
                  fontWeight="500"
                  letterSpacing="-0.2px"
                >
                  {payloadDisplay}
                </text>
              </g>
            </g>

            {/* TRAVELING SIGNAL PARTICLE 2: Staggered pulse following along curve */}
            <circle r="2" fill={color} opacity="0.8">
              <animateMotion
                key={`motion2-${edge.id}-${effectiveFlowSpeed}`}
                path={pathData}
                dur={effectiveFlowSpeed}
                begin={halfSpeedNum}
                repeatCount="indefinite"
              />
              <animate
                key={`opacity2-${edge.id}-${effectiveFlowSpeed}`}
                attributeName="opacity"
                values="0;0.8;0.8;0"
                keyTimes="0;0.1;0.9;1"
                dur={effectiveFlowSpeed}
                begin={halfSpeedNum}
                repeatCount="indefinite"
              />
            </circle>

            {/* CENTRAL STATIC WIRE BADGE & TELEMETRY INSPECTOR */}
            <foreignObject
              x={isVertical ? midX + 16 : midX - 110}
              y={isVertical ? midY - 14 : midY + 14}
              width="220"
              height={isHovered || isFocused ? "135" : "32"}
              className="overflow-visible pointer-events-auto"
            >
              <div className="flex flex-col items-center">
                {/* Main Wire Pill */}
                <div
                  className="flex items-center justify-between gap-2 px-2.5 py-1 rounded-none bg-[#0A0A0A] border border-[#222222] text-[11px] font-mono select-none transition-colors w-full shadow-[4px_4px_0px_#222222] text-[#888888]"
                >
                  <div className="flex items-center gap-1.5 truncate">
                    <span
                      className="w-1.5 h-1.5 rounded-none shrink-0"
                      style={{ backgroundColor: color }}
                    />
                    <span className="font-medium text-white truncate max-w-[125px]">
                      {edge.codeSymbol || edge.label}
                    </span>
                  </div>
                  <span className="text-[#888888] text-[9px] shrink-0 font-medium">
                    ➔ {targetFile.name.replace(".ts", "")}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      removeEdge(edge.id);
                    }}
                    title="Remove connection wire"
                    className="text-[#888888] hover:text-[#FF453A] transition-colors p-0.5 ml-0.5 shrink-0 rounded-none hover:bg-[#222222]"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>

                {/* Expanded Technical Inspector on Hover or Focus */}
                {(isHovered || isFocused) && (
                  <div className="mt-1 p-2.5 rounded-none bg-[#0A0A0A] border border-[#222222] text-[10px] font-mono text-[#888888] w-full space-y-1 shadow-[4px_4px_0px_#222222]">
                    <div className="flex items-center justify-between border-b border-[#222222] pb-1 text-[9px]">
                      <span className="uppercase font-semibold tracking-wider text-white">Live Code Pipeline</span>
                      <span className="text-[#007AFF] font-medium">● 0.08ms · {effectiveFlowSpeed}</span>
                    </div>
                    {edge.originalSnippet && (
                      <div className="text-[#FF453A] bg-[#FF453A]/10 border-l-2 border-[#FF453A] px-2 py-1 rounded-none text-[9px] truncate">
                        {edge.originalSnippet}
                      </div>
                    )}
                    <div className="text-[#00FF00] bg-[#00FF00]/10 border-l-2 border-[#00FF00] px-2 py-1 rounded-none text-[9.5px] leading-tight truncate font-medium">
                      {edge.changeCode || edge.codeSymbol}
                    </div>
                    {edge.payloadDescription && (
                      <div className="text-[9px] text-[#888888] leading-tight line-clamp-2">
                        {edge.payloadDescription}
                      </div>
                    )}
                    <div className="flex items-center justify-between text-[8px] text-[#888888] pt-1 border-t border-[#222222]">
                      <span>{sourceFile.name}:{edge.sourceLine || 1}</span>
                      <span>{targetFile.name}:{edge.targetLine || 1}</span>
                    </div>
                  </div>
                )}
              </div>
            </foreignObject>
          </g>
        );
      })}
    </svg>
  );
}
