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
          const color = edge.color || "#5e6ad2";
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
        const color = edge.color || "#5e6ad2";

        // Dynamic Flow Speed Calculation based on speed factor
        const baseSpeed = parseFloat(edge.flowSpeed || "7.2s");
        const speedMultiplier = flowSpeedFactor || 1;
        const effectiveFlowSpeed = (baseSpeed / speedMultiplier).toFixed(1) + "s";
        const halfSpeedNum = (baseSpeed / speedMultiplier / 2).toFixed(1) + "s";

        const isHovered = hoveredEdgeId === edge.id;
        const isFocused = focusedEdgeId === edge.id;
        const hasFocus = focusedEdgeId !== null;

        // Selective dimming: when tracking a specific wire, dim all other wires
        const wireOpacity = hasFocus
          ? isFocused
            ? 1
            : 0.18
          : isHovered
          ? 1
          : 0.65;
        const wireWidth = isFocused || isHovered ? "2.5" : "1.5";

        const changePayload = edge.changeCode || edge.codeSymbol || "+ code";
        const payloadDisplay = changePayload.startsWith("+ ") ? changePayload.slice(2) : changePayload;
        const badgeWidth = Math.max(payloadDisplay.length * 6.8 + 36, 130);
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

            {/* Static Hairline Base Wire - Linear Hairline */}
            <path
              d={pathData}
              fill="none"
              stroke="#222222"
              strokeWidth="1"
            />

            {/* Flowing Dashed Signal Stream - Accent Flowing Forward */}
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
              r="2.5"
              fill="#000000"
              stroke={color}
              strokeWidth="1.5"
            />

            {/* Target Anchor Arrival Point */}
            <circle
              cx={p2.x}
              cy={p2.y}
              r="2.5"
              fill={color}
              stroke="#000000"
              strokeWidth="1"
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
              <circle cx="0" cy="0" r="3.5" fill={color} stroke="#000000" strokeWidth="1.5" />

              {/* Hairline connector tick linking wire to badge */}
              <line x1="0" y1="0" x2="0" y2="-12" stroke={color} strokeWidth="1" strokeDasharray="1 1" />

              {/* Flowing Code Change Pill - Flat Black, 1px Contributor Color Border */}
              <g transform="translate(0, -22)">
                <rect
                  x={-halfWidth}
                  y="-10"
                  width={badgeWidth}
                  height="20"
                  fill="#0A0A0A"
                  stroke={color}
                  strokeWidth="1"
                />
                {/* Contributor color accent stripe on left */}
                <rect
                  x={-halfWidth}
                  y="-10"
                  width="3"
                  height="20"
                  fill={color}
                />
                {/* Diff '+' indicator */}
                <text
                  x={-halfWidth + 9}
                  y="3.5"
                  fill="#27a644"
                  fontSize="10"
                  fontFamily="monospace"
                  fontWeight="bold"
                >
                  +
                </text>
                {/* Code snippet text flowing from source to target */}
                <text
                  x={-halfWidth + 20}
                  y="3.5"
                  fill="#f7f8f8"
                  fontSize="9"
                  fontFamily="monospace"
                  fontWeight="500"
                  letterSpacing="-0.2px"
                >
                  {payloadDisplay}
                </text>
              </g>
            </g>

            {/* TRAVELING SIGNAL PARTICLE 2: Staggered pulse following along curve */}
            <circle r="2.2" fill={color} opacity="0.8">
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
                values="0;0.9;0.9;0"
                keyTimes="0;0.1;0.9;1"
                dur={effectiveFlowSpeed}
                begin={halfSpeedNum}
                repeatCount="indefinite"
              />
            </circle>

            {/* CENTRAL STATIC WIRE BADGE & TELEMETRY INSPECTOR */}
            <foreignObject
              x={isVertical ? midX + 16 : midX - 105}
              y={isVertical ? midY - 13 : midY + 12}
              width="210"
              height={isHovered || isFocused ? "125" : "26"}
              className="overflow-visible pointer-events-auto"
            >
              <div className="flex flex-col items-center">
                {/* Main Wire Pill */}
                <div
                  className={`flex items-center justify-between gap-1.5 px-2.5 py-1 bg-[#0A0A0A] border text-[10px] font-mono select-none transition-colors w-full ${
                    isHovered || isFocused
                      ? "text-[#f7f8f8]"
                      : "text-[#8a8f98]"
                  }`}
                  style={{
                    borderColor: isHovered || isFocused ? color : "#222222",
                  }}
                >
                  <div className="flex items-center gap-1.5 truncate">
                    <span
                      className="w-1.5 h-1.5 rounded-none animate-pulse shrink-0"
                      style={{ backgroundColor: color }}
                    />
                    <span className="font-medium text-[#f7f8f8] truncate max-w-[130px]">
                      {edge.codeSymbol || edge.label}
                    </span>
                  </div>
                  <span className="text-[#62666d] text-[9px] shrink-0">
                    ➔ {targetFile.name.replace(".ts", "")}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      removeEdge(edge.id);
                    }}
                    title="Remove connection wire"
                    className="text-[#62666d] hover:text-[#e5484d] transition-colors p-0.5 ml-0.5 shrink-0"
                  >
                    <Trash2 className="w-2.5 h-2.5" />
                  </button>
                </div>

                {/* Expanded Technical Inspector on Hover or Focus */}
                {(isHovered || isFocused) && (
                  <div className="mt-1 p-2 bg-[#0A0A0A] border text-[9.5px] font-mono text-[#8a8f98] w-full space-y-1 shadow-none" style={{ borderColor: color }}>
                    <div className="flex items-center justify-between border-b border-[#222222] pb-1 text-[8.5px]">
                      <span className="uppercase font-semibold" style={{ color }}>Live Code Pipeline</span>
                      <span className="text-[#27a644]">● 0.08ms · {effectiveFlowSpeed}</span>
                    </div>
                    {edge.originalSnippet && (
                      <div className="text-[#e5484d] bg-[#e5484d]/10 px-1 py-0.5 text-[8.5px] truncate">
                        {edge.originalSnippet}
                      </div>
                    )}
                    <div className="text-[#27a644] bg-[#27a644]/10 px-1 py-0.5 text-[9px] leading-tight truncate">
                      {edge.changeCode || edge.codeSymbol}
                    </div>
                    {edge.payloadDescription && (
                      <div className="text-[8px] text-[#8a8f98] leading-tight line-clamp-2">
                        {edge.payloadDescription}
                      </div>
                    )}
                    <div className="flex items-center justify-between text-[7.5px] text-[#62666d] pt-0.5 border-t border-[#1a1a1a]">
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
