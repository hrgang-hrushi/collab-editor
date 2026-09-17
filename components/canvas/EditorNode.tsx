"use client";

import React, { useRef, useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { FileNode } from "@/lib/types";
import {
  FileCode2,
  ArrowRight,
  Minus,
  Maximize2,
  ExternalLink,
  Database,
  ShieldCheck,
  Code2,
  Edit3,
} from "lucide-react";

interface EditorNodeProps {
  file: FileNode;
  onOpenInIde?: (fileId: string) => void;
}

// Ultra-fast, zero-overhead syntax tokenizer for crisp spatial canvas rendering
function highlightSyntax(line: string) {
  if (!line) return "\u00A0";
  const trimmed = line.trim();
  if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
    return <span className="text-[#62666d] italic">{line}</span>;
  }

  const tokenRegex = /(\b(?:import|export|from|function|const|let|var|return|async|await|class|interface|type|extends|implements|new|if|else|switch|case|default|true|false|null|undefined|private|public|protected|readonly|throw)\b|"[^"]*"|'[^']*'|`[^`]*`|\/\/.*)/g;
  const parts = line.split(tokenRegex);

  return parts.map((part, idx) => {
    if (!part) return null;
    if (part.startsWith("//")) {
      return <span key={idx} className="text-[#62666d] italic">{part}</span>;
    }
    if (
      (part.startsWith('"') && part.endsWith('"')) ||
      (part.startsWith("'") && part.endsWith("'")) ||
      (part.startsWith("`") && part.endsWith("`"))
    ) {
      return <span key={idx} className="text-[#27a644]">{part}</span>;
    }
    if (
      /^(import|export|from|function|const|let|var|return|async|await|class|interface|type|extends|implements|new|if|else|switch|case|default|true|false|null|undefined|private|public|protected|readonly|throw)$/.test(
        part
      )
    ) {
      return <span key={idx} className="text-[#5e6ad2] font-semibold">{part}</span>;
    }
    if (/^[A-Z][a-zA-Z0-9]*$/.test(part)) {
      return <span key={idx} className="text-[#f7f8f8] font-medium">{part}</span>;
    }
    return <span key={idx} className="text-[#d0d6e0]">{part}</span>;
  });
}

export default function EditorNode({ file, onOpenInIde }: EditorNodeProps) {
  const updateFilePosition = useWorkspaceStore((state) => state.updateFilePosition);
  const bringToFront = useWorkspaceStore((state) => state.bringToFront);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const startConnection = useWorkspaceStore((state) => state.startConnection);
  const completeConnection = useWorkspaceStore((state) => state.completeConnection);
  const isConnecting = useWorkspaceStore((state) => state.isConnectingNodes);
  const connectionSourceId = useWorkspaceStore((state) => state.connectionSourceId);
  const zoom = useWorkspaceStore((state) => state.canvasTransform.zoom);
  const activeUsers = useWorkspaceStore((state) => state.activeUsers);
  const edges = useWorkspaceStore((state) => state.edges);
  const focusedEdgeId = useWorkspaceStore((state) => state.focusedEdgeId);
  const updateFileContent = useWorkspaceStore((state) => state.updateFileContent);

  const [isMinimized, setIsMinimized] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  const [isInlineEditing, setIsInlineEditing] = useState(false);
  const dragStartRef = useRef<{ mouseX: number; mouseY: number; fileX: number; fileY: number } | null>(null);

  const isActive = activeFileId === file.id;
  const isConnectionTarget = isConnecting && connectionSourceId !== file.id;

  const isConnectedToFocusedEdge = focusedEdgeId
    ? edges.some(
        (e) =>
          e.id === focusedEdgeId &&
          (e.sourceNodeId === file.id || e.targetNodeId === file.id)
      )
    : false;
  const isDimmedByOtherFocus = focusedEdgeId !== null && !isConnectedToFocusedEdge;

  const peerInFile = file.activePeerIds?.map((pid) =>
    activeUsers.find((u) => u.id === pid)
  ).filter(Boolean);

  const outgoingEdges = edges.filter((e) => e.sourceNodeId === file.id);
  const incomingEdges = edges.filter((e) => e.targetNodeId === file.id);

  const handleHeaderMouseDown = (e: React.MouseEvent) => {
    e.stopPropagation();
    bringToFront(file.id);
    setActiveFile(file.id);
    setIsDragging(true);
    dragStartRef.current = {
      mouseX: e.clientX,
      mouseY: e.clientY,
      fileX: file.x,
      fileY: file.y,
    };

    const handleMouseMove = (moveEvent: MouseEvent) => {
      if (!dragStartRef.current) return;
      const dx = (moveEvent.clientX - dragStartRef.current.mouseX) / zoom;
      const dy = (moveEvent.clientY - dragStartRef.current.mouseY) / zoom;
      updateFilePosition(
        file.id,
        Math.round(dragStartRef.current.fileX + dx),
        Math.round(dragStartRef.current.fileY + dy)
      );
    };

    const handleMouseUp = () => {
      setIsDragging(false);
      dragStartRef.current = null;
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
  };

  const handleNodeClick = () => {
    bringToFront(file.id);
    setActiveFile(file.id);
    if (isConnectionTarget) {
      completeConnection(file.id);
    }
  };

  const handleDoubleClick = () => {
    if (onOpenInIde) {
      onOpenInIde(file.id);
    }
  };

  const getFileIcon = (name: string) => {
    if (name.includes("db") || name.includes("database") || name.includes("prisma")) {
      return <Database className="w-3.5 h-3.5 text-emerald-400 shrink-0" />;
    }
    if (name.includes("auth") || name.includes("session") || name.includes("token")) {
      return <ShieldCheck className="w-3.5 h-3.5 text-indigo-400 shrink-0" />;
    }
    if (name.endsWith(".rs")) {
      return <Code2 className="w-3.5 h-3.5 text-amber-400 shrink-0" />;
    }
    if (name.endsWith(".json")) {
      return <FileCode2 className="w-3.5 h-3.5 text-yellow-400 shrink-0" />;
    }
    if (name.endsWith(".css")) {
      return <FileCode2 className="w-3.5 h-3.5 text-rose-400 shrink-0" />;
    }
    return <FileCode2 className="w-3.5 h-3.5 text-sky-400 shrink-0" />;
  };

  const nodeColor = file.contributorColor || "#5e6ad2";
  const lines = (file.content || "").split("\n");

  return (
    <div
      onClick={handleNodeClick}
      onDoubleClick={handleDoubleClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`absolute flex flex-col transition-all duration-200 ${
        isDragging ? "cursor-grabbing" : ""
      }`}
      style={{
        transform: `translate3d(${file.x}px, ${file.y}px, 0)`,
        width: `${file.width}px`,
        height: isMinimized ? "34px" : `${file.height}px`,
        zIndex: isConnectedToFocusedEdge ? 35 : file.zIndex,
        backgroundColor: "#000000",
        opacity: isDimmedByOtherFocus ? 0.28 : isDragging ? 0.95 : 1,
        border: isConnectionTarget
          ? `2px solid ${nodeColor}`
          : isConnectedToFocusedEdge || isActive || isHovered
          ? `2px solid ${nodeColor}`
          : `1.5px solid ${nodeColor}`,
        outline: isConnectionTarget
          ? `2px solid ${nodeColor}`
          : isConnectedToFocusedEdge || isActive || isHovered
          ? `2px solid ${nodeColor}`
          : `1.5px solid ${nodeColor}90`,
        outlineOffset: "3px",
        boxShadow: isConnectionTarget
          ? `0 0 35px 4px ${nodeColor}85, 0 0 14px 2px ${nodeColor}, inset 0 0 20px 2px ${nodeColor}30, inset 0 1px 0 0 ${nodeColor}`
          : isConnectedToFocusedEdge || isActive || isHovered
          ? `0 0 32px 3px ${nodeColor}75, 0 0 12px 1px ${nodeColor}, inset 0 0 16px 1px ${nodeColor}25, inset 0 1px 0 0 ${nodeColor}`
          : `0 0 24px 3px ${nodeColor}50, 0 0 8px 1px ${nodeColor}80, inset 0 0 12px 1px ${nodeColor}15, inset 0 1px 0 0 ${nodeColor}60`,
      }}
    >
      {/* Precision CAD Corner Ticks matching contributor and path */}
      <div
        className="absolute -top-[5px] -left-[5px] w-2 h-2 border-t-2 border-l-2 pointer-events-none"
        style={{
          borderColor: nodeColor,
          filter: `drop-shadow(0 0 4px ${nodeColor})`,
        }}
      />
      <div
        className="absolute -top-[5px] -right-[5px] w-2 h-2 border-t-2 border-r-2 pointer-events-none"
        style={{
          borderColor: nodeColor,
          filter: `drop-shadow(0 0 4px ${nodeColor})`,
        }}
      />
      <div
        className="absolute -bottom-[5px] -left-[5px] w-2 h-2 border-b-2 border-l-2 pointer-events-none"
        style={{
          borderColor: nodeColor,
          filter: `drop-shadow(0 0 4px ${nodeColor})`,
        }}
      />
      <div
        className="absolute -bottom-[5px] -right-[5px] w-2 h-2 border-b-2 border-r-2 pointer-events-none"
        style={{
          borderColor: nodeColor,
          filter: `drop-shadow(0 0 4px ${nodeColor})`,
        }}
      />

      {/* Contributor Top Accent Hairline with Edge Glow */}
      <div
        className="h-[2.5px] w-full shrink-0"
        style={{
          backgroundColor: nodeColor,
          boxShadow: `0 0 12px 2px ${nodeColor}`,
        }}
      />

      {/* Draggable Node Window Header */}
      <div
        onMouseDown={handleHeaderMouseDown}
        className="h-8 px-2.5 flex items-center justify-between border-b border-[#222222] select-none cursor-grab active:cursor-grabbing bg-[#0A0A0A]"
      >
        <div className="flex items-center gap-2 overflow-hidden">
          <div className="flex items-center gap-1 mr-1 shrink-0">
            <div className="w-2 h-2 rounded-none bg-[#222222] border border-[#333333]" />
            <div className="w-2 h-2 rounded-none bg-[#222222] border border-[#333333]" />
            <div className="w-2 h-2 rounded-none bg-[#222222] border border-[#333333]" />
          </div>

          {getFileIcon(file.name)}
          <span className="font-mono text-xs font-semibold text-[#f7f8f8] tracking-tight truncate">
            {file.name}
          </span>
          <span className="text-[10px] px-1 py-0.2 bg-[#141516] text-[#8a8f98] font-mono border border-[#222222] shrink-0">
            {file.language}
          </span>

          {/* Contributor Tag */}
          {file.contributorName && (
            <div
              className="flex items-center gap-1 px-1.5 py-0.5 text-[9px] font-mono border select-none shrink-0"
              style={{
                borderColor: `${nodeColor}50`,
                color: nodeColor,
                backgroundColor: `${nodeColor}15`,
              }}
              title={`Contributor: ${file.contributorName}`}
            >
              <span className="w-1.5 h-1.5 rounded-none" style={{ backgroundColor: nodeColor }} />
              <span className="truncate max-w-[85px] font-medium">{file.contributorName}</span>
            </div>
          )}

          {/* Peer Presence Chip */}
          {peerInFile && peerInFile.length > 0 && (
            <div className="flex items-center -space-x-1 ml-1 shrink-0">
              {peerInFile.map(
                (p) =>
                  p && (
                    <div
                      key={p.id}
                      className="w-3.5 h-3.5 flex items-center justify-center text-[7px] font-mono font-bold text-white border border-[#222222]"
                      style={{ backgroundColor: p.color }}
                      title={`${p.name} active in this file`}
                    >
                      {p.name[0]}
                    </div>
                  )
              )}
            </div>
          )}
        </div>

        {/* Right Header Actions */}
        <div className="flex items-center gap-1">
          {/* Wire tool button */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              startConnection(file.id);
            }}
            title="Connect architectural wire to another file"
            className="flex items-center gap-1 px-1.5 py-0.5 bg-[#141516] hover:bg-[#191a1b] text-[#8a8f98] hover:text-[#5e6ad2] border border-[#222222] text-[10px] font-mono transition-colors"
          >
            <span>Wire</span>
            <ArrowRight className="w-2.5 h-2.5" />
          </button>

          {/* Inline Edit Toggle */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              setIsInlineEditing(!isInlineEditing);
            }}
            title={isInlineEditing ? "Exit inline edit" : "Edit buffer directly"}
            className={`p-1 border transition-colors ${
              isInlineEditing
                ? "bg-[#5e6ad2] text-white border-[#5e6ad2]"
                : "text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] border-transparent hover:border-[#222222]"
            }`}
          >
            <Edit3 className="w-3 h-3" />
          </button>

          {/* Open in IDE button */}
          {onOpenInIde && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onOpenInIde(file.id);
              }}
              title="Open full editor view in IDE (Zenith)"
              className="p-1 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] border border-transparent hover:border-[#222222] transition-colors"
            >
              <ExternalLink className="w-3 h-3" />
            </button>
          )}

          {/* Minimize toggle */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              setIsMinimized(!isMinimized);
            }}
            className="p-1 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] border border-transparent hover:border-[#222222] transition-colors"
          >
            {isMinimized ? (
              <Maximize2 className="w-3 h-3" />
            ) : (
              <Minus className="w-3 h-3" />
            )}
          </button>
        </div>
      </div>

      {/* Editor Body inside spatial node - Pure black */}
      {!isMinimized && (
        <div className="flex-1 overflow-hidden bg-black flex flex-col min-h-0">
          {/* Synchronous, Instant Syntax-Highlighted Code View or Direct Inline Textarea */}
          {isInlineEditing ? (
            <div className="flex-1 p-2 bg-black overflow-hidden flex flex-col">
              <textarea
                value={file.content}
                onChange={(e) => updateFileContent(file.id, e.target.value)}
                autoFocus
                className="w-full h-full bg-black text-[#f7f8f8] font-mono text-[11.5px] leading-[1.6] resize-none focus:outline-none border border-[#333333] p-2"
                spellCheck={false}
              />
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto overflow-x-auto bg-black p-2 font-mono text-[11.5px] leading-[1.6] select-text">
              {lines.map((line, idx) => {
                const lineNum = idx + 1;
                // Check if peer cursor is on this line
                const isPeerLine =
                  (file.id === "file-auth" && lineNum === 5) ||
                  (file.id === "file-stream-syncer" && lineNum === 8) ||
                  (file.id === "file-database" && lineNum === 6) ||
                  (file.id === "file-spatial" && lineNum === 5);

                return (
                  <div
                    key={idx}
                    className={`flex items-center group py-0.2 px-1 relative ${
                      isPeerLine ? "bg-[#5e6ad2]/10" : "hover:bg-[#141516]/60"
                    }`}
                  >
                    {/* Line number gutter */}
                    <span className="text-[#62666d] select-none w-7 text-right pr-2.5 text-[10.5px] shrink-0 font-mono">
                      {lineNum}
                    </span>

                    {/* Syntax Highlighted Line Tokens */}
                    <div className="flex-1 overflow-hidden whitespace-pre font-mono">
                      {highlightSyntax(line)}
                    </div>

                    {/* Active Peer Cursor Chip inline */}
                    {isPeerLine && file.contributorName && (
                      <span
                        className="ml-2 px-1.5 py-0.2 text-[8px] font-mono border shrink-0 animate-pulse"
                        style={{
                          borderColor: nodeColor,
                          color: nodeColor,
                          backgroundColor: `${nodeColor}20`,
                        }}
                      >
                        ● {file.contributorName}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Node Architectural Code Flow Status Strip */}
          {(outgoingEdges.length > 0 || incomingEdges.length > 0) && (
            <div className="h-6 px-2.5 border-t border-[#222222] bg-[#0A0A0A] flex items-center justify-between text-[9.5px] font-mono select-none shrink-0">
              <div className="flex items-center gap-2 truncate">
                {incomingEdges.length > 0 && (
                  <div className="flex items-center gap-1 text-[#8a8f98] truncate" title={`Consuming code from ${incomingEdges[0].sourceNodeId}`}>
                    <span className="w-1.5 h-1.5 bg-[#27a644]" />
                    <span className="text-[#62666d]">in:</span>
                    <span className="text-[#f7f8f8] font-medium truncate max-w-[130px]">
                      {incomingEdges[0].codeSymbol || incomingEdges[0].label}
                    </span>
                  </div>
                )}
                {incomingEdges.length > 0 && outgoingEdges.length > 0 && (
                  <span className="text-[#333333]">·</span>
                )}
                {outgoingEdges.length > 0 && (
                  <div className="flex items-center gap-1 text-[#8a8f98] truncate" title={`Streaming code to ${outgoingEdges[0].targetNodeId}`}>
                    <span className="w-1.5 h-1.5 animate-pulse" style={{ backgroundColor: nodeColor }} />
                    <span className="text-[#62666d]">out:</span>
                    <span className="font-medium truncate max-w-[130px]" style={{ color: nodeColor }}>
                      {outgoingEdges[0].changeCode || outgoingEdges[0].codeSymbol || outgoingEdges[0].label}
                    </span>
                  </div>
                )}
              </div>
              <div className="flex items-center gap-1.5 text-[9px] text-[#62666d] shrink-0 pl-1">
                <span className="w-1 h-1 rounded-none" style={{ backgroundColor: nodeColor }} />
                <span>0.08ms</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
