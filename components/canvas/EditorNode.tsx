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
    return <span className="text-[#888888] italic">{line}</span>;
  }

  const tokenRegex = /(\b(?:import|export|from|function|const|let|var|return|async|await|class|interface|type|extends|implements|new|if|else|switch|case|default|true|false|null|undefined|private|public|protected|readonly|throw)\b|"[^"]*"|'[^']*'|`[^`]*`|\/\/.*)/g;
  const parts = line.split(tokenRegex);

  return parts.map((part, idx) => {
    if (!part) return null;
    if (part.startsWith("//")) {
      return <span key={idx} className="text-[#888888] italic">{part}</span>;
    }
    if (
      (part.startsWith('"') && part.endsWith('"')) ||
      (part.startsWith("'") && part.endsWith("'")) ||
      (part.startsWith("`") && part.endsWith("`"))
    ) {
      return <span key={idx} className="text-[#cccccc]">{part}</span>;
    }
    if (
      /^(import|export|from|function|const|let|var|return|async|await|class|interface|type|extends|implements|new|if|else|switch|case|default|true|false|null|undefined|private|public|protected|readonly|throw)$/.test(
        part
      )
    ) {
      return <span key={idx} className="text-[#007AFF] font-medium">{part}</span>;
    }
    if (/^[A-Z][a-zA-Z0-9]*$/.test(part)) {
      return <span key={idx} className="text-white font-medium">{part}</span>;
    }
    return <span key={idx} className="text-[#888888]">{part}</span>;
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

  const fileX = Number.isFinite(file.x) ? file.x : 60;
  const fileY = Number.isFinite(file.y) ? file.y : 60;
  const fileW = Number.isFinite(file.width) && file.width > 0 ? file.width : 520;
  const fileH = Number.isFinite(file.height) && file.height > 0 ? file.height : 440;

  const handleHeaderMouseDown = (e: React.MouseEvent) => {
    e.stopPropagation();
    bringToFront(file.id);
    setActiveFile(file.id);
    setIsDragging(true);
    dragStartRef.current = {
      mouseX: e.clientX,
      mouseY: e.clientY,
      fileX,
      fileY,
    };

    let rafId: number | null = null;
    const handleMouseMove = (moveEvent: MouseEvent) => {
      if (!dragStartRef.current) return;
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(() => {
        if (!dragStartRef.current) return;
        const dx = (moveEvent.clientX - dragStartRef.current.mouseX) / zoom;
        const dy = (moveEvent.clientY - dragStartRef.current.mouseY) / zoom;
        updateFilePosition(
          file.id,
          Math.round(dragStartRef.current.fileX + dx),
          Math.round(dragStartRef.current.fileY + dy)
        );
      });
    };

    const handleMouseUp = () => {
      if (rafId) cancelAnimationFrame(rafId);
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
      return <Database className="w-3.5 h-3.5 text-[#858585] shrink-0" />;
    }
    if (name.includes("auth") || name.includes("session") || name.includes("token")) {
      return <ShieldCheck className="w-3.5 h-3.5 text-[#858585] shrink-0" />;
    }
    if (name.endsWith(".rs")) {
      return <Code2 className="w-3.5 h-3.5 text-[#858585] shrink-0" />;
    }
    if (name.endsWith(".json")) {
      return <FileCode2 className="w-3.5 h-3.5 text-[#858585] shrink-0" />;
    }
    if (name.endsWith(".css")) {
      return <FileCode2 className="w-3.5 h-3.5 text-[#858585] shrink-0" />;
    }
    return <FileCode2 className="w-3.5 h-3.5 text-[#858585] shrink-0" />;
  };

  const nodeColor =
    file.contributorColor ||
    (file.name.includes("db") || file.name.includes("database")
      ? "#FF453A"
      : file.name.includes("auth")
      ? "#38b6ff"
      : file.name.includes("types")
      ? "#00E5FF"
      : file.name.includes("spatial")
      ? "#ff914d"
      : "#007AFF");
  const lines = (file.content || "").split("\n");

  return (
    <div
      onClick={handleNodeClick}
      onDoubleClick={handleDoubleClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`absolute select-none flex flex-col rounded-none overflow-hidden ${
        isDragging ? "cursor-grabbing" : ""
      }`}
      style={{
        transform: `translate3d(${fileX}px, ${fileY}px, 0)`,
        transition: isDragging
          ? "none"
          : "transform 0.28s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.15s ease",
        willChange: "transform",
        width: `${fileW}px`,
        height: `${fileH}px`,
        zIndex: file.zIndex || 1,
        border: isActive
          ? `2px solid ${nodeColor}`
          : isConnectedToFocusedEdge
          ? "2px solid #FFFFFF"
          : isHovered
          ? `1.5px solid ${nodeColor}`
          : `1px solid ${nodeColor}`,
        backgroundColor: "#000000",
        boxShadow: isActive
          ? `0 0 0 1px ${nodeColor}, 4px 4px 0px ${nodeColor}40`
          : isConnectedToFocusedEdge
          ? "0 0 0 1px #FFFFFF, 4px 4px 0px rgba(255,255,255,0.25)"
          : isHovered
          ? `4px 4px 0px ${nodeColor}30`
          : "4px 4px 0px #161616",
        opacity: isDimmedByOtherFocus ? 0.35 : 1,
      }}
    >
      {/* Top Accent Line */}
      <div
        className="h-[2px] w-full shrink-0"
        style={{
          backgroundColor: nodeColor,
          opacity: isActive ? 1 : 0.85,
        }}
      />

      {/* Draggable Window Header */}
      <div
        onMouseDown={handleHeaderMouseDown}
        className="h-8 px-2.5 flex items-center justify-between border-b select-none cursor-grab active:cursor-grabbing bg-[#0A0A0A]"
        style={{
          borderBottomColor: `${nodeColor}40`,
        }}
      >
        <div className="flex items-center gap-2 overflow-hidden">
          {/* Color-coded node indicator dot */}
          <span
            className="w-2 h-2 rounded-none shrink-0"
            style={{ backgroundColor: nodeColor }}
            title={`Color code: ${nodeColor}`}
          />
          {getFileIcon(file.name)}
          <span className="font-mono text-xs font-semibold text-white tracking-tight truncate">
            {file.name}
          </span>
          <span className="text-[9px] px-1 py-0.2 rounded-none bg-black text-[#888888] font-mono border border-[#222222] shrink-0">
            {file.language}
          </span>

          {/* Contributor Tag */}
          {file.contributorName && (
            <div
              className="flex items-center gap-1 px-1.5 py-0.2 rounded-none text-[9.5px] font-mono border select-none shrink-0 font-medium bg-black"
              style={{
                borderColor: `${nodeColor}60`,
                color: nodeColor,
              }}
              title={`Contributor: ${file.contributorName}`}
            >
              <span className="w-1.5 h-1.5 rounded-none" style={{ backgroundColor: nodeColor }} />
              <span className="truncate max-w-[85px]">{file.contributorName}</span>
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
                      className="w-4 h-4 rounded-none flex items-center justify-center text-[8px] font-mono font-bold text-white border border-[#222222]"
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
          {/* Connect tool button */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              startConnection(file.id);
            }}
            title="Connect to another file"
            className="flex items-center gap-1 px-1.5 py-0.5 rounded-none bg-black hover:bg-[#222222] text-[#888888] hover:text-white border border-[#222222] text-[10px] font-mono transition-colors"
          >
            <span>Connect</span>
            <ArrowRight className="w-3 h-3" />
          </button>

          {/* Inline Edit Toggle */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              setIsInlineEditing(!isInlineEditing);
            }}
            title={isInlineEditing ? "Exit inline edit" : "Edit buffer directly"}
            className={`p-1 rounded-none border transition-colors ${
              isInlineEditing
                ? "bg-white text-black border-white"
                : "text-[#888888] hover:text-white hover:bg-[#222222] border-transparent"
            }`}
          >
            <Edit3 className="w-3.5 h-3.5" />
          </button>

          {/* Open in IDE button */}
          {onOpenInIde && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onOpenInIde(file.id);
              }}
              title="Open in Editor"
              className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] border border-transparent transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Minimize toggle */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              setIsMinimized(!isMinimized);
            }}
            className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] border border-transparent transition-colors"
          >
            {isMinimized ? (
              <Maximize2 className="w-3.5 h-3.5" />
            ) : (
              <Minus className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      </div>

      {/* Editor Body inside spatial node */}
      {!isMinimized && (
        <div className="flex-1 overflow-hidden bg-black flex flex-col min-h-0">
          {isInlineEditing ? (
            <div className="flex-1 p-3 bg-black overflow-hidden flex flex-col">
              <textarea
                value={file.content}
                onChange={(e) => updateFileContent(file.id, e.target.value)}
                autoFocus
                className="w-full h-full bg-black text-white font-mono text-[11px] leading-[1.6] resize-none focus:outline-none border border-[#222222] rounded-none p-2"
                spellCheck={false}
              />
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto overflow-x-auto p-2.5 font-mono text-[11px] leading-[1.6] select-text bg-black">
              {lines.map((line, idx) => {
                const lineNum = idx + 1;
                const isPeerLine =
                  (file.id === "file-auth" && lineNum === 5) ||
                  (file.id === "file-stream-syncer" && lineNum === 8) ||
                  (file.id === "file-database" && lineNum === 6) ||
                  (file.id === "file-spatial" && lineNum === 5);

                return (
                  <div
                    key={idx}
                    className={`flex items-center group py-0.5 px-1 rounded-none relative ${
                      isPeerLine ? "bg-[#0A0A0A] border-l-2" : "hover:bg-[#0A0A0A]"
                    }`}
                    style={{
                      borderLeftColor: isPeerLine ? nodeColor : undefined,
                    }}
                  >
                    {/* Line number gutter */}
                    <span className="text-[#888888] select-none w-7 text-right pr-2 text-[10px] shrink-0 font-mono">
                      {lineNum}
                    </span>

                    {/* Syntax Highlighted Line Tokens */}
                    <div className="flex-1 overflow-hidden whitespace-pre font-mono">
                      {highlightSyntax(line)}
                    </div>

                    {/* Active Peer Cursor Chip inline */}
                    {isPeerLine && file.contributorName && (
                      <span
                        className="ml-2 px-1 py-0.2 rounded-none text-[9px] font-mono border shrink-0 font-medium bg-black"
                        style={{
                          borderColor: nodeColor,
                          color: nodeColor,
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
            <div
              className="h-6 px-2.5 border-t bg-[#0A0A0A] flex items-center justify-between text-[10px] font-mono select-none shrink-0"
              style={{
                borderTopColor: `${nodeColor}40`,
              }}
            >
              <div className="flex items-center gap-2 truncate">
                {incomingEdges.length > 0 && (
                  <div className="flex items-center gap-1.5 text-[#888888] truncate" title={`Consuming code from ${incomingEdges[0].sourceNodeId}`}>
                    <span
                      className="w-1.5 h-1.5 rounded-none"
                      style={{ backgroundColor: incomingEdges[0]?.color || "#007AFF" }}
                    />
                    <span className="text-[#888888]">in:</span>
                    <span className="text-white font-medium truncate max-w-[130px]">
                      {incomingEdges[0].codeSymbol || incomingEdges[0].label}
                    </span>
                  </div>
                )}
                {incomingEdges.length > 0 && outgoingEdges.length > 0 && (
                  <span className="text-[#222222]">·</span>
                )}
                {outgoingEdges.length > 0 && (
                  <div className="flex items-center gap-1.5 text-[#888888] truncate" title={`Streaming code to ${outgoingEdges[0].targetNodeId}`}>
                    <span className="w-1.5 h-1.5 rounded-none" style={{ backgroundColor: nodeColor }} />
                    <span className="text-[#888888]">out:</span>
                    <span className="font-medium truncate max-w-[130px]" style={{ color: nodeColor }}>
                      {outgoingEdges[0].changeCode || outgoingEdges[0].codeSymbol || outgoingEdges[0].label}
                    </span>
                  </div>
                )}
              </div>
              <div className="flex items-center gap-1.5 text-[9.5px] text-[#888888] shrink-0 pl-1">
                <span className="w-1.5 h-1.5 rounded-none" style={{ backgroundColor: nodeColor }} />
                <span className="font-medium">0.08ms</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
