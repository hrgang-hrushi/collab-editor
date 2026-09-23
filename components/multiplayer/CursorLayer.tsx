"use client";

import React from "react";
import { useWorkspaceStore } from "@/lib/store";
import { SpatialCursor, FileNode } from "@/lib/types";
import CruxPointerCursor from "../crux/CruxPointerCursor";

interface CursorDisplayProps {
  cursor: SpatialCursor;
  scale: number;
  activeFile?: FileNode;
}

function AnimatedCursor({ cursor, scale, activeFile }: CursorDisplayProps) {
  let worldX: number;
  let worldY: number;

  if (cursor.offsetX !== undefined && cursor.offsetY !== undefined && activeFile) {
    const fileOriginX = Number.isFinite(activeFile.x) ? activeFile.x : 0;
    const fileOriginY = Number.isFinite(activeFile.y) ? activeFile.y : 0;
    worldX = Math.round(fileOriginX + cursor.offsetX);
    worldY = Math.round(fileOriginY + cursor.offsetY);
  } else {
    worldX = Math.round(cursor.targetX ?? cursor.x ?? 0);
    worldY = Math.round(cursor.targetY ?? cursor.y ?? 0);
  }

  return (
    <CruxPointerCursor
      name={cursor.userName}
      uid={cursor.userUid || (cursor.userId.includes("1") ? "CRX-9941-SL" : cursor.userId.includes("2") ? "CRX-0001-AI" : "CRX-5520-MV")}
      color={cursor.userColor}
      status={cursor.status || (cursor.isTyping ? "typing" : undefined)}
      x={worldX}
      y={worldY}
    />
  );
}

export default function CursorLayer() {
  const remoteCursors = useWorkspaceStore((state) => state.remoteCursors);
  const files = useWorkspaceStore((state) => state.files);
  const zoom = useWorkspaceStore((state) => state.canvasTransform.zoom);

  return (
    <div className="absolute inset-0 pointer-events-none overflow-visible">
      {Object.values(remoteCursors).map((cursor) => {
        const activeFile = cursor.activeFileId
          ? files.find((f) => f.id === cursor.activeFileId)
          : undefined;

        return (
          <AnimatedCursor
            key={cursor.userId}
            cursor={cursor}
            scale={zoom}
            activeFile={activeFile}
          />
        );
      })}
    </div>
  );
}
