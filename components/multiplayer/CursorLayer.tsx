"use client";

import React, { useEffect, useRef, useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { SpatialCursor, FileNode } from "@/lib/types";
import CruxPointerCursor from "../crux/CruxPointerCursor";

interface CursorDisplayProps {
  cursor: SpatialCursor;
  scale: number;
  activeFile?: FileNode;
}

function AnimatedCursor({ cursor, scale, activeFile }: CursorDisplayProps) {
  // Local offset within the active block (or absolute coords if unanchored)
  const initialX = cursor.offsetX ?? cursor.x;
  const initialY = cursor.offsetY ?? cursor.y;

  const [localPos, setLocalPos] = useState({ x: initialX, y: initialY });
  const animRef = useRef<number>();
  const currentPosRef = useRef({ x: initialX, y: initialY });
  const velRef = useRef({ x: 0, y: 0 });

  // Damped harmonic oscillator / spring interpolation for 120Hz liquid movement
  useEffect(() => {
    let lastTime = performance.now();

    const targetLocalX = cursor.offsetX ?? cursor.targetX;
    const targetLocalY = cursor.offsetY ?? cursor.targetY;

    const animate = (time: number) => {
      const dt = Math.min((time - lastTime) / 1000, 0.05); // cap at 50ms
      lastTime = time;

      const stiffness = 320;
      const damping = 28;

      const dx = targetLocalX - currentPosRef.current.x;
      const dy = targetLocalY - currentPosRef.current.y;

      const ax = dx * stiffness - velRef.current.x * damping;
      const ay = dy * stiffness - velRef.current.y * damping;

      velRef.current.x += ax * dt;
      velRef.current.y += ay * dt;

      currentPosRef.current.x += velRef.current.x * dt;
      currentPosRef.current.y += velRef.current.y * dt;

      setLocalPos({
        x: Math.round(currentPosRef.current.x * 10) / 10,
        y: Math.round(currentPosRef.current.y * 10) / 10,
      });

      animRef.current = requestAnimationFrame(animate);
    };

    animRef.current = requestAnimationFrame(animate);
    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current);
    };
  }, [cursor.offsetX, cursor.offsetY, cursor.targetX, cursor.targetY]);

  // ANCHORING TO BLOCK:
  // When activeFile moves (dragged on canvas), its x and y update instantaneously in state.
  // The cursor is rendered at (activeFile.x + localPos.x, activeFile.y + localPos.y).
  // Thus, the cursor moves 1-to-1 synchronously with the block at all times!
  const fileOriginX = activeFile ? activeFile.x : 0;
  const fileOriginY = activeFile ? activeFile.y : 0;

  // Clamp within file bounds so cursor stays inside the editor
  const maxX = activeFile ? activeFile.width - 40 : 99999;
  const maxY = activeFile ? activeFile.height - 30 : 99999;
  const clampedX = Math.max(30, Math.min(localPos.x, maxX));
  const clampedY = Math.max(42, Math.min(localPos.y, maxY));

  const worldX = fileOriginX + clampedX;
  const worldY = fileOriginY + clampedY;

  return (
    <CruxPointerCursor
      name={cursor.userName}
      uid={cursor.userUid || (cursor.userId === "user-1" ? "CRX-9941-SL" : cursor.userId === "user-2" ? "CRX-0001-AI" : "CRX-5520-MV")}
      color={cursor.userColor}
      x={worldX}
      y={worldY}
    />
  );
}

export default function CursorLayer() {
  const remoteCursors = useWorkspaceStore((state) => state.remoteCursors);
  const files = useWorkspaceStore((state) => state.files);
  const zoom = useWorkspaceStore((state) => state.canvasTransform.zoom);
  const updateRemoteCursor = useWorkspaceStore((state) => state.updateRemoteCursor);

  // Autonomous realistic simulation of remote teammates anchored to their files
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();

      // Sarah Lin inside auth.ts (inspecting Ed25519 signature checks)
      const sarahLocalX = 180 + Math.sin(now / 2200) * 40;
      const sarahLocalY = 150 + Math.cos(now / 2600) * 30;
      updateRemoteCursor("user-1", {
        offsetX: Math.round(sarahLocalX),
        offsetY: Math.round(sarahLocalY),
        targetX: Math.round(sarahLocalX),
        targetY: Math.round(sarahLocalY),
        x: Math.round(sarahLocalX),
        y: Math.round(sarahLocalY),
        activeFileId: "file-auth",
      });

      // CruxAI suggests optimizations inside stream_syncer.ts
      const cruxLocalX = 240 + Math.sin(now / 2800) * 30;
      const cruxLocalY = 135 + Math.cos(now / 2400) * 15;
      updateRemoteCursor("user-2", {
        offsetX: Math.round(cruxLocalX),
        offsetY: Math.round(cruxLocalY),
        targetX: Math.round(cruxLocalX),
        targetY: Math.round(cruxLocalY),
        x: Math.round(cruxLocalX),
        y: Math.round(cruxLocalY),
        activeFileId: "file-stream-syncer",
      });

      // Marcus Vance profiles 120Hz lerp inside spatialEngine.ts
      const marcusLocalX = 210 + Math.cos(now / 3000) * 45;
      const marcusLocalY = 160 + Math.sin(now / 2700) * 25;
      updateRemoteCursor("user-3", {
        offsetX: Math.round(marcusLocalX),
        offsetY: Math.round(marcusLocalY),
        targetX: Math.round(marcusLocalX),
        targetY: Math.round(marcusLocalY),
        x: Math.round(marcusLocalX),
        y: Math.round(marcusLocalY),
        activeFileId: "file-spatial",
      });
    }, 1600);

    return () => clearInterval(interval);
  }, [updateRemoteCursor]);

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
