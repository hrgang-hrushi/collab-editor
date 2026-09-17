"use client";

import React, { useEffect, useRef, useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { SpatialCursor, FileNode } from "@/lib/types";

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
    <div
      className="absolute top-0 left-0 pointer-events-none z-50 select-none"
      style={{
        transform: `translate3d(${worldX}px, ${worldY}px, 0)`,
        willChange: "transform",
      }}
    >
      {/* Flat and Sharp SVG Caret - Zero drop shadow, zero blur */}
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        fill="none"
        className="shrink-0"
      >
        <path
          d="M0 0L14 5.5L7.5 7.5L5.5 14L0 0Z"
          fill={cursor.userColor}
          stroke="#000000"
          strokeWidth="1"
          strokeLinejoin="miter"
        />
      </svg>

      {/* Flat & Sharp Name Badge - 1px border matching user color, pure flat surface */}
      <div
        className="ml-2 -mt-3 inline-flex items-center gap-1.5 px-1.5 py-0.5 bg-[#0A0A0A] border text-[9.5px] font-mono text-[#f7f8f8] select-none whitespace-nowrap shadow-none"
        style={{
          borderColor: `${cursor.userColor}80`,
        }}
      >
        <span
          className="w-1.5 h-1.5 rounded-none shrink-0"
          style={{ backgroundColor: cursor.userColor }}
        />
        <span className="font-medium">{cursor.userName}</span>
        {cursor.userId === "user-2" && (
          <span className="text-[8px] text-[#8b5cf6] font-bold px-0.5 bg-[#8b5cf6]/10 border border-[#8b5cf6]/30">
            AI
          </span>
        )}
      </div>
    </div>
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

      // Sarah Lin drifts inside auth.ts (inspecting Ed25519 signature checks)
      const sarahLocalX = 180 + Math.sin(now / 2200) * 80 + (Math.random() * 20 - 10);
      const sarahLocalY = 190 + Math.cos(now / 2600) * 55 + (Math.random() * 20 - 10);
      updateRemoteCursor("user-1", {
        offsetX: Math.round(sarahLocalX),
        offsetY: Math.round(sarahLocalY),
        targetX: Math.round(sarahLocalX),
        targetY: Math.round(sarahLocalY),
      });

      // CruxAI suggests optimizations inside database.ts (write ahead log ring buffer)
      const cruxLocalX = 210 + Math.sin(now / 2800) * 75;
      const cruxLocalY = 180 + Math.cos(now / 2400) * 45;
      updateRemoteCursor("user-2", {
        offsetX: Math.round(cruxLocalX),
        offsetY: Math.round(cruxLocalY),
        targetX: Math.round(cruxLocalX),
        targetY: Math.round(cruxLocalY),
      });

      // Marcus Vance profiles 120Hz lerp inside spatialEngine.ts
      const marcusLocalX = 200 + Math.cos(now / 3000) * 90;
      const marcusLocalY = 175 + Math.sin(now / 2700) * 50;
      updateRemoteCursor("user-3", {
        offsetX: Math.round(marcusLocalX),
        offsetY: Math.round(marcusLocalY),
        targetX: Math.round(marcusLocalX),
        targetY: Math.round(marcusLocalY),
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
