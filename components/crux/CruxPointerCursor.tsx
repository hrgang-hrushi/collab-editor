"use client";

import React from "react";

interface CruxPointerCursorProps {
  name: string;
  uid?: string;
  color?: string;
  status?: string;
  x?: number;
  y?: number;
}

/**
 * Calculates whether a hex color is perceived as light,
 * to ensure high contrast text on the collaborator tag.
 */
function isLightColor(hex?: string): boolean {
  if (!hex) return false;
  const c = hex.replace("#", "");
  if (c.length !== 6) return false;
  const r = parseInt(c.slice(0, 2), 16);
  const g = parseInt(c.slice(2, 4), 16);
  const b = parseInt(c.slice(4, 6), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance > 0.65;
}

/**
 * Crux Pointer Cursor
 * - Precision Canva Vector Dart Geometry
 * - Uniform, ultra-crisp 1.4px pure white stroke outline (zero blur / zero glow)
 * - Seamlessly tucked collaborator badge with matching 1.2px white border
 * - Smooth 3px corner radius with flush top-left anchor to the arrow notch
 */
export default function CruxPointerCursor({
  name = "Peer",
  uid,
  color = "#38b6ff",
  status,
  x,
  y,
}: CruxPointerCursorProps) {
  const resolvedUid =
    uid ||
    (name.toLowerCase().includes("ai") || name.toLowerCase().includes("copilot")
      ? "CRX-0001-AI"
      : name.toLowerCase().includes("marcus")
      ? "CRX-5520-MV"
      : "CRX-PEER");
  const textColor = isLightColor(color) ? "#000000" : "#FFFFFF";

  return (
    <div
      className="absolute pointer-events-none z-50 select-none flex items-start"
      style={{
        transform: x !== undefined && y !== undefined ? `translate3d(${x}px, ${y}px, 0)` : undefined,
        willChange: "transform",
      }}
    >
      <div className="relative flex items-start">
        {/* Crisp Dart Arrow with Uniform Vector Outline */}
        <svg
          width="21"
          height="23"
          viewBox="380 180 980 1140"
          fill="none"
          className="relative z-10 overflow-visible shrink-0"
        >
          <path
            d="M 1274.457031 729.308594 L 546.890625 251.507812 C 520.140625 233.945312 486.679688 233.585938 459.5625 250.59375 C 432.449219 267.589844 418.1875 297.863281 422.347656 329.597656 L 535.460938 1192.640625 C 539.992188 1227.210938 564.972656 1254.15625 599.101562 1261.28125 C 620.257812 1265.699219 641.238281 1261.726562 658.417969 1250.957031 C 668.945312 1244.355469 678.054688 1235.191406 684.890625 1223.839844 L 868.773438 918.429688 C 871.691406 913.578125 876.800781 910.378906 882.421875 909.871094 L 1237.433594 877.410156 C 1272.164062 874.226562 1300.058594 850.324219 1308.515625 816.496094 C 1316.96875 782.667969 1303.597656 748.445312 1274.457031 729.308594 "
            fill={color}
            stroke="#FFFFFF"
            strokeWidth="70"
            strokeLinejoin="round"
            strokeLinecap="round"
          />
        </svg>

        {/* Seamless Collaborator Pill Tag with Matching Pointer Color Outline & Corner Curve Radius */}
        <div
          className="absolute left-[11px] top-[11px] z-0 px-2 py-[2.5px] text-[10px] font-sans font-semibold leading-tight select-none whitespace-nowrap border-[1.2px] rounded-[4px] rounded-tl-none flex items-center gap-1.5 shadow-md"
          style={{
            backgroundColor: color,
            color: textColor,
            borderColor: color,
          }}
        >
          <span>{name}</span>
          {status === "typing" ? (
            <span className="inline-flex items-center gap-0.5 text-[9px] font-normal lowercase opacity-95">
              <span>typing</span>
              <span className="inline-flex gap-0.5 ml-0.5">
                <span className="w-1 h-1 rounded-full bg-current animate-bounce [animation-delay:-0.3s]" />
                <span className="w-1 h-1 rounded-full bg-current animate-bounce [animation-delay:-0.15s]" />
                <span className="w-1 h-1 rounded-full bg-current animate-bounce" />
              </span>
            </span>
          ) : (
            <>
              {resolvedUid && <span className="opacity-75 text-[8.5px] font-mono font-normal tracking-tight">[{resolvedUid}]</span>}
              {status && <span className="opacity-80 text-[8.5px] uppercase tracking-wider">({status})</span>}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
