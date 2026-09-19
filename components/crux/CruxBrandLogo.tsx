"use client";

import React from "react";


interface CruxBrandLogoProps {
  size?: number;
  withText?: boolean;
  className?: string;
}

/**
 * Crex Hardware Brutalism Brand Logo Component
 * - Strict 2x2 mechanical silicon grid:
 *   - Top-Right: Pure White Silk Block (#FFFFFF)
 *   - Top-Left, Bottom-Left, Bottom-Right: Deep Silicon Grid Tiles (#222222)
 * - 0px border radius, 0px drop shadow, absolute 1px hairline border.
 * - Brand Display Typography: Etna Sans Serif / Arial Black, heavy weight, -tracking-[0.05em].
 */
export default function CruxBrandLogo({
  size = 20,
  withText = false,
  className = "",
}: CruxBrandLogoProps) {
  if (withText) {
    return (
      <div className={`flex items-center gap-2 select-none ${className}`}>
        {/* Modular Grid Icon Mark (Zero border radius, zero shadow) */}
        <div
          className="grid grid-cols-2 gap-[1px] shrink-0"
          style={{ width: size, height: size }}
        >
          {/* Top-Left: Dark Silicon Tile */}
          <div className="bg-[#222222] border border-[#333333]" />
          {/* Top-Right: Elevated White Silk Tile */}
          <div className="bg-[#FFFFFF] border border-[#FFFFFF]" />
          {/* Bottom-Left: Dark Silicon Tile */}
          <div className="bg-[#222222] border border-[#333333]" />
          {/* Bottom-Right: Dark Silicon Tile */}
          <div className="bg-[#222222] border border-[#333333]" />
        </div>

        {/* Wordmark (Etna Sans Serif, 0 font spacing, heavy weight, C capitalized) */}
        <span
          className="font-brand font-black tracking-[0px] text-white"
          style={{ fontSize: Math.max(13, size * 0.75) }}
        >
          Crux
        </span>

        {/* Metallic PRO Badge with Transparent Background */}
        <div className="inline-flex items-center ml-1">
          <span
            className="px-1.5 py-0.5 text-[9px] font-mono font-bold tracking-widest uppercase bg-transparent border border-white/30 select-none transition-none"
            style={{
              background: "linear-gradient(135deg, #FFFFFF 0%, #999999 30%, #FFFFFF 50%, #666666 75%, #FFFFFF 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}
          >
            PRO
          </span>
        </div>
      </div>
    );
  }

  // Standalone Icon Mark
  return (
    <div
      className={`grid grid-cols-2 gap-[1px] shrink-0 select-none ${className}`}
      style={{ width: size, height: size }}
      title="Crex Platform"
    >
      {/* Top-Left */}
      <div className="bg-[#222222] border border-[#333333]" />
      {/* Top-Right */}
      <div className="bg-[#FFFFFF] border border-[#FFFFFF]" />
      {/* Bottom-Left */}
      <div className="bg-[#222222] border border-[#333333]" />
      {/* Bottom-Right */}
      <div className="bg-[#222222] border border-[#333333]" />
    </div>
  );
}
