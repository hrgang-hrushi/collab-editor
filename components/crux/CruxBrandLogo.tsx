"use client";

import React from "react";

interface CruxBrandLogoProps {
  size?: number;
  withText?: boolean;
  className?: string;
}

/**
 * Crux / Crex Brand Logo Component
 * Derived directly from the Canva design export (1.svg & 2.svg):
 * - 2x2 modular grid:
 *   - Top-Right: Elevated White Block (#FFFFFF)
 *   - Top-Left, Bottom-Left, Bottom-Right: Dark Industrial Blocks (#222222)
 * - Optional "Crex" / "Crux" geometric typography lockup
 */
export default function CruxBrandLogo({
  size = 20,
  withText = false,
  className = "",
}: CruxBrandLogoProps) {
  if (withText) {
    return (
      <div className={`flex items-center gap-2.5 select-none ${className}`}>
        {/* Modular Grid Icon Mark */}
        <div
          className="grid grid-cols-2 gap-[2px] shrink-0"
          style={{ width: size, height: size }}
        >
          {/* Top-Left: Dark Tile */}
          <div className="bg-[#222222] border border-[#333333] rounded-[2px]" />
          {/* Top-Right: Elevated White Tile */}
          <div className="bg-[#FFFFFF] border border-[#FFFFFF] rounded-[2px] shadow-[1px_1px_0px_#000000]" />
          {/* Bottom-Left: Dark Tile */}
          <div className="bg-[#222222] border border-[#333333] rounded-[2px]" />
          {/* Bottom-Right: Dark Tile */}
          <div className="bg-[#222222] border border-[#333333] rounded-[2px]" />
        </div>

        {/* Wordmark */}
        <span
          className="font-bold tracking-wider text-signal uppercase"
          style={{ fontSize: Math.max(12, size * 0.7) }}
        >
          Crux
        </span>
      </div>
    );
  }

  // Standalone Icon Mark (1:1 with 1.svg)
  return (
    <div
      className={`grid grid-cols-2 gap-[2px] shrink-0 select-none ${className}`}
      style={{ width: size, height: size }}
      title="Crux Platform"
    >
      {/* Top-Left */}
      <div className="bg-[#222222] border border-[#333333] rounded-[2px]" />
      {/* Top-Right (Elevated White Block) */}
      <div className="bg-[#FFFFFF] border border-[#FFFFFF] rounded-[2px] shadow-[1px_1px_0px_#000000]" />
      {/* Bottom-Left */}
      <div className="bg-[#222222] border border-[#333333] rounded-[2px]" />
      {/* Bottom-Right */}
      <div className="bg-[#222222] border border-[#333333] rounded-[2px]" />
    </div>
  );
}
