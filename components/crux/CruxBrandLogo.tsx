"use client";

import React from "react";
import { MetalBadge } from "metal-fx";

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

        {/* Metallic PRO Badge with Transparent Background and Real-Time WebGL Shader Animation */}
        <div className="metal-badge-transparent inline-flex items-center ml-1">
          <MetalBadge
            theme="dark"
            scale={0.72}
            textColor="#FFFFFF"
            core={{ r: 0, blur: 0, a: 0, size: 0 }}
            gradient={0}
            glow={0}
          >
            PRO
          </MetalBadge>
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
