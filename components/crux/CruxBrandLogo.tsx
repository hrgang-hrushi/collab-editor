"use client";

import React from "react";
import { MetalBadge } from "metal-fx";

interface CruxBrandLogoProps {
  size?: number;
  withText?: boolean;
  className?: string;
  showBadge?: boolean;
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
  size = 22,
  withText = true,
  className = "",
  showBadge = false,
}: CruxBrandLogoProps) {
  return (
    <div className={`inline-flex items-center gap-2 select-none ${className}`}>
      {/* Brand Display Logo: Crux in Etna Sans Serif */}
      <span
        className="font-brand font-black tracking-[0px] text-white leading-none select-none inline-block"
        style={{
          fontFamily: "'Etna Sans Serif', 'Etna', sans-serif",
          fontSize: size,
        }}
      >
        Crux
      </span>

      {showBadge && (
        <div className="metal-badge-transparent inline-flex items-center ml-1 select-none">
          <MetalBadge
            theme="dark"
            textColor="#FFFFFF"
            core={{ r: 0, blur: 0, a: 0, size: 0 }}
            gradient={0}
            glow={0}
          >
            PRO
          </MetalBadge>
        </div>
      )}
    </div>
  );
}
