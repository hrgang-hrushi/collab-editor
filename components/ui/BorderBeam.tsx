"use client";

import React, { useState, useEffect } from "react";
import {
  BorderBeam as RawBorderBeam,
  type BorderBeamProps,
  type BorderBeamSize,
  type BorderBeamColorVariant,
} from "border-beam";

export type { BorderBeamProps, BorderBeamSize, BorderBeamColorVariant };

/**
 * Returns CSS overrides for the exact Crux landing page blue: #0055FF / rgb(0, 85, 255).
 * Replaces the multi-color / purple tones with pure, vivid electric blue matching the landing page.
 */
function getCruxBlueCss(size?: BorderBeamSize): string {
  if (size === "pulse-outside") {
    return `
[data-beam="{id}"][data-active]::after,
[data-beam="{id}"][data-fading]::after {
  background: radial-gradient(ellipse calc(80px * var(--bw1-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(19px * var(--bh1-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(27% + var(--bx1-{id})) calc(0% + var(--by1-{id})), rgba(0, 85, 255, var(--bop-tl-{id})), transparent),
    radial-gradient(ellipse calc(74px * var(--bw2-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(11px * var(--bh2-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(73% + var(--bx2-{id})) calc(-1% + var(--by2-{id})), rgba(0, 85, 255, var(--bop-tr-{id})), transparent),
    radial-gradient(ellipse calc(15px * var(--bw3-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(44px * var(--bh3-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(100% + var(--bx3-{id})) calc(33% + var(--by3-{id})), rgba(51, 119, 255, var(--bop-tr-{id})), transparent),
    radial-gradient(ellipse calc(19px * var(--bw1-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(38px * var(--bh1-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(101% + var(--bx1-{id})) calc(72% + var(--by1-{id})), rgba(0, 85, 255, var(--bop-br-{id})), transparent),
    radial-gradient(ellipse calc(84px * var(--bw2-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(13px * var(--bh2-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(67% + var(--bx2-{id})) calc(100% + var(--by2-{id})), rgba(0, 68, 204, var(--bop-br-{id})), transparent),
    radial-gradient(ellipse calc(60px * var(--bw3-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(21px * var(--bh3-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(24% + var(--bx3-{id})) calc(101% + var(--by3-{id})), rgba(0, 85, 255, var(--bop-bl-{id})), transparent),
    radial-gradient(ellipse calc(17px * var(--bw1-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(40px * var(--bh1-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(0% + var(--bx1-{id})) calc(60% + var(--by1-{id})), rgba(51, 119, 255, var(--bop-bl-{id})), transparent),
    radial-gradient(ellipse calc(13px * var(--bw2-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(32px * var(--bh2-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(-1% + var(--bx2-{id})) calc(28% + var(--by2-{id})), rgba(0, 85, 255, var(--bop-tl-{id})), transparent) !important;
  filter: brightness(1.3) !important;
}

[data-beam="{id}"][data-active]::before,
[data-beam="{id}"][data-fading]::before {
  background: radial-gradient(ellipse calc(80px * var(--bw1-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(19px * var(--bh1-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(27% + var(--bx1-{id})) calc(0% + var(--by1-{id})), rgba(0, 85, 255, var(--bop-tl-{id})), transparent),
    radial-gradient(ellipse calc(74px * var(--bw2-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(11px * var(--bh2-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(73% + var(--bx2-{id})) calc(-1% + var(--by2-{id})), rgba(0, 85, 255, var(--bop-tr-{id})), transparent),
    radial-gradient(ellipse calc(15px * var(--bw3-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(44px * var(--bh3-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(100% + var(--bx3-{id})) calc(33% + var(--by3-{id})), rgba(51, 119, 255, var(--bop-tr-{id})), transparent),
    radial-gradient(ellipse calc(19px * var(--bw1-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(38px * var(--bh1-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(101% + var(--bx1-{id})) calc(72% + var(--by1-{id})), rgba(0, 85, 255, var(--bop-br-{id})), transparent),
    radial-gradient(ellipse calc(84px * var(--bw2-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(13px * var(--bh2-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(67% + var(--bx2-{id})) calc(100% + var(--by2-{id})), rgba(0, 68, 204, var(--bop-br-{id})), transparent),
    radial-gradient(ellipse calc(60px * var(--bw3-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(21px * var(--bh3-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(24% + var(--bx3-{id})) calc(101% + var(--by3-{id})), rgba(0, 85, 255, var(--bop-bl-{id})), transparent),
    radial-gradient(ellipse calc(17px * var(--bw1-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(40px * var(--bh1-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(0% + var(--bx1-{id})) calc(60% + var(--by1-{id})), rgba(51, 119, 255, var(--bop-bl-{id})), transparent),
    radial-gradient(ellipse calc(13px * var(--bw2-{id}) * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(32px * var(--bh2-{id}) * var(--bgh-{id}) * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at calc(-1% + var(--bx2-{id})) calc(28% + var(--by2-{id})), rgba(0, 85, 255, var(--bop-tl-{id})), transparent) !important;
  filter: blur(var(--beam-core-blur, 3px)) brightness(1.4) !important;
}

[data-beam="{id}"][data-active] [data-beam-bloom],
[data-beam="{id}"][data-fading] [data-beam-bloom] {
  background: radial-gradient(ellipse calc(110px * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(30px * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at 27% 3%, rgba(0, 85, 255, 0.85), transparent),
    radial-gradient(ellipse calc(100px * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(20px * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at 73% 1%, rgba(0, 85, 255, 0.85), transparent),
    radial-gradient(ellipse calc(26px * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(62px * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at 100% 33%, rgba(51, 119, 255, 0.85), transparent),
    radial-gradient(ellipse calc(30px * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(56px * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at 101% 72%, rgba(0, 85, 255, 0.85), transparent),
    radial-gradient(ellipse calc(120px * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(22px * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at 67% 99%, rgba(0, 68, 204, 0.85), transparent),
    radial-gradient(ellipse calc(88px * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(32px * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at 24% 99%, rgba(0, 85, 255, 0.85), transparent),
    radial-gradient(ellipse calc(28px * var(--pulse-glow-sx, 1) * var(--pulse-glow-boost, 1)) calc(58px * var(--pulse-glow-sy, 1) * var(--pulse-glow-boost, 1)) at 0% 60%, rgba(51, 119, 255, 0.85), transparent) !important;
  filter: blur(var(--beam-bloom-blur, 20px)) !important;
}
`;
  }

  // Rotating conic-gradient beam (md, sm, line, etc.) tuned to exact #0055FF
  return `
[data-beam="{id}"][data-active]::after,
[data-beam="{id}"][data-fading]::after {
  background: conic-gradient(
    from var(--beam-angle-{id}),
    transparent 0%, transparent 52%,
    rgba(0, 85, 255, 0.15) 58%,
    rgba(0, 85, 255, 0.6) 63%,
    rgba(0, 85, 255, 0.95) 67%,
    #0055FF 69%,
    #80b3ff 70.5%,
    #0055FF 72%,
    rgba(0, 85, 255, 0.95) 74%,
    rgba(0, 85, 255, 0.6) 78%,
    rgba(0, 85, 255, 0.15) 83%,
    transparent 88%, transparent 100%
  ) !important;
  filter: brightness(1.25) !important;
}

[data-beam="{id}"][data-active]::before,
[data-beam="{id}"][data-fading]::before {
  background: conic-gradient(
    from var(--beam-angle-{id}),
    transparent 0%, transparent 54%,
    rgba(0, 85, 255, 0.2) 60%,
    rgba(0, 85, 255, 0.65) 66%,
    #0055FF 70.5%,
    rgba(0, 85, 255, 0.65) 75%,
    rgba(0, 85, 255, 0.2) 81%,
    transparent 87%, transparent 100%
  ) !important;
  filter: blur(4px) brightness(1.3) !important;
}

[data-beam="{id}"][data-active] [data-beam-bloom],
[data-beam="{id}"][data-fading] [data-beam-bloom] {
  background: conic-gradient(
    from var(--beam-angle-{id}),
    transparent 0%, transparent 50%,
    rgba(0, 85, 255, 0.1) 58%,
    rgba(0, 85, 255, 0.5) 66%,
    rgba(0, 85, 255, 0.9) 70.5%,
    rgba(0, 85, 255, 0.5) 75%,
    rgba(0, 85, 255, 0.1) 83%,
    transparent 91%, transparent 100%
  ) !important;
  filter: blur(16px) !important;
}
`;
}

/**
 * SSR-safe BorderBeam wrapper for Next.js
 * Automatically styled with Crux landing page pure electric blue (#0055FF).
 * Prevents hydration mismatch caused by raw unescaped CSS @property text in SSR <style> tags.
 */
export function BorderBeam({
  children,
  className,
  style,
  size = "md",
  colorVariant = "ocean",
  staticColors = true,
  duration = 8.5,
  css: customCss,
  ...props
}: BorderBeamProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div className={className} style={style}>
        {children}
      </div>
    );
  }

  const blueCss = getCruxBlueCss(size);
  const combinedCss = customCss ? `${blueCss}\n${customCss}` : blueCss;

  return (
    <RawBorderBeam
      className={className}
      style={style}
      size={size}
      colorVariant={colorVariant}
      staticColors={staticColors}
      duration={duration}
      css={combinedCss}
      {...props}
    >
      {children}
    </RawBorderBeam>
  );
}

export default BorderBeam;
