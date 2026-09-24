"use client";

import React, { useRef, useEffect } from "react";

interface InteractivePixelGridProps {
  backgroundColor?: string;
  boxSize?: number;
  borderWidth?: number;
  borderColor?: string;
  colors?: string[];
  outDuration?: number;
}

const DEFAULT_COLORS = [
  "rgba(0, 85, 255, 0.95)",
  "rgba(0, 85, 255, 0.70)",
  "rgba(0, 85, 255, 0.45)",
  "rgba(255, 255, 255, 0.90)",
  "rgba(255, 255, 255, 0.65)",
  "rgba(0, 110, 255, 0.60)",
];

interface ActivePixel {
  c: number;
  r: number;
  alpha: number;
  color: string;
  decayRate: number;
}

interface RippleWave {
  x: number;
  y: number;
  radius: number;
  maxRadius: number;
  speed: number;
}

export default function InteractivePixelGrid({
  backgroundColor = "#000000",
  boxSize = 48,
  borderWidth = 1,
  borderColor = "#222222",
  colors = DEFAULT_COLORS,
  outDuration = 1.2,
}: InteractivePixelGridProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) return;

    let animId: number;
    let width = 0;
    let height = 0;
    let cols = 0;
    let rows = 0;

    // Active pixel map: key is `${c}_${r}`
    const activePixels = new Map<string, ActivePixel>();
    const ripples: RippleWave[] = [];

    const handleResize = () => {
      const rect = container.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width;
      height = rect.height;

      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;

      ctx.scale(dpr, dpr);

      cols = Math.ceil(width / boxSize) + 1;
      rows = Math.ceil(height / boxSize) + 1;
    };

    handleResize();
    window.addEventListener("resize", handleResize);

    const activatePixel = (c: number, r: number, colorOverride?: string) => {
      if (c < 0 || c >= cols || r < 0 || r >= rows) return;
      const key = `${c}_${r}`;
      const color = colorOverride || colors[Math.floor(Math.random() * colors.length)];
      activePixels.set(key, {
        c,
        r,
        alpha: 1.0,
        color,
        decayRate: 1 / (outDuration * 60),
      });
    };

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      const c = Math.floor(x / boxSize);
      const r = Math.floor(y / boxSize);

      activatePixel(c, r);
      // Also occasionally illuminate a neighbor for a fluid brush trail
      if (Math.random() > 0.4) {
        const offsetC = c + (Math.random() > 0.5 ? 1 : -1);
        activatePixel(offsetC, r, "rgba(0, 85, 255, 0.4)");
      }
    };

    const handleClick = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      ripples.push({
        x,
        y,
        radius: 0,
        maxRadius: Math.max(width, height) * 0.7,
        speed: 16,
      });

      // Also illuminate center cluster immediately
      const centerC = Math.floor(x / boxSize);
      const centerR = Math.floor(y / boxSize);
      for (let dc = -1; dc <= 1; dc++) {
        for (let dr = -1; dr <= 1; dr++) {
          activatePixel(centerC + dc, centerR + dr, "rgba(0, 85, 255, 0.9)");
        }
      }
    };

    container.addEventListener("mousemove", handleMouseMove);
    container.addEventListener("click", handleClick);

    // Subtle ambient circuit sparks
    let sparkTimer = 0;

    let lastTime = performance.now();

    const render = (now: number) => {
      const delta = (now - lastTime) / 1000;
      lastTime = now;

      sparkTimer += delta;
      if (sparkTimer > 0.7) {
        sparkTimer = 0;
        if (Math.random() > 0.3) {
          const randC = Math.floor(Math.random() * cols);
          const randR = Math.floor(Math.random() * rows);
          activatePixel(randC, randR, "rgba(0, 85, 255, 0.6)");
        }
      }

      // Update ripples
      for (let i = ripples.length - 1; i >= 0; i--) {
        const rip = ripples[i];
        rip.radius += rip.speed;

        // Activate pixels along ripple perimeter
        const ringStep = Math.PI / 16;
        for (let angle = 0; angle < Math.PI * 2; angle += ringStep) {
          const rx = rip.x + Math.cos(angle) * rip.radius;
          const ry = rip.y + Math.sin(angle) * rip.radius;
          const rc = Math.floor(rx / boxSize);
          const rr = Math.floor(ry / boxSize);
          const intensity = Math.max(0.2, 1 - rip.radius / rip.maxRadius);
          activatePixel(rc, rr, `rgba(0, 85, 255, ${intensity * 0.75})`);
        }

        if (rip.radius >= rip.maxRadius) {
          ripples.splice(i, 1);
        }
      }

      // Clear with background color
      ctx.fillStyle = backgroundColor;
      ctx.fillRect(0, 0, width, height);

      // Draw grid lines
      ctx.strokeStyle = borderColor;
      ctx.lineWidth = borderWidth;
      ctx.beginPath();

      for (let x = 0; x <= width; x += boxSize) {
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
      }
      for (let y = 0; y <= height; y += boxSize) {
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
      }
      ctx.stroke();

      // Render active pixels
      activePixels.forEach((pix, key) => {
        ctx.fillStyle = pix.color;
        ctx.globalAlpha = Math.max(0, pix.alpha);
        ctx.fillRect(
          pix.c * boxSize + borderWidth,
          pix.r * boxSize + borderWidth,
          boxSize - borderWidth,
          boxSize - borderWidth
        );

        pix.alpha -= pix.decayRate;
        if (pix.alpha <= 0) {
          activePixels.delete(key);
        }
      });
      ctx.globalAlpha = 1.0;

      animId = requestAnimationFrame(render);
    };

    animId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", handleResize);
      container.removeEventListener("mousemove", handleMouseMove);
      container.removeEventListener("click", handleClick);
    };
  }, [backgroundColor, boxSize, borderWidth, borderColor, colors, outDuration]);

  return (
    <div
      ref={containerRef}
      className="relative w-full h-full overflow-hidden cursor-crosshair"
      style={{ backgroundColor }}
    >
      <canvas ref={canvasRef} className="block w-full h-full pointer-events-auto" />
    </div>
  );
}
