"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import { playMagneticPulse, playMechanicalClick } from "@/lib/sound";

export type MagneticMode = "ATTRACT" | "DIPOLE" | "VORTEX";

interface Needle {
  x: number;
  y: number;
  baseX: number;
  baseY: number;
  angle: number;
  angularVelocity: number;
  length: number;
}

interface Shockwave {
  x: number;
  y: number;
  radius: number;
  speed: number;
  maxRadius: number;
  power: number;
}

interface MagneticNeedleFieldProps {
  gridSpacing?: number;
  needleLength?: number;
  influenceRadius?: number;
  initialMode?: MagneticMode;
  showTelemetry?: boolean;
}

export default function MagneticNeedleField({
  gridSpacing = 28,
  needleLength = 13,
  influenceRadius = 380,
  initialMode = "ATTRACT",
  showTelemetry = true,
}: MagneticNeedleFieldProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [mode, setMode] = useState<MagneticMode>(initialMode);
  const modeRef = useRef<MagneticMode>(initialMode);
  modeRef.current = mode;

  // Mouse tracking
  const mouseRef = useRef<{
    x: number;
    y: number;
    prevX: number;
    prevY: number;
    vx: number;
    vy: number;
    active: boolean;
    lastSeen: number;
  }>({
    x: -9999,
    y: -9999,
    prevX: -9999,
    prevY: -9999,
    vx: 0,
    vy: 0,
    active: false,
    lastSeen: 0,
  });

  const needlesRef = useRef<Needle[]>([]);
  const shockwavesRef = useRef<Shockwave[]>([]);
  const animFrameIdRef = useRef<number>(0);
  const [stats, setStats] = useState({ count: 0, activeNeedles: 0, fluxG: 0 });

  const cycleMode = useCallback(() => {
    playMechanicalClick("mid");
    setMode((curr) => {
      const next: MagneticMode =
        curr === "ATTRACT" ? "DIPOLE" : curr === "DIPOLE" ? "VORTEX" : "ATTRACT";
      return next;
    });
  }, []);

  // Shortest angle difference in [-PI, PI]
  const angleDiff = (target: number, current: number) => {
    let diff = target - current;
    while (diff < -Math.PI) diff += Math.PI * 2;
    while (diff > Math.PI) diff -= Math.PI * 2;
    return diff;
  };

  // Initialize needle grid according to container width/height
  const initNeedles = useCallback(
    (width: number, height: number) => {
      const needles: Needle[] = [];
      const cols = Math.ceil(width / gridSpacing) + 2;
      const rows = Math.ceil(height / gridSpacing) + 2;
      const offsetX = (width - (cols - 1) * gridSpacing) / 2;
      const offsetY = (height - (rows - 1) * gridSpacing) / 2;

      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const x = offsetX + c * gridSpacing;
          const y = offsetY + r * gridSpacing;
          needles.push({
            x,
            y,
            baseX: x,
            baseY: y,
            angle: 0,
            angularVelocity: 0,
            length: needleLength,
          });
        }
      }

      needlesRef.current = needles;
      setStats((prev) => ({ ...prev, count: needles.length }));
    },
    [gridSpacing, needleLength]
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) return;

    let width = 0;
    let height = 0;

    const handleResize = () => {
      if (!containerRef.current || !canvas) return;
      const rect = containerRef.current.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width;
      height = rect.height;

      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;

      ctx.scale(dpr, dpr);
      initNeedles(width, height);
    };

    handleResize();
    window.addEventListener("resize", handleResize);

    const onMouseMove = (e: MouseEvent) => {
      if (!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      const m = mouseRef.current;
      m.vx = mx - m.x;
      m.vy = my - m.y;
      m.prevX = m.x;
      m.prevY = m.y;
      m.x = mx;
      m.y = my;
      m.active = true;
      m.lastSeen = performance.now();
    };

    const onMouseLeave = () => {
      mouseRef.current.active = false;
      mouseRef.current.x = -9999;
      mouseRef.current.y = -9999;
    };

    const onClick = (e: MouseEvent) => {
      if (!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      playMagneticPulse();

      // Trigger high-velocity EMP Shockwave
      shockwavesRef.current.push({
        x: mx,
        y: my,
        radius: 6,
        speed: 820,
        maxRadius: Math.max(width, height) * 0.95,
        power: 1.0,
      });
    };

    const onKeyDown = (e: KeyboardEvent) => {
      if (
        document.activeElement?.tagName === "INPUT" ||
        document.activeElement?.tagName === "TEXTAREA"
      ) {
        return;
      }
      if (e.key.toLowerCase() === "m") {
        cycleMode();
      }
    };

    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseleave", onMouseLeave);
    window.addEventListener("click", onClick);
    window.addEventListener("keydown", onKeyDown);

    let lastTime = performance.now();
    let frameCounter = 0;

    const render = (now: number) => {
      const dt = Math.min((now - lastTime) / 1000, 0.05);
      lastTime = now;
      frameCounter++;

      const m = mouseRef.current;
      const isMouseActive = m.active && now - m.lastSeen < 4000;

      // Smooth velocity decay
      m.vx *= 0.88;
      m.vy *= 0.88;

      // Update shockwaves
      const activeShockwaves: Shockwave[] = [];
      for (const sw of shockwavesRef.current) {
        sw.radius += sw.speed * dt;
        sw.power = Math.max(0, 1 - sw.radius / sw.maxRadius);
        if (sw.radius < sw.maxRadius && sw.power > 0.01) {
          activeShockwaves.push(sw);
        }
      }
      shockwavesRef.current = activeShockwaves;

      // Clear Canvas to Absolute Void (#000000)
      ctx.fillStyle = "#000000";
      ctx.fillRect(0, 0, width, height);

      const needles = needlesRef.current;
      const timeSeconds = now * 0.001;
      let activeNearCursor = 0;

      // Compass physics
      const stiffness = 22.0;
      const damping = 0.84;
      const currentMode = modeRef.current;

      // Bucket queues for batch rendering
      const dimSegments: number[] = [];
      const midSegments: number[] = [];
      const brightSegments: number[] = [];
      const peakSegments: number[] = [];

      for (let i = 0; i < needles.length; i++) {
        const n = needles[i];

        // 1. Undulating Harmonic Vector Field (exact visual wave pattern from reference)
        const waveA = Math.sin(n.baseX * 0.0035 + timeSeconds * 1.8);
        const waveB = Math.cos(n.baseY * 0.0042 + timeSeconds * 1.4);
        const waveC = Math.sin((n.baseX + n.baseY) * 0.0028 - timeSeconds * 0.9);
        const ambientAngle = (waveA + waveB + waveC) * 0.85;

        let targetAngle = ambientAngle;
        let magneticWeight = 0;
        let displacementX = 0;
        let displacementY = 0;

        if (isMouseActive) {
          const dx = m.x - n.baseX;
          const dy = m.y - n.baseY;
          const distSq = dx * dx + dy * dy;
          const rSq = influenceRadius * influenceRadius;

          if (distSq < rSq) {
            activeNearCursor++;
            const dist = Math.sqrt(distSq);
            const normDist = dist / influenceRadius;
            magneticWeight = Math.max(0, 1 - normDist);
            const hermite = magneticWeight * magneticWeight * (3 - 2 * magneticWeight);

            let modeMagneticAngle = 0;

            if (currentMode === "ATTRACT") {
              // Direct attraction to cursor
              modeMagneticAngle = Math.atan2(dy, dx);
            } else if (currentMode === "DIPOLE") {
              // Magnetic dipole field: B = (3*(m.r_hat)*r_hat - m) / r^3
              // Using vertical magnetic dipole vector m = (0, 1)
              const rx = -dx / (dist || 1);
              const ry = -dy / (dist || 1);
              const mDotR = ry; // (0*rx + 1*ry)
              const bx = 3 * mDotR * rx;
              const by = 3 * mDotR * ry - 1;
              modeMagneticAngle = Math.atan2(by, bx);
            } else if (currentMode === "VORTEX") {
              // Electromagnetic circular vortex
              modeMagneticAngle = Math.atan2(dy, dx) + Math.PI * 0.5;
            }

            // Dynamic shear twist from cursor motion velocity
            const mouseSpeed = Math.sqrt(m.vx * m.vx + m.vy * m.vy);
            const speedFactor = Math.min(mouseSpeed * 0.025, 0.5);
            if (speedFactor > 0.02) {
              const motionAngle = Math.atan2(m.vy, m.vx);
              modeMagneticAngle = modeMagneticAngle * (1 - speedFactor) + motionAngle * speedFactor;
            }

            // Blend ambient field into magnetic field
            const diff = angleDiff(modeMagneticAngle, ambientAngle);
            targetAngle = ambientAngle + diff * hermite;

            // Physical magnetic attraction displacement
            const pullForce = (1 - normDist) * 5.5;
            displacementX = (dx / (dist || 1)) * pullForce;
            displacementY = (dy / (dist || 1)) * pullForce;
          }
        }

        // Shockwave EMP excitation
        for (const sw of activeShockwaves) {
          const sdx = n.baseX - sw.x;
          const sdy = n.baseY - sw.y;
          const sdist = Math.sqrt(sdx * sdx + sdy * sdy);
          const waveDist = Math.abs(sdist - sw.radius);

          if (waveDist < 80) {
            const waveFactor = (1 - waveDist / 80) * sw.power;
            const shockAngle = Math.atan2(sdy, sdx) + Math.PI * 0.5;
            const sDiff = angleDiff(shockAngle, targetAngle);
            targetAngle += sDiff * waveFactor * 0.9;
            n.angularVelocity += (Math.random() - 0.5) * waveFactor * 18;
            magneticWeight = Math.max(magneticWeight, waveFactor);
          }
        }

        // Integration with rotational momentum (Compass Inertia)
        const torque = angleDiff(targetAngle, n.angle) * stiffness;
        n.angularVelocity = (n.angularVelocity + torque * dt) * Math.pow(damping, dt * 60);
        n.angle += n.angularVelocity * dt;

        // Needle coordinates
        n.x = n.baseX + displacementX;
        n.y = n.baseY + displacementY;

        // Magnetic length stretch
        const currentLength = needleLength * (1 + magneticWeight * 0.55);
        const halfL = currentLength * 0.5;

        const cosA = Math.cos(n.angle);
        const sinA = Math.sin(n.angle);
        const x1 = n.x - cosA * halfL;
        const y1 = n.y - sinA * halfL;
        const x2 = n.x + cosA * halfL;
        const y2 = n.y + sinA * halfL;

        // Classify into brightness buckets
        if (magneticWeight > 0.65) {
          peakSegments.push(x1, y1, x2, y2);
        } else if (magneticWeight > 0.35) {
          brightSegments.push(x1, y1, x2, y2);
        } else if (magneticWeight > 0.08) {
          midSegments.push(x1, y1, x2, y2);
        } else {
          dimSegments.push(x1, y1, x2, y2);
        }
      }

      // 1. Draw Dim Background Needles (#222222)
      if (dimSegments.length > 0) {
        ctx.strokeStyle = "#222222";
        ctx.lineWidth = 1.0;
        ctx.beginPath();
        for (let i = 0; i < dimSegments.length; i += 4) {
          ctx.moveTo(dimSegments[i], dimSegments[i + 1]);
          ctx.lineTo(dimSegments[i + 2], dimSegments[i + 3]);
        }
        ctx.stroke();
      }

      // 2. Draw Mid Flux Needles (#444444)
      if (midSegments.length > 0) {
        ctx.strokeStyle = "#444444";
        ctx.lineWidth = 1.0;
        ctx.beginPath();
        for (let i = 0; i < midSegments.length; i += 4) {
          ctx.moveTo(midSegments[i], midSegments[i + 1]);
          ctx.lineTo(midSegments[i + 2], midSegments[i + 3]);
        }
        ctx.stroke();
      }

      // 3. Draw Bright Flux Needles (#999999)
      if (brightSegments.length > 0) {
        ctx.strokeStyle = "#999999";
        ctx.lineWidth = 1.25;
        ctx.beginPath();
        for (let i = 0; i < brightSegments.length; i += 4) {
          ctx.moveTo(brightSegments[i], brightSegments[i + 1]);
          ctx.lineTo(brightSegments[i + 2], brightSegments[i + 3]);
        }
        ctx.stroke();
      }

      // 4. Draw Peak Magnetic Core Needles (#FFFFFF Silk)
      if (peakSegments.length > 0) {
        ctx.strokeStyle = "#FFFFFF";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        for (let i = 0; i < peakSegments.length; i += 4) {
          ctx.moveTo(peakSegments[i], peakSegments[i + 1]);
          ctx.lineTo(peakSegments[i + 2], peakSegments[i + 3]);
        }
        ctx.stroke();
      }

      // 5. Draw EMP Shockwave Rings
      for (const sw of activeShockwaves) {
        ctx.strokeStyle = `rgba(255, 255, 255, ${sw.power * 0.75})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(sw.x, sw.y, sw.radius, 0, Math.PI * 2);
        ctx.stroke();
      }

      if (frameCounter % 12 === 0) {
        setStats({
          count: needles.length,
          activeNeedles: activeNearCursor,
          fluxG: isMouseActive ? Math.round(activeNearCursor * 14.5) : 0,
        });
      }

      animFrameIdRef.current = requestAnimationFrame(render);
    };

    animFrameIdRef.current = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animFrameIdRef.current);
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseleave", onMouseLeave);
      window.removeEventListener("click", onClick);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [initNeedles, influenceRadius, needleLength, cycleMode]);

  return (
    <div
      ref={containerRef}
      className="absolute inset-0 w-full h-full overflow-hidden pointer-events-auto select-none"
    >
      <canvas ref={canvasRef} className="absolute inset-0 block w-full h-full" />

      {/* Brutalist Hardware Telemetry Tag & Mode Switcher */}
      {showTelemetry && (
        <div className="absolute top-2.5 left-1/2 -translate-x-1/2 pointer-events-auto z-20 flex items-center gap-2 font-mono text-[9px] text-[#555555] bg-[#000000] border border-[#222222] px-2.5 py-1 select-none uppercase tracking-wider">
          <span className="text-[#333333]">[FLUX_FIELD]</span>
          <span className="text-white font-bold">{stats.fluxG}G</span>
          <span className="text-[#222222]">/</span>
          <span>{stats.count} NEEDLES</span>
          <span className="text-[#222222]">/</span>
          <button
            onClick={cycleMode}
            className="text-white hover:bg-white hover:text-black px-1 border border-[#333333] transition-none cursor-pointer"
            title="Press 'M' or click to cycle magnetic field mode"
          >
            MODE: {mode}
          </button>
          <span className="text-[#222222]">/</span>
          <span className="text-[#444444] hidden sm:inline">CLICK FOR EMP SHOCKWAVE</span>
        </div>
      )}
    </div>
  );
}
