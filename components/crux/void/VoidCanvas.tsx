"use client";

import React, { useState, useEffect } from "react";
import MagneticNeedleField from "./MagneticNeedleField";

export default function VoidCanvas({ children }: { children?: React.ReactNode }) {
  const [mousePos, setMousePos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      setMousePos({ x: e.clientX, y: e.clientY });
    };
    window.addEventListener("mousemove", handleMouseMove);
    return () => window.removeEventListener("mousemove", handleMouseMove);
  }, []);

  return (
    <div className="relative w-screen h-screen bg-[#000000] text-white overflow-hidden select-none flex flex-col font-sans">
      {/* 1. Macro Silicon Wafer Architectural Circuit Grid (Z-0) */}
      <div className="absolute inset-0 pointer-events-none z-0 overflow-hidden opacity-15">
        <svg
          className="w-full h-full stroke-[#1c1c1c] fill-none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <pattern id="pcb-grid" width="80" height="80" patternUnits="userSpaceOnUse">
              {/* Bus traces */}
              <path d="M 0 40 L 80 40 M 40 0 L 40 80" strokeWidth="0.5" stroke="#161616" />
              <path d="M 10 10 L 30 10 L 40 20 L 70 20" strokeWidth="0.75" stroke="#222222" />
              <path d="M 70 60 L 50 60 L 40 50 L 10 50" strokeWidth="0.75" stroke="#222222" />
              {/* Pin pads */}
              <circle cx="10" cy="10" r="1.5" fill="#222222" />
              <circle cx="70" cy="20" r="1.5" fill="#222222" />
              <circle cx="70" cy="60" r="1.5" fill="#222222" />
              <circle cx="10" cy="50" r="1.5" fill="#222222" />
              {/* Center test point */}
              <rect x="38" y="38" width="4" height="4" fill="#181818" stroke="#242424" strokeWidth="0.5" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#pcb-grid)" />
        </svg>
      </div>

      {/* 2. Magnetic Needle Vector Field (Z-5, Magnetic to Cursor) */}
      <div className="absolute inset-0 z-5">
        <MagneticNeedleField
          gridSpacing={28}
          needleLength={13}
          influenceRadius={380}
          initialMode="ATTRACT"
          showTelemetry={true}
        />
      </div>

      {/* 3. The Crex Effect: Dual Counter-Rotating Spinny Blur Gyroscope (Z-10) */}
      <div className="absolute inset-0 pointer-events-none z-10 overflow-hidden flex items-center justify-center opacity-25">
        {/* Layer A: Clockwise Rotating Silicon Turbine with Heavy Blur */}
        <div className="absolute w-[920px] h-[920px] crex-spinny-blur pointer-events-none select-none">

          <svg viewBox="0 0 500 500" className="w-full h-full stroke-[#555555] fill-none" strokeWidth="1">
            <circle cx="250" cy="250" r="230" strokeDasharray="3 8" />
            <circle cx="250" cy="250" r="190" strokeDasharray="16 6" />
            <circle cx="250" cy="250" r="150" strokeDasharray="8 4" />
            <circle cx="250" cy="250" r="110" strokeDasharray="2 12" />
            <circle cx="250" cy="250" r="70" strokeDasharray="10 8" />
            {/* Hex bus radiating spokes */}
            <line x1="20" y1="250" x2="480" y2="250" />
            <line x1="250" y1="20" x2="250" y2="480" />
            <line x1="87" y1="87" x2="413" y2="413" strokeDasharray="6 6" />
            <line x1="413" y1="87" x2="87" y2="413" strokeDasharray="6 6" />
            {/* Circuit notch marks */}
            <rect x="240" y="8" width="20" height="8" fill="#444444" />
            <rect x="240" y="484" width="20" height="8" fill="#444444" />
            <rect x="8" y="240" width="8" height="20" fill="#444444" />
            <rect x="484" y="240" width="8" height="20" fill="#444444" />
          </svg>
        </div>

        {/* Layer B: Counter-Rotating Ring (20s) */}
        <div
          className="absolute w-[680px] h-[680px] opacity-25 pointer-events-none select-none"
          style={{
            animation: "crexSpin 20s linear infinite reverse",
            maskImage: "radial-gradient(circle at center, rgba(0,0,0,1) 30%, rgba(0,0,0,0) 80%)",
            WebkitMaskImage: "radial-gradient(circle at center, rgba(0,0,0,1) 30%, rgba(0,0,0,0) 80%)",
          }}
        >
          <svg viewBox="0 0 400 400" className="w-full h-full stroke-[#444444] fill-none" strokeWidth="0.8">
            <circle cx="200" cy="200" r="180" strokeDasharray="1 6" />
            <circle cx="200" cy="200" r="140" strokeDasharray="12 4" />
            <circle cx="200" cy="200" r="100" strokeDasharray="6 8" />
            {/* Stenciled bus degree ticks */}
            {Array.from({ length: 24 }).map((_, i) => {
              const angle = (i * 360) / 24;
              const rad = (angle * Math.PI) / 180;
              const x1 = 200 + Math.cos(rad) * 160;
              const y1 = 200 + Math.sin(rad) * 160;
              const x2 = 200 + Math.cos(rad) * 175;
              const y2 = 200 + Math.sin(rad) * 175;
              return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} />;
            })}
          </svg>
        </div>

        {/* Layer C: Razor-Sharp Center Optical Reticle */}
        <div className="absolute w-48 h-48 border border-[#222222] pointer-events-none">
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-24 h-24 border border-[#222222]" />
            <div className="absolute w-full h-[1px] bg-[#222222]" />
            <div className="absolute h-full w-[1px] bg-[#222222]" />
            {/* Blinking activity micro-LED */}
            <div className="w-2 h-2 bg-white animate-hard-blink" />
          </div>
        </div>
      </div>

      {/* 3. Interactive Mouse Crosshair Tracker (Z-15) */}
      {mousePos.x > 0 && (
        <div className="absolute inset-0 pointer-events-none z-15">
          {/* Horizontal tracking hairline */}
          <div
            className="absolute left-0 right-0 h-[1px] bg-[#1a1a1a]"
            style={{ top: mousePos.y }}
          />
          {/* Vertical tracking hairline */}
          <div
            className="absolute top-0 bottom-0 w-[1px] bg-[#1a1a1a]"
            style={{ left: mousePos.x }}
          />
        </div>
      )}

      {/* Content Slot (Z-50) */}
      {children}
    </div>
  );
}
