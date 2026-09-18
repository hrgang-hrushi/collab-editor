"use client";

import React from "react";

export default function VoidCanvas({ children }: { children?: React.ReactNode }) {
  return (
    <div className="relative w-screen h-screen bg-[#000000] text-white overflow-hidden select-none flex flex-col font-sans">
      {/* 1. Subtle 12px Dot Grid */}
      <div
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: "radial-gradient(#444444 1px, transparent 1px)",
          backgroundSize: "16px 16px",
        }}
      />

      {/* 2. Hairline Center Crosshairs Reticle */}
      <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
        {/* Horizontal center hairline ticks */}
        <div className="absolute w-12 h-[1px] bg-[#262626]" />
        {/* Vertical center hairline ticks */}
        <div className="absolute h-12 w-[1px] bg-[#262626]" />
        {/* Center reticle ring */}
        <div className="w-6 h-6 rounded-full border border-[#1a1a1a]" />
      </div>

      {/* 3. Corner Hairline Brackets */}
      <div className="absolute top-4 left-4 pointer-events-none font-mono text-[10px] text-[#333333] flex items-center gap-1.5">
        <span className="text-[#555555]">┌</span>
        <span>SYS.RETICLE // 0.0.0</span>
      </div>
      <div className="absolute top-4 right-4 pointer-events-none font-mono text-[10px] text-[#333333] flex items-center gap-1.5">
        <span>GRID 16PX</span>
        <span className="text-[#555555]">┐</span>
      </div>
      <div className="absolute bottom-4 left-4 pointer-events-none font-mono text-[10px] text-[#333333] flex items-center gap-1.5">
        <span className="text-[#555555]">└</span>
        <span>LATENCY: 0.04ms</span>
      </div>
      <div className="absolute bottom-4 right-4 pointer-events-none font-mono text-[10px] text-[#333333] flex items-center gap-1.5">
        <span>ENCLAVE: SECURE</span>
        <span className="text-[#555555]">┘</span>
      </div>

      {/* Content slot */}
      {children}
    </div>
  );
}
