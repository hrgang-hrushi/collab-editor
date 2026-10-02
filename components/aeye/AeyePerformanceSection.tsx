"use client";

import React, { useState, useRef, useCallback } from "react";
import { motion } from "framer-motion";

// 80 data bars (exactly 10 bars per 100-unit dividend across 8 dividends: 0 - 800)
const CHART_BARS = [
  // Dividend 1: 0 - 100 (bars 0 - 9)
  { low: 8, high: 82 }, { low: 12, high: 85 }, { low: 18, high: 88 }, { low: 26, high: 91 }, { low: 34, high: 94 },
  { low: 42, high: 92 }, { low: 46, high: 89 }, { low: 38, high: 87 }, { low: 30, high: 85 }, { low: 24, high: 88 },

  // Dividend 2: 100 - 200 (bars 10 - 19)
  { low: 20, high: 90 }, { low: 25, high: 93 }, { low: 32, high: 89 }, { low: 38, high: 91 }, { low: 44, high: 95 },
  { low: 52, high: 93 }, { low: 58, high: 90 }, { low: 64, high: 92 }, { low: 55, high: 94 }, { low: 45, high: 91 },

  // Dividend 3: 200 - 300 (bars 20 - 29)
  { low: 40, high: 88 }, { low: 32, high: 86 }, { low: 22, high: 89 }, { low: 15, high: 92 }, { low: 10, high: 94 },
  { low: 8, high: 91 }, { low: 10, high: 88 }, { low: 15, high: 85 }, { low: 22, high: 87 }, { low: 30, high: 90 },

  // Dividend 4: 300 - 400 (bars 30 - 39)
  { low: 38, high: 92 }, { low: 45, high: 94 }, { low: 50, high: 96 }, { low: 46, high: 93 }, { low: 40, high: 90 },
  { low: 36, high: 88 }, { low: 42, high: 91 }, { low: 48, high: 95 }, { low: 54, high: 93 }, { low: 48, high: 89 },

  // Dividend 5: 400 - 500 (bars 40 - 49)
  { low: 42, high: 91 }, { low: 38, high: 93 }, { low: 44, high: 95 }, { low: 48, high: 92 }, { low: 52, high: 89 },
  { low: 50, high: 91 }, { low: 45, high: 94 }, { low: 40, high: 96 }, { low: 35, high: 93 }, { low: 32, high: 90 },

  // Dividend 6: 500 - 600 (bars 50 - 59)
  { low: 28, high: 92 }, { low: 33, high: 95 }, { low: 40, high: 93 }, { low: 46, high: 90 }, { low: 52, high: 93 },
  { low: 56, high: 96 }, { low: 50, high: 94 }, { low: 44, high: 91 }, { low: 38, high: 89 }, { low: 34, high: 92 },

  // Dividend 7: 600 - 700 (bars 60 - 69)
  { low: 30, high: 94 }, { low: 36, high: 96 }, { low: 42, high: 92 }, { low: 48, high: 90 }, { low: 44, high: 93 },
  { low: 38, high: 95 }, { low: 32, high: 92 }, { low: 28, high: 89 }, { low: 34, high: 91 }, { low: 40, high: 94 },

  // Dividend 8: 700 - 800 (bars 70 - 79)
  { low: 45, high: 93 }, { low: 48, high: 95 }, { low: 42, high: 92 }, { low: 36, high: 90 }, { low: 30, high: 88 },
  { low: 25, high: 86 }, { low: 20, high: 84 }, { low: 16, high: 82 }, { low: 12, high: 79 }, { low: 10, high: 75 },
];

export default function AeyePerformanceSection() {
  const [sliderPos, setSliderPos] = useState<number>(58); // percentage 0 - 100
  const [isDragging, setIsDragging] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const stats = [
    { value: "LIVE", label: "Collaborative editing" },
    { value: "MAP", label: "Spatial file context" },
    { value: "PTY", label: "Integrated terminal" },
    { value: "WEB", label: "Browser access" },
  ];

  const updatePosition = useCallback((clientX: number) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = Math.max(0, Math.min(clientX - rect.left, rect.width));
    const percent = Math.round((x / rect.width) * 100);
    setSliderPos(percent);
  }, []);

  const handlePointerDown = (e: React.PointerEvent) => {
    setIsDragging(true);
    updatePosition(e.clientX);
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  };

  const handlePointerMove = (e: React.PointerEvent) => {
    if (isDragging) {
      updatePosition(e.clientX);
    }
  };

  const handlePointerUp = (e: React.PointerEvent) => {
    setIsDragging(false);
    try {
      (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    } catch {}
  };

  return (
    <section id="performance" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[N.02/11]</span>
            <span className="text-[#888888]">— &gt;</span>
            <span className="text-[#888888] uppercase">WORKFLOW</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            ILLUSTRATIVE PRODUCT VIEW
          </div>
        </div>

        {/* Top Area: Headline + Button on left, 2x2 Metric Grid on right */}
        <div className="pt-6 pb-6 sm:pb-8 grid grid-cols-1 lg:grid-cols-12 gap-8 items-end">
          {/* Left Column: Heading + Action */}
          <div className="lg:col-span-7">
            <h2 className="text-4xl sm:text-5xl lg:text-[56px] font-normal tracking-[-0.05em] text-white font-sans leading-[1.08]">
              Code, context, and people.<br />
              In one workspace.
            </h2>

            <div className="mt-5">
              <a
                href="#waitlist"
                className="inline-flex items-center gap-2.5 px-6 py-3.5 bg-[#0e0e11] border border-[#333333] hover:border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none cursor-pointer rounded-none font-medium no-underline group"
              >
                <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block transition-none" />
                <span>GET STARTED</span>
              </a>
            </div>
          </div>

          {/* Right Column: Product capability grid */}
          <div className="lg:col-span-5 border border-[#222222] bg-[#000000] grid grid-cols-2 divide-x divide-y divide-[#222222] rounded-none">
            {stats.map((item, idx) => (
              <div key={idx} className="p-5 sm:p-6 flex flex-col justify-between min-h-[100px]">
                <div className="text-3xl sm:text-4xl font-normal text-white font-sans tracking-tight">
                  {item.value}
                </div>
                <div className="mt-2 text-xs sm:text-sm text-[#71717a] font-sans">
                  {item.label}
                </div>
              </div>
            ))}
          </div>
        </div>

          {/* Bottom Area: Illustrative workflow comparison */}
        <div className="border border-[#222222] bg-[#000000] relative rounded-none select-none overflow-hidden">
          {/* Chart Viewport */}
          <div
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
            className="relative w-full h-[320px] sm:h-[380px] md:h-[420px] overflow-hidden cursor-ew-resize touch-none bg-[#000000] px-4 sm:px-6"
          >
            {/* Inner Plot Area spanning 100% of the bar graph space */}
            <div ref={containerRef} className="relative w-full h-full">
              {/* 7 Vertical Dashed Grid Lines matching dividends 100 to 700 */}
              <div className="absolute inset-0 pointer-events-none z-0">
                {[12.5, 25, 37.5, 50, 62.5, 75, 87.5].map((pct) => (
                  <div
                    key={pct}
                    style={{ left: `${pct}%` }}
                    className="absolute top-0 bottom-0 w-[1px] border-r border-dashed border-[#222222]"
                  />
                ))}
              </div>

              {/* Base Layer: scattered tools, shown illustratively */}
              <div className="absolute inset-0 z-10 pointer-events-none pt-6 pb-3 flex items-end">
                <svg
                  viewBox="0 0 800 300"
                  preserveAspectRatio="none"
                  className="w-full h-full overflow-visible"
                >
                  {CHART_BARS.map((bar, i) => {
                    const barHeight = (bar.low / 100) * 280;
                    return (
                      <rect
                        key={i}
                        x={i * 10 + 2}
                        y={300 - barHeight}
                        width="6"
                        height={barHeight}
                        fill="#26262b"
                      />
                    );
                  })}
                </svg>
              </div>

              {/* Top Layer: one workspace, shown illustratively */}
              <div
                style={{
                  clipPath: `inset(0px 0px 0px ${sliderPos}%)`,
                  WebkitClipPath: `inset(0px 0px 0px ${sliderPos}%)`,
                }}
                className="absolute inset-0 z-20 pointer-events-none pt-6 pb-3 flex items-end transition-none"
              >
                <svg
                  viewBox="0 0 800 300"
                  preserveAspectRatio="none"
                  className="w-full h-full overflow-visible"
                >
                  {CHART_BARS.map((bar, i) => {
                    const barHeight = (bar.high / 100) * 280;
                    return (
                      <rect
                        key={i}
                        x={i * 10 + 2}
                        y={300 - barHeight}
                        width="6"
                        height={barHeight}
                        fill="#0055FF"
                      />
                    );
                  })}
                </svg>
              </div>

              {/* Slider Dividing Vertical Line in Electric Blue */}
              <div
                style={{ left: `${sliderPos}%` }}
                className="absolute top-0 bottom-0 w-[1.5px] bg-[#0055FF] -translate-x-1/2 z-30 pointer-events-none shadow-[0_0_8px_rgba(0,85,255,0.7)]"
              />

              {/* Slider Handle in the Center: [ WITHOUT CRUX < ] [■] [ > WITH CRUX ] */}
              <div
                style={{ left: `${sliderPos}%`, top: "50%" }}
                className="absolute -translate-x-1/2 -translate-y-1/2 z-40 pointer-events-none flex items-center gap-1.5 whitespace-nowrap select-none"
              >
                {/* Left Badge: WITHOUT CRUX < */}
                <div className="px-2.5 py-1 bg-[#0a0a0c] border border-[#222222] text-[#888888] text-[11px] font-mono uppercase tracking-wider rounded-none">
                  <span>SCATTERED TOOLS</span>
                  <span className="ml-1 text-[#666666]">&lt;</span>
                </div>

                {/* Blue Center Square */}
                <div className="w-4 h-4 bg-[#0055FF] border border-white flex items-center justify-center rounded-none shadow-[0_0_8px_rgba(0,85,255,0.8)]">
                  <span className="w-1 h-1 bg-white inline-block" />
                </div>

                {/* Right Badge: > WITH CRUX */}
                <div className="px-2.5 py-1 bg-[#0a0a0c] border border-[#222222] text-white text-[11px] font-mono uppercase tracking-wider rounded-none font-medium">
                  <span className="mr-1 text-[#0055FF] font-bold">&gt;</span>
                  <span>ONE WORKSPACE</span>
                </div>
              </div>
            </div>
          </div>

          <div className="border-t border-[#222222] bg-[#000000] py-3 px-4 sm:px-6 font-mono text-xs text-[#71717a]">
            Concept illustration of a connected workflow. Bars are not performance measurements.
          </div>
        </div>
      </div>
    </section>
  );
}
