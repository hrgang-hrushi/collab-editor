"use client";

import React, { useState, useRef, useCallback } from "react";
import { motion } from "framer-motion";

// 100 data bars with realistic benchmark distribution matching reference screenshot
const CHART_BARS = [
  // 0 - 19
  { low: 8, high: 78 }, { low: 10, high: 82 }, { low: 14, high: 89 }, { low: 18, high: 86 }, { low: 22, high: 94 },
  { low: 26, high: 91 }, { low: 24, high: 76 }, { low: 28, high: 90 }, { low: 32, high: 93 }, { low: 30, high: 85 },
  { low: 28, high: 79 }, { low: 32, high: 88 }, { low: 34, high: 83 }, { low: 36, high: 80 }, { low: 32, high: 74 },
  { low: 28, high: 81 }, { low: 24, high: 76 }, { low: 22, high: 73 }, { low: 20, high: 80 }, { low: 18, high: 77 },
  // 20 - 39
  { low: 22, high: 83 }, { low: 26, high: 85 }, { low: 28, high: 82 }, { low: 30, high: 80 }, { low: 32, high: 86 },
  { low: 34, high: 84 }, { low: 38, high: 90 }, { low: 42, high: 82 }, { low: 40, high: 78 }, { low: 38, high: 85 },
  { low: 35, high: 81 }, { low: 28, high: 79 }, { low: 22, high: 87 }, { low: 18, high: 84 }, { low: 12, high: 88 },
  { low: 10, high: 88 }, { low: 8, high: 83 }, { low: 6, high: 75 }, { low: 8, high: 78 }, { low: 10, high: 76 },
  // 40 - 59
  { low: 12, high: 82 }, { low: 16, high: 84 }, { low: 20, high: 80 }, { low: 24, high: 85 }, { low: 28, high: 83 },
  { low: 32, high: 89 }, { low: 30, high: 81 }, { low: 28, high: 87 }, { low: 32, high: 83 }, { low: 34, high: 76 },
  { low: 38, high: 84 }, { low: 34, high: 81 }, { low: 30, high: 88 }, { low: 26, high: 82 }, { low: 28, high: 86 },
  { low: 30, high: 84 }, { low: 34, high: 87 }, { low: 36, high: 89 }, { low: 32, high: 85 }, { low: 28, high: 88 },
  // 60 - 79
  { low: 25, high: 90 }, { low: 22, high: 93 }, { low: 26, high: 95 }, { low: 28, high: 91 }, { low: 30, high: 88 },
  { low: 26, high: 92 }, { low: 22, high: 89 }, { low: 18, high: 91 }, { low: 20, high: 95 }, { low: 24, high: 93 },
  { low: 26, high: 90 }, { low: 28, high: 94 }, { low: 30, high: 96 }, { low: 32, high: 91 }, { low: 34, high: 94 },
  { low: 32, high: 95 }, { low: 28, high: 88 }, { low: 24, high: 84 }, { low: 22, high: 85 }, { low: 25, high: 89 },
  // 80 - 99
  { low: 28, high: 91 }, { low: 30, high: 94 }, { low: 32, high: 92 }, { low: 35, high: 89 }, { low: 38, high: 93 },
  { low: 36, high: 95 }, { low: 32, high: 91 }, { low: 28, high: 87 }, { low: 25, high: 90 }, { low: 22, high: 92 },
  { low: 20, high: 89 }, { low: 18, high: 86 }, { low: 16, high: 84 }, { low: 15, high: 88 }, { low: 18, high: 90 },
  { low: 20, high: 92 }, { low: 22, high: 88 }, { low: 25, high: 85 }, { low: 22, high: 82 }, { low: 18, high: 79 },
];

export default function AeyePerformanceSection() {
  const [sliderPos, setSliderPos] = useState<number>(50); // percentage 0 - 100
  const [isDragging, setIsDragging] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const stats = [
    { value: "< 1.8s", label: "Generated Time" },
    { value: "2-4x", label: "Faster Execution" },
    { value: "~ 90%", label: "Steps Reduction" },
    { value: "< 1.8s", label: "Output Consistency" },
  ];

  const gridIntervals = [0, 100, 200, 300, 400, 500, 600, 700, 800];

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
            <span className="text-[#888888] uppercase">PERFORMANCE</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            HARDWARE-ACCELERATED BENCHMARKS
          </div>
        </div>

        {/* Top Area: Headline + Button on left, 2x2 Metric Grid on right */}
        <div className="pt-6 pb-6 sm:pb-8 grid grid-cols-1 lg:grid-cols-12 gap-8 items-end">
          {/* Left Column: Heading + Action */}
          <div className="lg:col-span-7">
            <h2 className="text-4xl sm:text-5xl lg:text-[56px] font-normal tracking-[-0.05em] text-white font-sans leading-[1.08]">
              Real-time intelligence.<br />
              Zero unnecessary work.
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

          {/* Right Column: 2x2 Metric Grid matching screenshot */}
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

        {/* Bottom Area: Vector Interactive Benchmark Comparison Visualizer */}
        <div className="border border-[#222222] bg-[#000000] relative rounded-none select-none overflow-hidden">
          {/* Chart Viewport */}
          <div
            ref={containerRef}
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
            className="relative w-full h-[320px] sm:h-[380px] md:h-[420px] overflow-hidden cursor-ew-resize touch-none bg-[#000000]"
          >
            {/* Background 8 Vertical Dashed Grid Columns matching screenshot */}
            <div className="absolute inset-0 grid grid-cols-8 pointer-events-none z-0">
              {gridIntervals.slice(0, 8).map((_, i) => (
                <div
                  key={i}
                  className="h-full border-r border-dashed border-[#222222]"
                />
              ))}
            </div>

            {/* Base Layer: WITHOUT CRUX (short, muted gray/dark bars) */}
            <div className="absolute inset-0 z-10 pointer-events-none px-4 pt-5 pb-3 flex items-end">
              <svg
                viewBox="0 0 1000 300"
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
                      width="5.5"
                      height={barHeight}
                      fill="#26262b"
                    />
                  );
                })}
              </svg>
            </div>

            {/* Top Clipped Layer: WITH CRUX (tall, vibrant electric blue bars) */}
            <div
              style={{
                clipPath: `inset(0px 0px 0px ${sliderPos}%)`,
                WebkitClipPath: `inset(0px 0px 0px ${sliderPos}%)`,
              }}
              className="absolute inset-0 z-20 pointer-events-none px-4 pt-5 pb-3 flex items-end transition-none"
            >
              <svg
                viewBox="0 0 1000 300"
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
                      width="5.5"
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
                <span>WITHOUT CRUX</span>
                <span className="ml-1 text-[#666666]">&lt;</span>
              </div>

              {/* Blue Center Square */}
              <div className="w-4 h-4 bg-[#0055FF] border border-white flex items-center justify-center rounded-none shadow-[0_0_8px_rgba(0,85,255,0.8)]">
                <span className="w-1 h-1 bg-white inline-block" />
              </div>

              {/* Right Badge: > WITH CRUX */}
              <div className="px-2.5 py-1 bg-[#0a0a0c] border border-[#222222] text-white text-[11px] font-mono uppercase tracking-wider rounded-none font-medium">
                <span className="mr-1 text-[#0055FF] font-bold">&gt;</span>
                <span>WITH CRUX</span>
              </div>
            </div>
          </div>

          {/* Bottom X-Axis Scale (0 to 800) matching screenshot */}
          <div className="relative w-full border-t border-[#222222] bg-[#000000] py-3 px-4 font-mono text-xs text-[#71717a]">
            <div className="grid grid-cols-8 text-left">
              {gridIntervals.map((num, i) => (
                <div
                  key={i}
                  className={
                    i === 0
                      ? "text-left"
                      : i === 8
                      ? "text-right"
                      : "text-left -ml-2"
                  }
                >
                  {num}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
