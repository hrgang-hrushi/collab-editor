"use client";

import React, { useState, useRef, useCallback } from "react";
import { motion } from "framer-motion";

interface AeyePerformanceSectionProps {
  onOpenTour?: (stepIndex?: number) => void;
}

// Benchmark datasets for the 4 interactive categories
const DATASETS = [
  // Dataset 0: Pipeline Generation Time (< 1.8s)
  Array.from({ length: 100 }, (_, i) => ({
    low: Math.round(15 + Math.sin(i * 0.15) * 10 + (i % 7) * 2),
    high: Math.round(75 + Math.cos(i * 0.12) * 15 + ((i * 3) % 9)),
  })),
  // Dataset 1: Execution Speed (2-4x Faster)
  Array.from({ length: 100 }, (_, i) => ({
    low: Math.round(10 + ((i * 2) % 15)),
    high: Math.round(82 + Math.sin(i * 0.2) * 12),
  })),
  // Dataset 2: Steps Reduction (~ 90%)
  Array.from({ length: 100 }, (_, i) => ({
    low: Math.round(20 + Math.cos(i * 0.18) * 12),
    high: Math.round(88 + ((i * 5) % 10)),
  })),
  // Dataset 3: Output Consistency (< 1.8s)
  Array.from({ length: 100 }, (_, i) => ({
    low: Math.round(12 + Math.sin(i * 0.1) * 8),
    high: Math.round(91 + ((i * 4) % 8)),
  })),
];

export default function AeyePerformanceSection({ onOpenTour }: AeyePerformanceSectionProps) {
  const [activeMetricIdx, setActiveMetricIdx] = useState<number>(0);
  const [sliderPos, setSliderPos] = useState<number>(50); // percentage 0 - 100
  const [isDragging, setIsDragging] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const stats = [
    { value: "< 1.8s", label: "Generated Time", desc: "SIMD AST-CRDT pipeline pass" },
    { value: "2-4x", label: "Faster Execution", desc: "Direct Metal & WebGPU rasterizer" },
    { value: "~ 90%", label: "Steps Reduction", desc: "Zero Electron DOM serialization" },
    { value: "< 1.8s", label: "Output Consistency", desc: "Attested compiler-verified output" },
  ];

  const presets = [
    { label: "Input-to-Photon (4.2ms)", metricIdx: 1, slider: 40 },
    { label: "Cold-Start Launch (0.08s)", metricIdx: 0, slider: 65 },
    { label: "RAM Footprint (38MB)", metricIdx: 2, slider: 50 },
    { label: "250K Scroll (120 FPS)", metricIdx: 3, slider: 30 },
  ];

  const currentBars = DATASETS[activeMetricIdx] || DATASETS[0];
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
            <span className="text-[#444444]">|</span>
            <span className="text-white font-medium">BARE-METAL BENCHMARK MATRIX</span>
          </div>
          <div className="flex items-center gap-3 pt-2 sm:pt-0">
            {onOpenTour && (
              <button
                onClick={() => onOpenTour(1)}
                className="px-2.5 py-1 bg-[#111114] hover:bg-[#1a1a24] border border-[#0055FF]/60 hover:border-[#0055FF] text-white text-[11px] font-mono uppercase tracking-wider flex items-center gap-1.5 cursor-pointer rounded-none"
              >
                <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                <span>START TELEMETRY TOUR</span>
              </button>
            )}
            <div className="text-[11px] text-[#71717a] font-mono">
              HARDWARE-ACCELERATED TELEMETRY
            </div>
          </div>
        </div>

        {/* Top Area: Headline + Button on left, 2x2 Clickable Metric Grid on right */}
        <div className="pt-6 pb-6 sm:pb-8 grid grid-cols-1 lg:grid-cols-12 gap-8 items-end">
          {/* Left Column: Heading + Actions */}
          <div className="lg:col-span-7">
            <h2 className="text-4xl sm:text-5xl lg:text-[56px] font-normal tracking-[-0.05em] text-white font-sans leading-[1.08]">
              Real-time intelligence.<br />
              Zero unnecessary work.
            </h2>

            <div className="mt-5 flex flex-wrap items-center gap-3">
              <a
                href="/ide"
                className="inline-flex items-center gap-2.5 px-6 py-3.5 bg-[#000000] border border-white hover:border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none cursor-pointer rounded-none font-medium no-underline group"
              >
                <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block transition-none" />
                <span>LAUNCH IN LIVE IDE ↵</span>
              </a>

              <a
                href="#waitlist"
                className="inline-flex items-center gap-2.5 px-6 py-3.5 bg-[#0e0e11] border border-[#333333] hover:border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none cursor-pointer rounded-none font-medium no-underline group"
              >
                <span>JOIN WAITLIST</span>
              </a>
            </div>
          </div>

          {/* Right Column: 2x2 Interactive Metric Grid (Click to switch dataset) */}
          <div className="lg:col-span-5 border border-[#222222] bg-[#000000] grid grid-cols-2 divide-x divide-y divide-[#222222] rounded-none">
            {stats.map((item, idx) => {
              const isSelected = activeMetricIdx === idx;
              return (
                <button
                  key={idx}
                  onClick={() => setActiveMetricIdx(idx)}
                  className={`p-5 sm:p-6 flex flex-col justify-between min-h-[110px] text-left cursor-pointer transition-none rounded-none border-none outline-none ${
                    isSelected ? "bg-[#0c0c14] border-l-2 border-l-[#0055FF]" : "bg-[#000000] hover:bg-[#070709]"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div
                      className={`text-3xl sm:text-4xl font-normal font-sans tracking-tight transition-none ${
                        isSelected ? "text-[#0055FF] font-semibold" : "text-white"
                      }`}
                    >
                      {item.value}
                    </div>
                    {isSelected && (
                      <span className="w-2 h-2 bg-[#0055FF] rounded-none" />
                    )}
                  </div>
                  <div>
                    <div className="mt-2 text-xs sm:text-sm text-white font-sans">
                      {item.label}
                    </div>
                    <div className="text-[10px] text-[#71717a] font-mono truncate">
                      {item.desc}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Quick Benchmark Preset Selectors */}
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3 font-mono text-xs">
          <div className="flex items-center gap-2 text-[#71717a]">
            <span className="text-white font-bold">[BENCHMARK PRESETS]:</span>
            <span>Click to compare hardware profiles</span>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {presets.map((p, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setActiveMetricIdx(p.metricIdx);
                  setSliderPos(p.slider);
                }}
                className={`px-2.5 py-1 text-[11px] font-mono cursor-pointer rounded-none border transition-none ${
                  activeMetricIdx === p.metricIdx
                    ? "bg-[#0055FF] text-white border-[#0055FF] font-bold"
                    : "bg-[#111114] text-[#888888] border-[#222222] hover:text-white"
                }`}
              >
                {p.label}
              </button>
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
            {/* Background 8 Vertical Dashed Grid Columns */}
            <div className="absolute inset-0 grid grid-cols-8 pointer-events-none z-0">
              {gridIntervals.slice(0, 8).map((_, i) => (
                <div
                  key={i}
                  className="h-full border-r border-dashed border-[#222222]"
                />
              ))}
            </div>

            {/* Base Layer: WITHOUT CRUX (gray/dark bars) */}
            <div className="absolute inset-0 z-10 pointer-events-none px-4 pt-5 pb-3 flex items-end">
              <svg
                viewBox="0 0 1000 300"
                preserveAspectRatio="none"
                className="w-full h-full overflow-visible"
              >
                {currentBars.map((bar, i) => {
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

            {/* Top Clipped Layer: WITH CRUX (tall electric blue bars) */}
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
                {currentBars.map((bar, i) => {
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
              className="absolute top-0 bottom-0 w-[2px] bg-[#0055FF] z-30 pointer-events-none"
            >
              <div className="absolute top-1/2 -translate-y-1/2 -left-3.5 w-7 h-7 bg-[#0055FF] border border-white flex items-center justify-center shadow-lg">
                <span className="text-[10px] text-white font-mono font-bold select-none">&lt;&gt;</span>
              </div>
            </div>

            {/* Float Labels: Without Crux vs With Crux */}
            <div className="absolute top-4 left-4 z-40 bg-[#000000]/80 border border-[#222222] px-3 py-1.5 text-xs font-mono text-[#888888]">
              TRADITIONAL ELECTRON: <span className="text-white">UNOPTIMIZED</span>
            </div>
            <div className="absolute top-4 right-4 z-40 bg-[#0055FF]/20 border border-[#0055FF] px-3 py-1.5 text-xs font-mono text-[#0055FF] font-bold">
              WITH CRUX: <span className="text-white">HARDWARE NATIVE</span>
            </div>
          </div>

          {/* Footer Bar */}
          <div className="h-10 px-4 border-t border-[#222222] bg-[#08080a] flex items-center justify-between text-[11px] font-mono">
            <span className="text-[#71717a]">
              ACTIVE METRIC: <strong className="text-white">{stats[activeMetricIdx].label}</strong>
            </span>
            <span className="text-[#0055FF] font-bold">
              DRAG SLIDER TO REVEAL BARE-METAL DELTA
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}
