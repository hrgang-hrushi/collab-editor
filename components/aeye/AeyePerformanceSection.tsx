"use client";

import React, { useState, useRef, useEffect, useCallback } from "react";
import { motion } from "framer-motion";

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
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  };

  const handlePointerMove = (e: React.PointerEvent) => {
    updatePosition(e.clientX);
  };

  const handlePointerUp = (e: React.PointerEvent) => {
    setIsDragging(false);
    try {
      (e.target as HTMLElement).releasePointerCapture(e.pointerId);
    } catch {}
  };

  return (
    <section id="performance" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Line matching screenshot */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          className="flex items-center gap-3 pb-6 text-xs font-mono"
        >
          <span className="text-[#0055FF] font-semibold tracking-wider">[N.02/11]</span>
          <span className="w-8 h-[1px] bg-[#222222]" />
          <span className="text-[#0055FF] font-bold">&gt;</span>
          <span className="text-[#888888] uppercase tracking-wider font-semibold">PERFORMANCE</span>
          <div className="flex-1 h-[1px] bg-[#222222] ml-2" />
        </motion.div>

        {/* Top Area: Headline + Button on left, 2x2 Metric Grid on right */}
        <div className="pt-6 pb-14 grid grid-cols-1 lg:grid-cols-12 gap-10 items-end">
          {/* Left Column: Heading + Action */}
          <div className="lg:col-span-7">
            <motion.h2
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-40px" }}
              transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
              className="text-4xl sm:text-5xl lg:text-[56px] font-normal tracking-[-0.05em] text-white font-sans leading-[1.08]"
            >
              Real-time intelligence.<br />
              Zero unnecessary work.
            </motion.h2>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-40px" }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="mt-8"
            >
              <a
                href="/?app=true"
                className="inline-flex items-center gap-3 px-6 py-3.5 bg-[#0055FF] hover:bg-[#0044CC] text-white border border-[#0055FF] text-xs font-mono uppercase tracking-wider transition-none cursor-pointer rounded-none font-bold group"
              >
                <span className="w-2.5 h-2.5 bg-white inline-block transition-none" />
                <span>GET STARTED</span>
              </a>
            </motion.div>
          </div>

          {/* Right Column: 2x2 Stat Grid */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-40px" }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="lg:col-span-5 border border-[#222222] bg-[#000000] grid grid-cols-2 divide-x divide-y divide-[#222222] rounded-none"
          >
            {stats.map((item, idx) => (
              <div key={idx} className="p-6 sm:p-8 flex flex-col justify-between min-h-[120px]">
                <div className="text-3xl sm:text-4xl font-normal text-white font-sans tracking-tight">
                  {item.value}
                </div>
                <div className="mt-2 text-xs sm:text-sm text-[#71717a] font-sans">
                  {item.label}
                </div>
              </div>
            ))}
          </motion.div>
        </div>

        {/* Bottom Area: Interactive Before / After Comparison Visualizer */}
        <motion.div
          initial={{ opacity: 0, y: 25 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="mt-6 border border-[#222222] bg-[#000000] relative rounded-none select-none"
        >
          {/* Chart Viewport */}
          <div
            ref={containerRef}
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
            className="relative w-full h-[320px] sm:h-[420px] md:h-[480px] overflow-hidden cursor-ew-resize bg-[#000000]"
          >
            {/* Background Vertical Guide Dashed Lines */}
            <div className="absolute inset-0 grid grid-cols-8 pointer-events-none z-0">
              {gridIntervals.slice(0, 8).map((_, i) => (
                <div
                  key={i}
                  className="h-full border-r border-dashed border-[#222222]/80"
                />
              ))}
            </div>

            {/* Base Layer: "WITH CRUX" High-Performance Chart (vibrant blue original) */}
            <div className="absolute inset-0 z-10 pointer-events-none">
              <img
                src="/chart_after_dark.png"
                alt="With Crux Performance"
                className="w-full h-full object-fill pointer-events-none"
                draggable={false}
              />
            </div>

            {/* Clipped Overlay Layer: "WITHOUT CRUX" Low Muted Faint Chart */}
            <div
              style={{
                clipPath: `inset(0px ${100 - sliderPos}% 0px 0px)`,
                WebkitClipPath: `inset(0px ${100 - sliderPos}% 0px 0px)`,
              }}
              className="absolute inset-0 z-20 pointer-events-none opacity-60"
            >
              <img
                src="/chart_before_dark.png"
                alt="Without Crux Performance"
                className="w-full h-full object-fill pointer-events-none"
                draggable={false}
              />
            </div>

            {/* Central Divider 2px Line in Electric Blue */}
            <div
              style={{ left: `${sliderPos}%` }}
              className="absolute top-0 bottom-0 w-[2px] bg-[#0055FF] transform -translate-x-1/2 z-30 pointer-events-none shadow-[0_0_8px_rgba(0,85,255,0.8)]"
            />

            {/* Draggable Square Handle */}
            <div
              style={{ left: `${sliderPos}%`, top: "50%" }}
              className="absolute w-6 h-6 bg-[#0055FF] border-2 border-white transform -translate-x-1/2 -translate-y-1/2 z-40 pointer-events-none flex items-center justify-center rounded-none shadow-[0_0_12px_rgba(0,85,255,0.7)]"
            >
              <span className="w-1.5 h-1.5 bg-white inline-block" />
            </div>

            {/* Left Badge: WITHOUT CRUX < */}
            <div
              style={{
                right: `calc(${100 - sliderPos}% + 16px)`,
                top: "50%",
                transform: "translateY(-50%)",
              }}
              className="absolute z-40 flex items-center gap-1.5 px-2.5 py-1 bg-[#111111] border border-[#222222] text-white text-[11px] font-mono uppercase tracking-wider pointer-events-none whitespace-nowrap rounded-none"
            >
              <span>WITHOUT CRUX</span>
              <span className="text-[#888888]">&lt;</span>
            </div>

            {/* Right Badge: > WITH CRUX in Blue */}
            <div
              style={{
                left: `calc(${sliderPos}% + 16px)`,
                top: "50%",
                transform: "translateY(-50%)",
              }}
              className="absolute z-40 flex items-center gap-1.5 px-2.5 py-1 bg-[#0055FF]/10 border border-[#0055FF] text-[#0055FF] text-[11px] font-mono uppercase tracking-wider pointer-events-none whitespace-nowrap rounded-none font-bold"
            >
              <span className="text-[#0055FF] font-bold">&gt;</span>
              <span>WITH CRUX</span>
            </div>
          </div>

          {/* Bottom X-Axis Scale (0 to 800) */}
          <div className="relative w-full border-t border-[#222222] bg-[#000000] py-3 px-2 font-mono text-xs text-[#71717a]">
            <div className="grid grid-cols-8 text-left">
              {gridIntervals.map((num, i) => (
                <div
                  key={i}
                  className={
                    i === 0
                      ? "text-left pl-2"
                      : i === 8
                      ? "text-right pr-2"
                      : "text-left -ml-2"
                  }
                >
                  {num}
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
