"use client";

import React, { useState, useRef, useEffect } from "react";
import { motion, useScroll, useMotionValueEvent } from "framer-motion";
import Link from "next/link";

export default function AeyeHowItWorkSection() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [activeStep, setActiveStep] = useState(0);
  const [scrollProgress, setScrollProgress] = useState(0);
  const isManualClickRef = useRef(false);
  const manualTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end end"],
  });

  useMotionValueEvent(scrollYProgress, "change", (latest) => {
    setScrollProgress(latest);
    if (isManualClickRef.current) return;

    if (latest < 0.25) {
      setActiveStep(0);
    } else if (latest < 0.50) {
      setActiveStep(1);
    } else if (latest < 0.75) {
      setActiveStep(2);
    } else {
      setActiveStep(3);
    }
  });

  const handleStepClick = (idx: number) => {
    setActiveStep(idx);
    if (containerRef.current && typeof window !== "undefined") {
      if (window.innerWidth >= 1024) {
        isManualClickRef.current = true;
        if (manualTimeoutRef.current) clearTimeout(manualTimeoutRef.current);
        manualTimeoutRef.current = setTimeout(() => {
          isManualClickRef.current = false;
        }, 700);

        const rect = containerRef.current.getBoundingClientRect();
        const scrollTop = window.scrollY || document.documentElement.scrollTop;
        const containerTop = rect.top + scrollTop;
        const scrollableDistance = containerRef.current.offsetHeight - window.innerHeight;

        if (scrollableDistance > 0) {
          const targetProgress = idx === 0 ? 0.05 : idx === 1 ? 0.35 : idx === 2 ? 0.65 : 0.95;
          window.scrollTo({
            top: containerTop + targetProgress * scrollableDistance,
            behavior: "smooth",
          });
        }
      }
    }
  };

  const getStepFill = (idx: number, progress: number) => {
    // If not desktop or scroll hasn't started, fill up to activeStep
    if (typeof window !== "undefined" && window.innerWidth < 1024) {
      if (idx < activeStep) return 100;
      if (idx === activeStep) return 100;
      return 0;
    }
    const start = idx * 0.25;
    const end = (idx + 1) * 0.25;
    if (progress <= start) return 0;
    if (progress >= end) return 100;
    return ((progress - start) / (end - start)) * 100;
  };

  const steps = [
    {
      serial: "// 001",
      badge: "INGESTION",
      title: "Input your data",
      desc: "Add prompts, data, or context from your workflow with minimal setup.",
      renderIcon: (isActive: boolean) => (
        <svg
          viewBox="0 0 64 64"
          className="w-16 h-16 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Isometric Data Rack */}
          <path
            d="M32 6L54 18V26L32 38L10 26V18L32 6Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#444444"}
            strokeWidth="1.5"
          />
          <path
            d="M32 20L54 32V40L32 52L10 40V32L32 20Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#444444"}
            strokeWidth="1.5"
          />
          <path
            d="M32 34L54 46V54L32 66L10 54V46L32 34Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#444444"}
            strokeWidth="1.5"
          />
          {/* Pixel LED indicators */}
          {isActive && (
            <>
              <circle cx="20" cy="24" r="1.5" fill="#FFFFFF" />
              <circle cx="20" cy="38" r="1.5" fill="#FFFFFF" />
              <circle cx="20" cy="52" r="1.5" fill="#FFFFFF" />
            </>
          )}
        </svg>
      ),
    },
    {
      serial: "// 002",
      badge: "SYNTHESIS",
      title: "Process with AI",
      desc: "Transform inputs into structured, meaningful outputs in real time.",
      renderIcon: (isActive: boolean) => (
        <svg
          viewBox="0 0 64 64"
          className="w-16 h-16 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Isometric Chip / Processor */}
          <path
            d="M32 12L52 24V40L32 52L12 40V24L32 12Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#444444"}
            strokeWidth="1.5"
          />
          <path
            d="M32 20L44 27V37L32 44L20 37V27L32 20Z"
            fill={isActive ? "#0033AA" : "#000000"}
            stroke={isActive ? "#FFFFFF" : "#333333"}
            strokeWidth="1"
          />
          {/* Pin Traces radiating */}
          <path
            d="M18 20L10 15M24 16L18 10M40 16L46 10M46 20L54 15M50 36L58 41M46 44L52 50M18 44L12 50M14 36L6 41"
            stroke={isActive ? "#0055FF" : "#444444"}
            strokeWidth="1.5"
            strokeDasharray={isActive ? "2 2" : "none"}
          />
        </svg>
      ),
    },
    {
      serial: "// 003",
      badge: "EXECUTION",
      title: "Generate results",
      desc: "Turn processed data into actionable outputs ready to use, refine, or share.",
      renderIcon: (isActive: boolean) => (
        <svg
          viewBox="0 0 64 64"
          className="w-16 h-16 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Hexagonal node cluster */}
          {[
            { cx: 32, cy: 20 },
            { cx: 20, cy: 30 },
            { cx: 44, cy: 30 },
            { cx: 20, cy: 46 },
            { cx: 44, cy: 46 },
            { cx: 32, cy: 56 },
          ].map((pt, i) => (
            <g key={i}>
              <ellipse
                cx={pt.cx}
                cy={pt.cy}
                rx="6"
                ry="3"
                fill={isActive ? "#0055FF" : "#111111"}
                stroke={isActive ? "#FFFFFF" : "#444444"}
                strokeWidth="1.2"
              />
              <path
                d={`M${pt.cx - 6} ${pt.cy}V${pt.cy + 5}C${pt.cx - 6} ${pt.cy + 7} ${pt.cx + 6} ${pt.cy + 7} ${pt.cx + 6} ${pt.cy + 5}V${pt.cy}`}
                fill={isActive ? "#0044DD" : "#111111"}
                stroke={isActive ? "#0055FF" : "#444444"}
                strokeWidth="1.2"
              />
            </g>
          ))}
        </svg>
      ),
    },
    {
      serial: "// 004",
      badge: "RECURSION",
      title: "Refine and repeat",
      desc: "Iterate continuously on your pipeline with autonomous feedback loops.",
      renderIcon: (isActive: boolean) => (
        <svg
          viewBox="0 0 64 64"
          className="w-16 h-16 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Interlocking geometric bracket angles */}
          <path
            d="M32 10L48 18V28L32 20V10Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#FFFFFF" : "#444444"}
            strokeWidth="1.5"
          />
          <path
            d="M48 28L54 44L44 48L40 34L48 28Z"
            fill={isActive ? "#0044DD" : "#111111"}
            stroke={isActive ? "#0055FF" : "#444444"}
            strokeWidth="1.5"
          />
          <path
            d="M32 54L16 46V36L32 44V54Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#FFFFFF" : "#444444"}
            strokeWidth="1.5"
          />
          <path
            d="M16 36L10 20L20 16L24 30L16 36Z"
            fill={isActive ? "#0044DD" : "#111111"}
            stroke={isActive ? "#0055FF" : "#444444"}
            strokeWidth="1.5"
          />
        </svg>
      ),
    },
  ];

  return (
    <section id="how-it-works" className="relative w-full border-b border-[#222222] bg-[#000000]">
      {/* Scroll-driven Sticky Container */}
      <div ref={containerRef} className="relative lg:h-[300vh]">
        <div className="relative lg:sticky lg:top-0 lg:h-screen lg:flex lg:flex-col lg:justify-center overflow-visible lg:overflow-hidden py-14 lg:py-0">
          <div className="max-w-[1280px] w-full mx-auto px-6">
            {/* Section Header Meta with Live Step Tracking */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-5 border-b border-[#222222] text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="text-[#0055FF] font-bold">[N.04/11]</span>
                <span className="text-[#888888]">— &gt;</span>
                <span className="text-[#888888] uppercase">HOW IT WORKS</span>
              </div>
              <div className="flex items-center gap-3 pt-2 sm:pt-0">
                <span className="text-[10px] text-[#71717a] uppercase tracking-wider hidden sm:inline font-mono">
                  WORKFLOW PIPELINE
                </span>
                <div className="flex items-center gap-1.5">
                  {[0, 1, 2, 3].map((stepIdx) => (
                    <button
                      key={stepIdx}
                      type="button"
                      onClick={() => handleStepClick(stepIdx)}
                      className={`h-1.5 transition-all duration-300 rounded-none ${
                        activeStep === stepIdx ? "w-7 bg-[#0055FF]" : "w-2.5 bg-[#222222] hover:bg-[#444444]"
                      }`}
                      aria-label={`Jump to Step 0${stepIdx + 1}`}
                    />
                  ))}
                </div>
                <span className="text-xs font-mono text-[#0055FF] font-bold">
                  [ 0{activeStep + 1} / 04 ]
                </span>
              </div>
            </div>

            {/* Section Title & Subtitle + Action Button */}
            <div className="pt-8 pb-10 flex flex-col md:flex-row md:items-end justify-between gap-6">
              <div>
                <h2 className="text-3xl sm:text-4xl lg:text-[46px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
                  Understand the flow.
                  <span className="block text-[#888888]">See how it all connects.</span>
                </h2>
              </div>
              <div className="flex items-center gap-4 shrink-0">
                <div className="text-[11px] font-mono text-[#71717a] hidden md:flex items-center gap-2">
                  <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                  <span>SCROLL TO ADVANCE // STEP 0{activeStep + 1} OF 04</span>
                </div>
                <Link
                  href="#pricing"
                  className="inline-flex items-center gap-2.5 px-4 py-2 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none"
                >
                  <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                  GET STARTED
                </Link>
              </div>
            </div>

            {/* 4 Connected Process Columns with Cumulative Blue Bars and Active Spotlight */}
            <div className="border border-[#222222] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 bg-[#000000] relative">
              {steps.map((step, idx) => {
                const isActive = activeStep === idx;
                const fillWidth = getStepFill(idx, scrollProgress);

                return (
                  <div
                    key={idx}
                    onClick={() => handleStepClick(idx)}
                    onMouseEnter={() => setActiveStep(idx)}
                    className={`relative p-6 sm:p-7 flex flex-col justify-between min-h-[340px] sm:min-h-[360px] cursor-pointer transition-all duration-300 border-b sm:border-b-0 ${
                      idx !== 3 ? "lg:border-r border-[#222222]" : ""
                    } ${idx % 2 === 0 ? "sm:border-r border-[#222222]" : ""} ${
                      isActive
                        ? "bg-[#0a0a10] border-[#0055FF] shadow-[0_0_24px_rgba(0,85,255,0.16)] scale-[1.01] z-20"
                        : "bg-[#000000] border-[#222222] opacity-75 hover:opacity-100 z-10"
                    }`}
                  >
                    {/* Active Top Spotlight Glowing Bar */}
                    {isActive && (
                      <motion.div
                        layoutId="howItWorksActiveIndicator"
                        className="absolute top-0 left-0 right-0 h-[2px] bg-[#0055FF] shadow-[0_0_10px_#0055FF]"
                      />
                    )}

                    {/* Top Section: Serial + Badge + Description */}
                    <div>
                      <div className="flex items-center justify-between">
                        <span
                          className={`font-mono text-xs font-semibold block transition-none ${
                            isActive ? "text-[#0055FF]" : "text-[#71717a]"
                          }`}
                        >
                          {step.serial}
                        </span>
                        <span
                          className={`text-[9px] font-mono px-1.5 py-0.5 uppercase tracking-wider transition-none ${
                            isActive
                              ? "bg-[#0055FF]/15 text-[#0055FF] border border-[#0055FF]/40 font-bold"
                              : "bg-[#111111] text-[#555555] border border-[#222222]"
                          }`}
                        >
                          {step.badge}
                        </span>
                      </div>

                      <p
                        className={`mt-6 text-xs sm:text-sm font-sans leading-relaxed min-h-[48px] transition-none ${
                          isActive ? "text-white" : "text-[#888888]"
                        }`}
                      >
                        {step.desc}
                      </p>
                    </div>

                    {/* Middle Cumulative Blue Progress Rail */}
                    <div className="my-6 relative">
                      <div className="w-full h-1.5 bg-[#141418] relative overflow-hidden border border-[#222222]">
                        <div
                          className="h-full bg-[#0055FF] transition-all duration-150 ease-out relative"
                          style={{ width: `${fillWidth}%` }}
                        >
                          {/* Trailing glow node at leading edge of fill */}
                          {fillWidth > 0 && fillWidth < 100 && (
                            <div className="absolute right-0 top-0 bottom-0 w-1 bg-white shadow-[0_0_6px_#FFFFFF]" />
                          )}
                        </div>
                      </div>
                      {/* Dotted indicator pattern below bar */}
                      <div className="w-full h-1 mt-1 opacity-25 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:4px_4px]" />
                    </div>

                    {/* Bottom Section: Title + Graphic */}
                    <div className="flex items-end justify-between pt-2">
                      <div className="flex flex-col">
                        <span className="text-[10px] font-mono text-[#555555] uppercase">
                          PHASE 0{idx + 1}
                        </span>
                        <h3
                          className={`text-lg sm:text-xl font-medium font-sans transition-none ${
                            isActive ? "text-[#0055FF] font-semibold" : "text-[#888888]"
                          }`}
                        >
                          {step.title}
                        </h3>
                      </div>
                      <div className="shrink-0 pl-2">
                        {step.renderIcon(isActive)}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
