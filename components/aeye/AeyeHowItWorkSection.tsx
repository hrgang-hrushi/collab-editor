"use client";

import React, { useState, useRef } from "react";
import { motion, useScroll, useSpring, useTransform, useMotionValueEvent, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { Terminal, Cpu, Zap, Activity, ArrowRight, ShieldCheck, CheckCircle2 } from "lucide-react";

export default function AeyeHowItWorkSection() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [activeStep, setActiveStep] = useState(0);
  const isManualClickRef = useRef(false);
  const manualTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Smooth scroll interpolation using spring physics for butter-smooth response
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end end"],
  });

  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 140,
    damping: 26,
    mass: 0.2,
  });

  // Dedicated direct GPU-composited MotionValues for each cumulative progress bar
  const fill0 = useTransform(smoothProgress, [0.02, 0.25], ["0%", "100%"]);
  const fill1 = useTransform(smoothProgress, [0.25, 0.50], ["0%", "100%"]);
  const fill2 = useTransform(smoothProgress, [0.50, 0.75], ["0%", "100%"]);
  const fill3 = useTransform(smoothProgress, [0.75, 0.98], ["0%", "100%"]);
  const fills = [fill0, fill1, fill2, fill3];

  // Update activeStep ONLY when thresholding across steps (zero scroll micro-lag)
  useMotionValueEvent(smoothProgress, "change", (latest) => {
    if (isManualClickRef.current) return;
    let next = 0;
    if (latest >= 0.75) next = 3;
    else if (latest >= 0.50) next = 2;
    else if (latest >= 0.25) next = 1;
    setActiveStep((prev) => (prev !== next ? next : prev));
  });

  const handleStepClick = (idx: number) => {
    setActiveStep(idx);
    if (containerRef.current && typeof window !== "undefined") {
      if (window.innerWidth >= 1024) {
        isManualClickRef.current = true;
        if (manualTimeoutRef.current) clearTimeout(manualTimeoutRef.current);
        manualTimeoutRef.current = setTimeout(() => {
          isManualClickRef.current = false;
        }, 750);

        const rect = containerRef.current.getBoundingClientRect();
        const scrollTop = window.scrollY || document.documentElement.scrollTop;
        const containerTop = rect.top + scrollTop;
        const scrollableDistance = containerRef.current.offsetHeight - window.innerHeight;

        if (scrollableDistance > 0) {
          const targets = [0.05, 0.35, 0.65, 0.95];
          window.scrollTo({
            top: containerTop + targets[idx] * scrollableDistance,
            behavior: "smooth",
          });
        }
      }
    }
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
          className="w-14 h-14 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Isometric Data Rack */}
          <path
            d="M32 8L52 19V26L32 37L12 26V19L32 8Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#333333"}
            strokeWidth="1.5"
          />
          <path
            d="M32 21L52 32V39L32 50L12 39V32L32 21Z"
            fill={isActive ? "#0044DD" : "#0d0d10"}
            stroke={isActive ? "#0055FF" : "#333333"}
            strokeWidth="1.5"
          />
          <path
            d="M32 34L52 45V52L32 63L12 52V45L32 34Z"
            fill={isActive ? "#0033AA" : "#08080a"}
            stroke={isActive ? "#0055FF" : "#333333"}
            strokeWidth="1.5"
          />
          {isActive && (
            <>
              <circle cx="20" cy="24" r="1.5" fill="#FFFFFF" />
              <circle cx="20" cy="37" r="1.5" fill="#FFFFFF" />
              <circle cx="20" cy="50" r="1.5" fill="#FFFFFF" />
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
          className="w-14 h-14 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Isometric Chip / Processor */}
          <path
            d="M32 12L52 24V40L32 52L12 40V24L32 12Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#333333"}
            strokeWidth="1.5"
          />
          <path
            d="M32 20L44 27V37L32 44L20 37V27L32 20Z"
            fill={isActive ? "#0033AA" : "#000000"}
            stroke={isActive ? "#FFFFFF" : "#222222"}
            strokeWidth="1"
          />
          {/* Pin Traces radiating */}
          <path
            d="M18 20L10 15M24 16L18 10M40 16L46 10M46 20L54 15M50 36L58 41M46 44L52 50M18 44L12 50M14 36L6 41"
            stroke={isActive ? "#0055FF" : "#333333"}
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
          className="w-14 h-14 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Hexagonal node cluster */}
          {[
            { cx: 32, cy: 18 },
            { cx: 20, cy: 28 },
            { cx: 44, cy: 28 },
            { cx: 20, cy: 44 },
            { cx: 44, cy: 44 },
            { cx: 32, cy: 54 },
          ].map((pt, i) => (
            <g key={i}>
              <ellipse
                cx={pt.cx}
                cy={pt.cy}
                rx="6"
                ry="3"
                fill={isActive ? "#0055FF" : "#111111"}
                stroke={isActive ? "#FFFFFF" : "#333333"}
                strokeWidth="1.2"
              />
              <path
                d={`M${pt.cx - 6} ${pt.cy}V${pt.cy + 4}C${pt.cx - 6} ${pt.cy + 6} ${pt.cx + 6} ${pt.cy + 6} ${pt.cx + 6} ${pt.cy + 4}V${pt.cy}`}
                fill={isActive ? "#0044DD" : "#111111"}
                stroke={isActive ? "#0055FF" : "#333333"}
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
          className="w-14 h-14 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Interlocking geometric bracket angles */}
          <path
            d="M32 10L48 18V28L32 20V10Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#FFFFFF" : "#333333"}
            strokeWidth="1.5"
          />
          <path
            d="M48 28L54 44L44 48L40 34L48 28Z"
            fill={isActive ? "#0044DD" : "#0d0d10"}
            stroke={isActive ? "#0055FF" : "#333333"}
            strokeWidth="1.5"
          />
          <path
            d="M32 54L16 46V36L32 44V54Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#FFFFFF" : "#333333"}
            strokeWidth="1.5"
          />
          <path
            d="M16 36L10 20L20 16L24 30L16 36Z"
            fill={isActive ? "#0044DD" : "#0d0d10"}
            stroke={isActive ? "#0055FF" : "#333333"}
            strokeWidth="1.5"
          />
        </svg>
      ),
    },
  ];

  return (
    <section id="how-it-works" className="relative w-full border-b border-[#222222] bg-[#000000]">
      {/* Scroll-driven Sticky Container with calibrated 220vh distance for buttery smooth traversal */}
      <div ref={containerRef} className="relative lg:h-[220vh]">
        <div className="relative lg:sticky lg:top-0 lg:h-screen lg:flex lg:flex-col lg:justify-center overflow-visible lg:overflow-hidden py-12 lg:py-0">
          <div className="max-w-[1280px] w-full mx-auto px-6">
            {/* Section Header Meta with Live Step Tracking */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#222222] text-xs font-mono">
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
                      className={`h-1.5 transition-none rounded-none ${
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
            <div className="pt-6 pb-8 flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <h2 className="text-2xl sm:text-4xl lg:text-[42px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
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
                  className="inline-flex items-center gap-2 px-3.5 py-2 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none"
                >
                  <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                  GET STARTED
                </Link>
              </div>
            </div>

            {/* 4 Connected Process Columns with Hardware Brutalist Dividers */}
            <div className="border border-[#222222] divide-y lg:divide-y-0 lg:divide-x divide-[#222222] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 bg-[#000000] relative">
              {steps.map((step, idx) => {
                const isActive = activeStep === idx;
                const fillMotionValue = fills[idx];

                return (
                  <div
                    key={idx}
                    onClick={() => handleStepClick(idx)}
                    className={`relative p-5 sm:p-6 flex flex-col justify-between min-h-[300px] sm:min-h-[320px] cursor-pointer transition-none select-none ${
                      isActive ? "bg-[#0b0c10]" : "bg-[#000000] hover:bg-[#070709]"
                    }`}
                  >
                    {/* Active Spotlight Top Indicator Accent */}
                    {isActive && (
                      <div className="absolute top-0 left-0 right-0 h-[2px] bg-[#0055FF]" />
                    )}

                    {/* Top Section: Serial + Badge */}
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
                              ? "bg-[#0055FF] text-white font-bold"
                              : "bg-[#111111] text-[#555555] border border-[#222222]"
                          }`}
                        >
                          {step.badge}
                        </span>
                      </div>

                      <p
                        className={`mt-5 text-xs sm:text-sm font-sans leading-relaxed min-h-[44px] transition-none ${
                          isActive ? "text-white" : "text-[#777777]"
                        }`}
                      >
                        {step.desc}
                      </p>
                    </div>

                    {/* Middle Cumulative Blue Progress Rail (GPU-accelerated, zero stutter) */}
                    <div className="my-5 relative">
                      <div className="w-full h-1 bg-[#141418] relative overflow-hidden">
                        <motion.div
                          className="h-full bg-[#0055FF]"
                          style={{ width: fillMotionValue }}
                        />
                      </div>
                      {/* Dotted indicator pattern below bar */}
                      <div className="w-full h-1 mt-1 opacity-20 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:4px_4px]" />
                    </div>

                    {/* Bottom Section: Title + Graphic */}
                    <div className="flex items-end justify-between pt-1">
                      <div className="flex flex-col">
                        <span className="text-[9px] font-mono text-[#555555] uppercase">
                          PHASE 0{idx + 1}
                        </span>
                        <h3
                          className={`text-lg font-medium font-sans transition-none ${
                            isActive ? "text-white font-semibold" : "text-[#666666]"
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
