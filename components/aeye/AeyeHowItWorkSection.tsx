"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";

export default function AeyeHowItWorkSection() {
  const [activeStep, setActiveStep] = useState(0);

  const steps = [
    {
      serial: "// 001",
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
            stroke={isActive ? "#0055FF" : "#555555"}
            strokeWidth="1.5"
          />
          <path
            d="M32 20L54 32V40L32 52L10 40V32L32 20Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#555555"}
            strokeWidth="1.5"
          />
          <path
            d="M32 34L54 46V54L32 66L10 54V46L32 34Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#555555"}
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
            stroke={isActive ? "#0055FF" : "#555555"}
            strokeWidth="1.5"
          />
          <path
            d="M32 20L44 27V37L32 44L20 37V27L32 20Z"
            fill={isActive ? "#0033AA" : "#000000"}
            stroke={isActive ? "#FFFFFF" : "#444444"}
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
                stroke={isActive ? "#FFFFFF" : "#555555"}
                strokeWidth="1.2"
              />
              <path
                d={`M${pt.cx - 6} ${pt.cy}V${pt.cy + 5}C${pt.cx - 6} ${pt.cy + 7} ${pt.cx + 6} ${pt.cy + 7} ${pt.cx + 6} ${pt.cy + 5}V${pt.cy}`}
                fill={isActive ? "#0044DD" : "#111111"}
                stroke={isActive ? "#0055FF" : "#555555"}
                strokeWidth="1.2"
              />
            </g>
          ))}
        </svg>
      ),
    },
    {
      serial: "// 004",
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
            stroke={isActive ? "#FFFFFF" : "#555555"}
            strokeWidth="1.5"
          />
          <path
            d="M48 28L54 44L44 48L40 34L48 28Z"
            fill={isActive ? "#0044DD" : "#111111"}
            stroke={isActive ? "#0055FF" : "#555555"}
            strokeWidth="1.5"
          />
          <path
            d="M32 54L16 46V36L32 44V54Z"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#FFFFFF" : "#555555"}
            strokeWidth="1.5"
          />
          <path
            d="M16 36L10 20L20 16L24 30L16 36Z"
            fill={isActive ? "#0044DD" : "#111111"}
            stroke={isActive ? "#0055FF" : "#555555"}
            strokeWidth="1.5"
          />
        </svg>
      ),
    },
  ];

  return (
    <section id="how-it-works" className="relative w-full border-b border-[#222222] bg-[#000000]">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[N.04/11]</span>
            <span className="text-[#888888]">— &gt;</span>
            <span className="text-[#888888] uppercase">HOW IT WORK</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            WORKFLOW ORCHESTRATION &amp; EXECUTION
          </div>
        </div>

        {/* Section Title & Subtitle + Action Button */}
        <div className="pt-10 pb-14 flex flex-col md:flex-row md:items-end justify-between gap-6">
          <div>
            <h2 className="text-3xl sm:text-5xl lg:text-[54px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
              Understand the flow.
              <span className="block text-[#888888]">See how it all connects.</span>
            </h2>
          </div>
          <Link
            href="#pricing"
            className="inline-flex items-center gap-2.5 px-4 py-2.5 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none shrink-0"
          >
            <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
            GET STARTED
          </Link>
        </div>

        {/* 4 Connected Process Columns matching Frame 005 / 012 */}
        <div className="border border-[#222222] divide-y lg:divide-y-0 lg:divide-x divide-[#222222] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 bg-[#000000]">
          {steps.map((step, idx) => {
            const isActive = activeStep === idx;
            return (
              <div
                key={idx}
                onClick={() => setActiveStep(idx)}
                onMouseEnter={() => setActiveStep(idx)}
                className={`p-6 sm:p-7 flex flex-col justify-between min-h-[360px] cursor-pointer transition-none ${
                  isActive ? "bg-[#08080a]" : "bg-[#000000] hover:bg-[#0a0a0c]"
                }`}
              >
                {/* Top Section: Serial + Description */}
                <div>
                  <span className="font-mono text-xs text-[#888888] font-medium block">
                    {step.serial}
                  </span>
                  <p className="mt-8 text-xs sm:text-sm text-[#aaaaaa] font-sans leading-relaxed min-h-[48px]">
                    {step.desc}
                  </p>
                </div>

                {/* Middle Progress Rail */}
                <div className="my-8 relative">
                  <div className="w-full h-1 bg-[#1a1a1e] relative overflow-hidden">
                    {isActive && (
                      <motion.div
                        layoutId="activeHowItWorkRail"
                        initial={{ width: "20%" }}
                        animate={{ width: "100%" }}
                        transition={{ duration: 0.4 }}
                        className="h-full bg-[#0055FF]"
                      />
                    )}
                  </div>
                  {/* Dotted indicator background pattern */}
                  <div className="w-full h-1.5 mt-1 opacity-20 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:4px_4px]" />
                </div>

                {/* Bottom Section: Title + Graphic */}
                <div className="flex items-end justify-between">
                  <h3
                    className={`text-xl font-medium font-sans transition-none ${
                      isActive ? "text-[#0055FF]" : "text-[#777777]"
                    }`}
                  >
                    {step.title}
                  </h3>
                  <div className="shrink-0 pl-2">
                    {step.renderIcon(isActive)}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
