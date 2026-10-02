"use client";

import React, { useState, useRef } from "react";
import { motion, AnimatePresence, useScroll, useSpring, useTransform, useMotionValueEvent } from "framer-motion";
import Link from "next/link";

export default function AeyeInstallationSection() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState<"multiplayer" | "silicon" | "crdt" | "agent">("multiplayer");
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

  // Continuous vertical rail fill height (0% to 100%)
  const verticalRailHeight = useTransform(smoothProgress, [0.06, 0.94], ["0%", "100%"]);

  // Update activeTab ONLY when thresholding across sections (prevents re-render lag)
  useMotionValueEvent(smoothProgress, "change", (latest) => {
    if (isManualClickRef.current) return;
    if (latest < 0.25) {
      setActiveTab((prev) => (prev !== "multiplayer" ? "multiplayer" : prev));
    } else if (latest < 0.50) {
      setActiveTab((prev) => (prev !== "silicon" ? "silicon" : prev));
    } else if (latest < 0.75) {
      setActiveTab((prev) => (prev !== "crdt" ? "crdt" : prev));
    } else {
      setActiveTab((prev) => (prev !== "agent" ? "agent" : prev));
    }
  });

  const tabs = [
    {
      id: "multiplayer" as const,
      serial: "// 001",
      label: "Real-Time Collaboration",
      subtitle: "SHARED EDITING",
      desc: "Edit shared files with teammates and see their cursors in the workspace.",
      copyText: "Crux collaboration:\n- Open a shared workspace\n- Edit files together\n- See teammate cursors and selections",
    },
    {
      id: "silicon" as const,
      serial: "// 002",
      label: "Spatial Code Canvas",
      subtitle: "PROJECT CONTEXT",
      desc: "Arrange multiple files on one canvas to follow the connections across your codebase.",
      copyText: "Crux spatial canvas:\n- Open multiple files\n- Place related code side by side\n- Keep project context in view",
    },
    {
      id: "crdt" as const,
      serial: "// 003",
      label: "Shared Text Editing",
      subtitle: "LIVE UPDATES",
      desc: "See shared changes as collaborators edit the same project.",
      copyText: "Shared editing:\n- Work in the same file\n- Follow live changes\n- Coordinate through cursor presence",
    },
    {
      id: "agent" as const,
      serial: "// 004",
      label: "Integrated Development Tools",
      subtitle: "EDITOR AND TERMINAL",
      desc: "Keep the terminal beside your code to run commands and inspect output.",
      copyText: "Crux tools:\n- Edit code\n- Run terminal commands\n- Review output in the workspace",
    },
  ];

  const activeIndex = tabs.findIndex((t) => t.id === activeTab);
  const currentTab = tabs[activeIndex] || tabs[0];

  const handleStepClick = (idx: number) => {
    const selected = tabs[idx];
    if (!selected) return;
    setActiveTab(selected.id);

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
          const targets = [0.05, 0.32, 0.62, 0.92];
          window.scrollTo({
            top: containerTop + targets[idx] * scrollableDistance,
            behavior: "smooth",
          });
        }
      }
    }
  };

  return (
    <section id="why-crux" className="relative w-full border-b border-[#222222] bg-[#000000]">
      {/* Anchor for backwards compatibility */}
      <div id="installation" className="absolute -top-20" />

      {/* Scroll-driven Sticky Container matching Feature & How-It-Works sections */}
      <div ref={containerRef} className="relative lg:h-[260vh]">
        <div className="relative lg:sticky lg:top-0 lg:h-screen lg:flex lg:flex-col lg:justify-center overflow-visible lg:overflow-hidden py-12 lg:py-0">
          <div className="max-w-[1280px] w-full mx-auto px-6">
            {/* Section Header Meta with Live Step Tracking */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#222222] text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="text-[#0055FF] font-bold">[N.05/11]</span>
                <span className="text-[#888888]">— &gt;</span>
                <span className="text-[#888888] uppercase">WHY CRUX?</span>
              </div>
              <div className="flex items-center gap-3 pt-2 sm:pt-0">
                <span className="text-[10px] text-[#71717a] uppercase tracking-wider hidden sm:inline font-mono">
                  ONE CONNECTED WORKSPACE
                </span>
                <div className="flex items-center gap-1.5">
                  {tabs.map((tab, idx) => (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => handleStepClick(idx)}
                      className={`h-1.5 transition-none rounded-none ${
                        activeTab === tab.id ? "w-7 bg-[#0055FF]" : "w-2.5 bg-[#222222] hover:bg-[#444444]"
                      }`}
                      aria-label={`Jump to ${tab.label}`}
                    />
                  ))}
                </div>
                <span className="text-xs font-mono text-[#0055FF] font-bold">
                  [ 0{activeIndex + 1} / 04 ]
                </span>
              </div>
            </div>

            {/* 2-Column Section Layout */}
            <div className="pt-8 sm:pt-10 grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 xl:gap-16 items-center">
              {/* Left Column: Fixed-Height Interactive Engineering Display (Zero Height Jumping) */}
              <div className="lg:col-span-7">
                <div className="relative p-5 sm:p-6 border border-[#222222] bg-[#050507]">
                  {/* Corner Double-Dot Accents */}
                  <div className="absolute top-2 left-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>
                  <div className="absolute top-2 right-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>
                  <div className="absolute bottom-2 left-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>
                  <div className="absolute bottom-2 right-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>

                  {/* Authentic 110% Real Crux IDE Workbench with Amoeba Spotlight */}
                  <div className="border border-[#222222] bg-[#000000] rounded-none overflow-visible h-[490px] sm:h-[510px] flex flex-col justify-between relative">
                    <AnimatePresence mode="wait">
                      <motion.div
                        key={`tab-${activeTab}`}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.15 }}
                        className="h-full w-full select-none relative overflow-visible"
                      >
                        <img loading="lazy" decoding="async" src="/email/canvas-preview.png" alt="Crux IDE workspace with a spatial canvas and code editor" width="3840" height="2400" className="w-full h-full object-contain" />
                      </motion.div>
                    </AnimatePresence>
                  </div>
                </div>
              </div>

              {/* Right Column: Title, Action Button, and Clean Continuous Vertical Rail */}
              <div className="lg:col-span-5 flex flex-col justify-between py-2">
                <div>
                  <h2 className="text-3xl sm:text-4xl lg:text-[44px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
                    Why Crux?
                    <span className="block text-[#888888]">Designed for shared coding.</span>
                  </h2>

                  <div className="mt-6 flex items-center gap-4">
                    <Link
                      href="#pricing"
                      className="inline-flex items-center gap-2.5 px-4 py-2.5 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none"
                    >
                      <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                      GET STARTED
                    </Link>
                    <div className="text-[11px] font-mono text-[#71717a] hidden sm:flex items-center gap-2">
                      <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                      <span>SCROLL TO ADVANCE // 0{activeIndex + 1} OF 04</span>
                    </div>
                  </div>
                </div>

                {/* Continuous Vertical Timeline Rail exactly as before with clean bounds */}
                <div className="mt-10 sm:mt-12 relative pl-8 select-none">
                  {/* Background Track Rail */}
                  <div className="absolute left-[8px] top-3 bottom-5 w-[2px] bg-[#1a1a1e]" />

                  {/* Continuous Smooth Electric Blue Fill */}
                  <div className="absolute left-[8px] top-3 bottom-5 w-[2px] overflow-hidden">
                    <motion.div
                      className="w-full bg-[#0055FF]"
                      style={{ height: verticalRailHeight }}
                    />
                  </div>

                  <div className="space-y-7 sm:space-y-8">
                    {tabs.map((tab, idx) => {
                      const isActive = activeTab === tab.id;

                      return (
                        <div
                          key={tab.id}
                          onClick={() => handleStepClick(idx)}
                          className="relative cursor-pointer group transition-none"
                        >
                          {/* Active Indicator Square Node sitting directly on the vertical line */}
                          <div
                            className={`absolute -left-[28px] top-1.5 w-2.5 h-2.5 transition-none z-10 ${
                              isActive
                                ? "bg-[#0055FF] border border-white shadow-[0_0_8px_#0055FF]"
                                : "bg-[#222222] border border-[#333333] group-hover:bg-[#444444]"
                            }`}
                          />

                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] font-mono font-semibold transition-none ${
                                isActive ? "text-[#0055FF]" : "text-[#555555]"
                              }`}
                            >
                              {tab.serial}
                            </span>
                            <h3
                              className={`text-lg sm:text-xl font-medium font-sans transition-none ${
                                isActive ? "text-[#0055FF] font-semibold" : "text-[#71717a] group-hover:text-white"
                              }`}
                            >
                              {tab.label}
                            </h3>
                          </div>

                          <p
                            className={`mt-1.5 text-xs sm:text-sm font-sans leading-relaxed transition-none ${
                              isActive ? "text-white" : "text-[#666666] group-hover:text-[#888888]"
                            }`}
                          >
                            {tab.desc}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
