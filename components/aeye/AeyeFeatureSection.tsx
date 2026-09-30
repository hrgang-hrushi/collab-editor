"use client";

import React, { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence, useScroll, useMotionValueEvent } from "framer-motion";
import RecordedIdePreview from "./RecordedIdePreview";

// Calculate the (x, y) coordinates of the square dot as it travels along the rectangle perimeter
function getPerimeterPoint(p: number, w: number, h: number) {
  if (w <= 0 || h <= 0) return { x: 0, y: 0 };
  const P = 2 * (w + h);
  const d = Math.max(0, Math.min(1, p)) * P;

  // Perimeter path starting top-left (0,0):
  // 1. Down the left edge: (0,0) -> (0, h)
  // 2. Across the bottom edge: (0, h) -> (w, h)
  // 3. Up the right edge: (w, h) -> (w, 0)
  // 4. Across the top edge: (w, 0) -> (0, 0)
  if (d <= h) {
    return { x: 0, y: d };
  } else if (d <= h + w) {
    return { x: d - h, y: h };
  } else if (d <= 2 * h + w) {
    return { x: w, y: h - (d - (h + w)) };
  } else {
    return { x: w - (d - (2 * h + w)), y: 0 };
  }
}

export default function AeyeFeatureSection() {
  const [activeTab, setActiveTab] = useState<number>(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const isManualClickRef = useRef(false);
  const manualTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const [rectSize, setRectSize] = useState({ width: 0, height: 0 });
  const [dotPos, setDotPos] = useState({ x: 0, y: 0 });

  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end end"],
  });

  // Track size of the main split architecture card
  useEffect(() => {
    if (!cardRef.current) return;
    const updateSize = () => {
      if (cardRef.current) {
        setRectSize({
          width: cardRef.current.offsetWidth,
          height: cardRef.current.offsetHeight,
        });
      }
    };
    updateSize();
    const ro = new ResizeObserver(updateSize);
    ro.observe(cardRef.current);
    window.addEventListener("resize", updateSize);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", updateSize);
    };
  }, []);

  // Update scroll progression and traveling dot position
  useMotionValueEvent(scrollYProgress, "change", (latest) => {
    if (rectSize.width > 0 && rectSize.height > 0) {
      setDotPos(getPerimeterPoint(latest, rectSize.width, rectSize.height));
    }
    if (isManualClickRef.current) return;
    if (latest < 0.35) {
      setActiveTab(0);
    } else if (latest < 0.70) {
      setActiveTab(1);
    } else {
      setActiveTab(2);
    }
  });

  // Sync initial dot position once rectSize is measured
  useEffect(() => {
    if (rectSize.width > 0 && rectSize.height > 0) {
      const current = scrollYProgress.get();
      setDotPos(getPerimeterPoint(current, rectSize.width, rectSize.height));
    }
  }, [rectSize, scrollYProgress]);

  const handleTabClick = (idx: number) => {
    setActiveTab(idx);
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
          const targetProgress = idx === 0 ? 0.05 : idx === 1 ? 0.50 : 0.92;
          window.scrollTo({
            top: containerTop + targetProgress * scrollableDistance,
            behavior: "smooth",
          });
        }
      }
    }
  };

  const tabs = [
    {
      serial: "// 001",
      badges: ["DATA", "SIGNALS"],
      title: "Context Awareness",
      systemTitle: "Bare-Metal Silicon Runtime",
      desc: "Ingests raw filesystem buffers, keystrokes, and AST tokens — streaming deterministic signals directly into the native host kernel.",
      systemDesc: "Rust native kernel executing directly on host hardware with WebGPU acceleration and zero Chromium/V8 overhead.",
    },
    {
      serial: "// 002",
      badges: ["ACTIONABLE", "LOGIC"],
      title: "Intelligent Processing",
      systemTitle: "Decentralized AST-CRDT Sync",
      desc: "Synthesizes real-time code transformations, concurrent edits, and agentic refactors into conflict-free structural AST operations.",
      systemDesc: "Conflict-free real-time syntax tree replication over encrypted P2P WebRTC channels with sub-10ms peer convergence.",
    },
    {
      serial: "// 003",
      badges: ["RESULTS", "STRUCTURE"],
      title: "Actionable Output",
      systemTitle: "Autonomous @CruxAI Kernel",
      desc: "Compiles verified native machine binaries, generates atomic git diffs, and streams hardware-accelerated buffers ready for deployment.",
      systemDesc: "Terminal agent executing multi-file refactors, background compiler passes, and atomic git diffs inside an isolated OS namespace.",
    },
  ];

  const bottomFeatures = [
    {
      title: "Hardware Brutalist DOM Engine",
      desc: "0px border radius, 1px dividers, sub-15ms input-to-photon latency, and zero V8 garbage collection pauses.",
    },
    {
      title: "Lock-Free Shared Memory Ring Buffer",
      desc: "64-bit atomic vector clock with 0.08ms local IPC sync latency across editor and agent threads.",
    },
    {
      title: "100% Air-Gapped Zero Telemetry",
      desc: "Zero cloud telemetry dependencies with complete local filesystem residency and private alpha self-hosting.",
    },
  ];

  return (
    <section id="features" className="relative w-full border-b border-[#222222] bg-[#000000]">
      {/* Sticky Scroll Container for 3 Capability Layers */}
      <div ref={containerRef} className="relative lg:h-[300vh]">
        <div className="relative lg:sticky lg:top-0 lg:h-screen lg:flex lg:flex-col lg:justify-center overflow-visible lg:overflow-hidden py-16 lg:py-0">
          <div className="max-w-[1280px] w-full mx-auto px-6">
            {/* Section Header Meta */}
            <div className="flex items-center justify-between pb-6 text-xs font-mono">
              <div className="flex items-center gap-3">
                <span className="text-[#0055FF] font-semibold tracking-wider">[N.03/11]</span>
                <span className="w-8 h-[1px] bg-[#222222]" />
                <span className="text-[#0055FF] font-bold">&gt;</span>
                <span className="text-[#888888] uppercase tracking-wider font-semibold">CORE CAPABILITIES</span>
              </div>

              {/* Live Layer Scroll Indicator */}
              <div className="flex items-center gap-3">
                <span className="text-[10px] text-[#71717a] uppercase tracking-wider hidden sm:inline font-mono">
                  LAYER PROGRESS
                </span>
                <div className="flex items-center gap-1.5">
                  {[0, 1, 2].map((step) => (
                    <button
                      key={step}
                      type="button"
                      onClick={() => handleTabClick(step)}
                      className={`h-1.5 transition-all duration-300 rounded-none ${
                        activeTab === step ? "w-8 bg-[#0055FF]" : "w-3 bg-[#222222] hover:bg-[#444444]"
                      }`}
                      aria-label={`Go to Layer 0${step + 1}`}
                    />
                  ))}
                </div>
                <span className="text-xs font-mono text-[#0055FF] font-bold ml-1">
                  [ 0{activeTab + 1} / 03 ]
                </span>
              </div>
            </div>

            {/* Main Split Architecture with Traveling Dot & Blue Tail Outline */}
            <div
              ref={cardRef}
              className="relative grid grid-cols-1 lg:grid-cols-12 border border-[#222222] bg-[#000000]"
            >
              {/* Traveling Square Dot with Blue Tail turning the Gray Outline to Blue */}
              {rectSize.width > 0 && rectSize.height > 0 && (
                <>
                  <svg className="absolute inset-0 w-full h-full pointer-events-none z-20 overflow-visible">
                    <motion.path
                      d={`M 0 0 L 0 ${rectSize.height} L ${rectSize.width} ${rectSize.height} L ${rectSize.width} 0 Z`}
                      stroke="#0055FF"
                      strokeWidth={2}
                      fill="none"
                      style={{
                        pathLength: scrollYProgress,
                      }}
                    />
                  </svg>
                  {/* Square Dot at the leading tip of the blue tail */}
                  <div
                    className="absolute w-2.5 h-2.5 bg-[#0055FF] border border-white z-30 pointer-events-none shadow-[0_0_10px_#0055FF]"
                    style={{
                      left: `${dotPos.x}px`,
                      top: `${dotPos.y}px`,
                      transform: "translate(-50%, -50%)",
                    }}
                  />
                </>
              )}

              {/* Left Column: 3 Interactive Capability Tabs + Bottom Headline */}
              <div className="lg:col-span-5 p-6 sm:p-8 lg:p-10 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-[#222222] bg-[#000000] relative z-10">
                {/* Top Interactive Tabs List */}
                <div className="space-y-6 lg:space-y-7">
                  {tabs.map((tab, idx) => {
                    const isActive = activeTab === idx;
                    return (
                      <div
                        key={idx}
                        onClick={() => handleTabClick(idx)}
                        className="cursor-pointer group select-none transition-none"
                      >
                        {/* Badge Row */}
                        <div className="flex items-center gap-2 mb-2.5">
                          {tab.badges.map((b, bidx) => (
                            <span
                              key={bidx}
                              className={`px-2 py-0.5 text-[9px] font-mono uppercase font-bold tracking-wider rounded-none transition-none ${
                                isActive
                                  ? "bg-[#0055FF] text-white font-bold"
                                  : "bg-[#111111] text-[#71717a] border border-[#222222]"
                              }`}
                            >
                              {b}
                            </span>
                          ))}
                        </div>

                        {/* Title with Dotted Leader Line to Serial */}
                        <div className="flex items-center justify-between gap-3 text-lg sm:text-xl font-medium font-sans">
                          <div className="flex items-center gap-2.5">
                            <span
                              className={`w-2 h-2 rounded-none transition-none ${
                                isActive ? "bg-[#0055FF]" : "bg-transparent border border-[#333333]"
                              }`}
                            />
                            <span className={isActive ? "text-[#0055FF] font-semibold" : "text-[#71717a] group-hover:text-white"}>
                              {tab.title}
                            </span>
                          </div>
                          <div className="flex-1 border-b border-dotted border-[#222222] mx-2 hidden sm:block" />
                          <span className="text-xs font-mono text-[#0055FF] font-bold flex-shrink-0">
                            {tab.serial}
                          </span>
                        </div>

                        {/* Description revealed on active */}
                        <AnimatePresence>
                          {isActive && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.2 }}
                              className="overflow-hidden"
                            >
                              <p className="mt-3 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed pl-4.5 border-l border-white">
                                {tab.desc}
                              </p>
                              <div className="mt-2 text-[10px] font-mono text-white pl-4.5 uppercase">
                                // CRUX SYSTEM: {tab.systemTitle}
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    );
                  })}
                </div>

                {/* Bottom Section Title */}
                <div className="pt-8 mt-8 border-t border-[#222222]">
                  <h2 className="text-2xl sm:text-3xl lg:text-[38px] font-normal tracking-[-0.05em] text-white font-sans leading-[1.1]">
                    Three core layers.<br />
                    <span className="text-[#888888]">One seamless system.</span>
                  </h2>
                  <div className="mt-4 flex items-center gap-2 text-[10px] font-mono text-[#71717a] tracking-wider uppercase">
                    <span className="w-2 h-2 rounded-none bg-[#0055FF] animate-pulse" />
                    <span>SCROLL TO ADVANCE // LAYER 0{activeTab + 1} OF 03</span>
                  </div>
                </div>
              </div>

              {/* Right Column: footage recorded from the Crux IDE */}
              <div className="lg:col-span-7 p-4 sm:p-6 lg:p-8 flex items-center justify-center bg-[#050507] overflow-hidden">
                <div className="w-full max-w-[600px] aspect-video border border-[#222222] bg-[#000000] rounded-none overflow-hidden flex flex-col justify-between">
                  <AnimatePresence mode="wait">
                    <motion.div
                      key={`feature-tab-${activeTab}`}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.15 }}
                      className="h-full w-full select-none relative"
                    >
                      <RecordedIdePreview shot={activeTab === 0 ? "editor" : activeTab === 1 ? "collaboration" : "ai"} />
                    </motion.div>
                  </AnimatePresence>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

  {/* 3 Secondary Capability Cards matching Video Recording */}
  <div className="max-w-[1280px] mx-auto px-6 py-12 lg:py-16 border-t border-[#222222]">
    <div className="grid grid-cols-1 md:grid-cols-3 border border-[#222222] divide-y md:divide-y-0 md:divide-x divide-[#222222] bg-[#000000]">
      {/* Card 1: Works with your workflow */}
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-20px" }}
        transition={{ duration: 0.4 }}
        className="p-8 sm:p-10 flex flex-col justify-between hover:bg-[#111111] transition-none rounded-none cursor-default group overflow-hidden min-h-[280px]"
      >
        <div>
          <h4 className="text-xl font-medium text-white font-sans">
            Works with your workflow
          </h4>
          <p className="mt-3 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
            Connect seamlessly with your existing tools, systems, and data sources.
          </p>
        </div>

        {/* 2-row Toolchain Infinite Scrolling Marquee */}
        <div
          className="mt-8 space-y-2.5 overflow-hidden relative select-none"
          style={{
            maskImage: "linear-gradient(to right, transparent, black 12%, black 88%, transparent)",
            WebkitMaskImage: "linear-gradient(to right, transparent, black 12%, black 88%, transparent)",
          }}
        >
          {/* Row 1: Leftward continuous scroll */}
          <motion.div
            animate={{ x: ["0%", "-50%"] }}
            transition={{ repeat: Infinity, ease: "linear", duration: 16 }}
            className="flex gap-2 w-max"
          >
            {["RUST", "GIT", "WEBGPU", "LLVM", "CLANG", "WEBRTC", "RUST", "GIT", "WEBGPU", "LLVM", "CLANG", "WEBRTC"].map((item, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2 px-3 py-1.5 border border-[#222222] bg-[#0a0a0c] text-white shrink-0 group-hover:border-[#333333]"
              >
                <div className="w-3.5 h-3.5 bg-white/20 flex items-center justify-center">
                  <div className="w-2 h-2 bg-white transform rotate-45" />
                </div>
                <span className="text-[11px] font-bold tracking-wider uppercase font-mono">
                  {item}
                </span>
              </div>
            ))}
          </motion.div>

          {/* Row 2: Rightward continuous scroll */}
          <motion.div
            animate={{ x: ["-50%", "0%"] }}
            transition={{ repeat: Infinity, ease: "linear", duration: 20 }}
            className="flex gap-2 w-max"
          >
            {["CARGO", "DOCKER", "NEOVIM", "RUST", "GIT", "ZSH", "CARGO", "DOCKER", "NEOVIM", "RUST", "GIT", "ZSH"].map((item, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2 px-3 py-1.5 border border-[#222222] bg-[#0a0a0c] text-white shrink-0 group-hover:border-[#333333]"
              >
                <div className="w-3.5 h-3.5 border border-[#0055FF]/40 bg-[#0055FF]/10 flex items-center justify-center">
                  <div className="w-1.5 h-1.5 bg-[#0055FF]" />
                </div>
                <span className="text-[11px] font-bold tracking-wider uppercase font-mono">
                  {item}
                </span>
              </div>
            ))}
          </motion.div>
        </div>
      </motion.div>

      {/* Card 2: Minimal by default */}
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-20px" }}
        transition={{ duration: 0.4, delay: 0.08 }}
        className="p-8 sm:p-10 flex flex-col justify-between hover:bg-[#111111] transition-none rounded-none cursor-default group min-h-[280px]"
      >
        <div>
          <h4 className="text-xl font-medium text-white font-sans">
            Minimal by default
          </h4>
          <p className="mt-3 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
            Focus only on what matters, no unnecessary complexity.
          </p>
        </div>

        {/* Minimal geometric square outline matching video */}
        <div className="flex justify-end pt-8">
          <div className="w-12 h-12 border-4 border-[#666666] group-hover:border-white transition-none" />
        </div>
      </motion.div>

      {/* Card 3: Built to scale */}
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-20px" }}
        transition={{ duration: 0.4, delay: 0.16 }}
        className="p-8 sm:p-10 flex flex-col justify-between hover:bg-[#111111] transition-none rounded-none cursor-default group min-h-[280px]"
      >
        <div>
          <h4 className="text-xl font-medium text-white font-sans">
            Built to scale
          </h4>
          <p className="mt-3 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
            Handle growing workflows, data, and outputs over time.
          </p>
        </div>

        {/* Overlapping stacked squares matching video */}
        <div className="flex justify-end pt-8">
          <div className="relative w-14 h-14">
            <div className="absolute top-0 left-0 w-10 h-10 border-4 border-[#555555] group-hover:border-[#888888] transition-none" />
            <div className="absolute bottom-0 right-0 w-10 h-10 border-4 border-[#888888] group-hover:border-white bg-[#000000] transition-none" />
          </div>
        </div>
      </motion.div>
    </div>
  </div>
</section>
  );
}
