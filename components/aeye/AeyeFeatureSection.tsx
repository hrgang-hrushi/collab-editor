"use client";

import React, { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence, useScroll, useMotionValueEvent } from "framer-motion";
import {
  FileText,
  AlignLeft,
  Command,
  Database,
  User,
  Crosshair,
  GitFork,
  Smile,
  BarChart3,
  Bell,
  ChevronDown,
  CheckCircle2,
  Lightbulb,
  Flag,
} from "lucide-react";

// 8-Point Asterisk Core Icon matching Frame 001, 008, 026
function AsteriskCoreIcon({ className = "w-6 h-6 text-white" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="square">
      <line x1="12" y1="2" x2="12" y2="22" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
      <line x1="19.07" y1="4.93" x2="4.93" y2="19.07" />
    </svg>
  );
}

// Diamond Alert Icon matching Frame 005 (< ! >)
function DiamondAlert({ className = "w-4 h-4 text-[#0055FF]" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 2L22 12L12 22L2 12Z" strokeDasharray="3 3" />
      <line x1="12" y1="8" x2="12" y2="13" strokeWidth="2.5" />
      <line x1="12" y1="17" x2="12.01" y2="17" strokeWidth="3" />
    </svg>
  );
}

// Sunflower / Asterisk Loader matching Frame 008
function SunflowerLoader({ className = "w-4 h-4 text-white" }: { className?: string }) {
  return (
    <motion.svg
      animate={{ rotate: 360 }}
      transition={{ repeat: Infinity, duration: 1.4, ease: "linear" }}
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
    >
      <line x1="12" y1="2" x2="12" y2="6" />
      <line x1="12" y1="18" x2="12" y2="22" />
      <line x1="4.93" y1="4.93" x2="7.76" y2="7.76" />
      <line x1="16.24" y1="16.24" x2="19.07" y2="19.07" />
      <line x1="2" y1="12" x2="6" y2="12" />
      <line x1="18" y1="12" x2="22" y2="12" />
      <line x1="4.93" y1="19.07" x2="7.76" y2="16.24" />
      <line x1="16.24" y1="7.76" x2="19.07" y2="4.93" />
    </motion.svg>
  );
}

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
      desc: "Understand inputs, context, and user intent — turning raw data into meaningful signals.",
      systemDesc: "Rust native kernel executing directly on host hardware with WebGPU acceleration and zero Chromium/V8 overhead.",
    },
    {
      serial: "// 002",
      badges: ["ACTIONABLE", "LOGIC"],
      title: "Intelligent Processing",
      systemTitle: "Decentralized AST-CRDT Sync",
      desc: "Apply AI to analyze, reason, and adapt dynamically across different workflows and use cases.",
      systemDesc: "Conflict-free real-time syntax tree replication over encrypted P2P WebRTC channels with sub-10ms peer convergence.",
    },
    {
      serial: "// 003",
      badges: ["RESULTS", "STRUCTURE"],
      title: "Actionable Output",
      systemTitle: "Autonomous @CruxAI Kernel",
      desc: "Generate structured, reliable outputs that can be used, refined, and integrated into real workflows.",
      systemDesc: "Terminal agent executing multi-file refactors, background compiler passes, and atomic git diffs inside an isolated OS namespace.",
    },
  ];

  const bottomFeatures = [
    {
      title: "Works with your workflow",
      desc: "Connect seamlessly with your existing tools, systems, and data sources. One-click VS Code settings and keybindings importer.",
    },
    {
      title: "Minimal by default",
      desc: "Focus only on what matters, no unnecessary complexity. Hardware brutalist design with 0px radius and zero drop shadows.",
    },
    {
      title: "Built to scale",
      desc: "Handle growing workflows, data, and outputs over time. Encrypted P2P multiplayer mesh engineered for massive 100K-line monorepos.",
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

              {/* Right Column: Visual Diagram Canvas Frame-to-Frame Clone */}
              <div className="lg:col-span-7 relative min-h-[460px] lg:min-h-[520px] p-6 sm:p-8 lg:p-10 flex items-center justify-center bg-[#000000] overflow-hidden">
                {/* Dot Matrix Canvas Texture */}
                <div className="absolute inset-0 aeye-dot-bg invert opacity-20 pointer-events-none" />

                {/* Interactive Canvas Content */}
                <div className="relative z-10 w-full max-w-[540px]">
                  <AnimatePresence mode="wait">
                    {activeTab === 0 && (
                      /* TAB 1: Context Awareness (RAW INPUTS -> BRACKETS -> CORE -> DOUBLE CABLE -> SIGNALS) */
                      <motion.div
                        key="tab-0"
                        initial={{ opacity: 0, scale: 0.96 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.96 }}
                        transition={{ duration: 0.25 }}
                        className="w-full flex flex-col items-center gap-6 relative"
                      >
                        {/* Upper Row: RAW INPUTS, BRACKET TRACES, CENTER ASTERISK CORE, CONTEXTS */}
                        <div className="w-full flex items-center justify-between gap-2 sm:gap-4 relative">
                          {/* Left: RAW INPUTS Box */}
                          <div className="w-36 sm:w-44 p-3 bg-[#0d0d0f] border border-[#222222] rounded-none z-10 shadow-md">
                            <div className="text-[10px] font-mono uppercase text-[#71717a] font-semibold pb-1.5 border-b border-[#222222] mb-2">
                              RAW INPUTS
                            </div>
                            <ul className="space-y-2 text-xs font-sans text-[#d4d4d8] list-none p-0 m-0">
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <FileText className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px]">Text</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <AlignLeft className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px]">Logs</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Command className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px]">User Actions</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Database className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px]">Metadata</span>
                              </li>
                              <li className="pt-0.5 text-[#555555] font-mono text-[10px] tracking-widest pl-1">
                                ...
                              </li>
                            </ul>
                          </div>

                          {/* Left Circuit Bracket Trace (RAW INPUTS to Center) */}
                          <div className="flex-1 h-24 relative flex items-center justify-center">
                            <svg className="w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 80 80">
                              <line x1="0" y1="40" x2="35" y2="40" stroke="#333333" strokeWidth="1" />
                              <line x1="35" y1="15" x2="35" y2="65" stroke="#333333" strokeWidth="1" />
                              <line x1="35" y1="15" x2="45" y2="15" stroke="#333333" strokeWidth="1" />
                              <line x1="35" y1="65" x2="45" y2="65" stroke="#333333" strokeWidth="1" />
                              <line x1="35" y1="40" x2="80" y2="40" stroke="#333333" strokeWidth="1" />
                            </svg>
                          </div>

                          {/* Center Core: Black Box with White 8-Point Asterisk */}
                          <div className="w-14 h-14 bg-[#0a0a0a] border border-[#222222] flex items-center justify-center relative flex-shrink-0 z-10 shadow-lg">
                            <AsteriskCoreIcon className="w-6 h-6 text-white" />
                          </div>

                          {/* Right Circuit Bracket Trace (Center to CONTEXTS) */}
                          <div className="flex-1 h-24 relative flex items-center justify-center">
                            <svg className="w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 80 80">
                              <line x1="0" y1="40" x2="45" y2="40" stroke="#333333" strokeWidth="1" />
                              <line x1="45" y1="15" x2="45" y2="65" stroke="#333333" strokeWidth="1" />
                              <line x1="35" y1="15" x2="45" y2="15" stroke="#333333" strokeWidth="1" />
                              <line x1="35" y1="65" x2="45" y2="65" stroke="#333333" strokeWidth="1" />
                              <line x1="45" y1="40" x2="80" y2="40" stroke="#333333" strokeWidth="1" />
                            </svg>
                          </div>

                          {/* Right: CONTEXTS Box */}
                          <div className="w-36 sm:w-44 p-3 bg-[#0d0d0f] border border-[#222222] rounded-none z-10 shadow-md">
                            <div className="text-[10px] font-mono uppercase text-[#71717a] font-semibold pb-1.5 border-b border-[#222222] mb-2">
                              CONTEXTS
                            </div>
                            <ul className="space-y-2 text-xs font-sans text-[#d4d4d8] list-none p-0 m-0">
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <User className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px]">Entities</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Crosshair className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px]">Intent</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <GitFork className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px]">Relationships</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Smile className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px]">Sentiment</span>
                              </li>
                              <li className="pt-0.5 text-[#555555] font-mono text-[10px] tracking-widest pl-1">
                                ...
                              </li>
                            </ul>
                          </div>
                        </div>

                        {/* Double Blue Vertical Cable from Center down to SIGNALS */}
                        <div className="w-3 h-12 relative flex justify-between">
                          <div className="w-[1px] h-full bg-[#0055FF]" />
                          <div className="w-[1px] h-full bg-[#0055FF]" />
                          {/* Animated Blue Pulse Particle flowing down */}
                          <motion.div
                            animate={{ y: ["0%", "100%"] }}
                            transition={{ repeat: Infinity, duration: 1.2, ease: "linear" }}
                            className="absolute left-0 right-0 h-4 bg-[#0055FF]/40 border-y border-[#0055FF]"
                          />
                        </div>

                        {/* Bottom: SIGNALS Box matching Frame 005 identically */}
                        <div className="border border-[#0055FF] bg-[#0c0c0e] p-4 w-full max-w-sm rounded-none text-center relative shadow-[0_0_15px_rgba(0,85,255,0.15)]">
                          <div className="text-[10px] font-mono uppercase text-[#71717a] tracking-[0.2em] font-semibold mb-3">
                            SIGNALS
                          </div>
                          <div className="flex items-center justify-center gap-3 sm:gap-4">
                            <span className="w-1.5 h-1.5 bg-[#333333] rounded-none shrink-0" />
                            <div className="w-11 h-11 bg-[#111111] border border-[#222222] flex items-center justify-center text-[#0055FF]">
                              <BarChart3 className="w-5 h-5 stroke-[2.2]" />
                            </div>
                            <span className="w-1.5 h-1.5 bg-[#0055FF] rounded-full shrink-0" />
                            <div className="w-11 h-11 bg-[#111111] border border-[#222222] flex items-center justify-center text-[#0055FF]">
                              <DiamondAlert className="w-5 h-5" />
                            </div>
                            <span className="w-1.5 h-1.5 bg-[#0055FF] rounded-full shrink-0" />
                            <div className="w-11 h-11 bg-[#111111] border border-[#222222] flex items-center justify-center text-[#0055FF]">
                              <Bell className="w-5 h-5 stroke-[2.2]" />
                            </div>
                            <span className="w-1.5 h-1.5 bg-[#333333] rounded-none shrink-0" />
                          </div>
                        </div>
                      </motion.div>
                    )}

                    {activeTab === 1 && (
                      /* TAB 2: Intelligent Processing (Workflow Analyzer & Active Task Dispatch) */
                      <motion.div
                        key="tab-1"
                        initial={{ opacity: 0, scale: 0.96 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.96 }}
                        transition={{ duration: 0.25 }}
                        className="w-full relative flex items-center justify-center py-4"
                      >
                        {/* Main Background Workflow Card matching Frame 008 */}
                        <div className="w-full max-w-[340px] bg-[#0e0e10] border border-[#222222] p-6 rounded-none space-y-4 shadow-xl">
                          {/* 3 Skeleton horizontal bars */}
                          <div className="space-y-2">
                            <div className="w-3/5 h-3.5 bg-[#262626] rounded-none" />
                            <div className="w-2/5 h-3.5 bg-[#1f1f1f] rounded-none" />
                            <div className="w-4/5 h-3.5 bg-[#262626] rounded-none" />
                          </div>

                          {/* Sunflower Spinner: Analyzing your workflow... */}
                          <div className="pt-6 flex items-center gap-3 text-xs font-sans text-[#888888]">
                            <SunflowerLoader className="w-4 h-4 text-white" />
                            <span>Analyzing your workflow...</span>
                          </div>

                          {/* Bottom row: Chevron + #project01 */}
                          <div className="pt-6 flex items-center gap-1.5 text-xs font-mono text-[#71717a]">
                            <ChevronDown className="w-3.5 h-3.5 text-[#71717a]" />
                            <span>#project01</span>
                          </div>
                        </div>

                        {/* Floating Foreground Task Card matching Frame 010 */}
                        <motion.div
                          initial={{ y: 20, opacity: 0 }}
                          animate={{ y: 0, opacity: 1 }}
                          transition={{ delay: 0.15 }}
                          className="absolute -bottom-4 right-2 sm:right-6 w-72 sm:w-80 bg-[#0a0a0a] border border-[#222222] p-4.5 rounded-none shadow-2xl z-20"
                        >
                          {/* Header: Check icon + To-do, and [ 5 ] count badge */}
                          <div className="flex items-center justify-between text-xs pb-3 border-b border-[#222222]">
                            <div className="flex items-center gap-2 text-white font-medium font-sans">
                              <CheckCircle2 className="w-4 h-4 text-white" />
                              <span>To-do</span>
                            </div>
                            <div className="px-2 py-0.5 bg-[#18181b] border border-[#27272a] text-[11px] font-mono text-white">
                              5
                            </div>
                          </div>

                          {/* Assignees chips: Anna and John */}
                          <div className="mt-3.5 flex items-center gap-2.5">
                            <div className="flex items-center gap-1.5 px-2.5 py-1 bg-[#141416] border border-[#27272a] text-xs text-[#d4d4d8] font-sans">
                              <User className="w-3.5 h-3.5 text-[#888888]" />
                              <span>Anna</span>
                            </div>
                            <div className="flex items-center gap-1.5 px-2.5 py-1 bg-[#141416] border border-[#27272a] text-xs text-[#a1a1aa] font-sans">
                              <User className="w-3.5 h-3.5 text-[#888888]" />
                              <span>John</span>
                            </div>
                          </div>

                          {/* Electric Blue Progress Bar */}
                          <div className="mt-4 w-full h-1 bg-[#222222] overflow-hidden rounded-none">
                            <motion.div
                              animate={{ width: ["20%", "65%", "100%", "20%"] }}
                              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
                              className="h-full bg-[#0055FF]"
                            />
                          </div>
                        </motion.div>
                      </motion.div>
                    )}

                    {activeTab === 2 && (
                      /* TAB 3: Actionable Output (Multi-Format Pipeline Stack matching Frame 026) */
                      <motion.div
                        key="tab-2"
                        initial={{ opacity: 0, scale: 0.96 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.96 }}
                        transition={{ duration: 0.25 }}
                        className="w-full flex flex-col items-center gap-2.5 relative"
                      >
                        {/* Central Vertical Electric Blue Laser Line behind the cards */}
                        <div className="absolute top-12 bottom-0 w-[1.5px] bg-[#0055FF] pointer-events-none z-0" />

                        {/* Top Asterisk Core Box */}
                        <div className="w-14 h-14 bg-[#0a0a0a] border border-[#222222] flex items-center justify-center relative z-10 mb-2 shadow-lg">
                          <AsteriskCoreIcon className="w-6 h-6 text-white" />
                        </div>

                        {/* Card 1: Summary [PDF] */}
                        <div className="w-72 sm:w-80 bg-[#0d0d0f] border border-[#222222] px-4 py-2.5 rounded-none flex items-center justify-between relative z-10">
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 bg-[#141416] border border-[#222222] flex items-center justify-center text-[#a1a1aa]">
                              <AlignLeft className="w-3.5 h-3.5" />
                            </div>
                            <span className="text-xs font-medium text-[#e4e4e7] font-sans">Summary</span>
                          </div>
                          <div className="text-[10px] font-mono text-[#71717a] font-bold px-1.5 py-0.5 bg-[#141416] border border-[#222222]">
                            PDF
                          </div>
                        </div>

                        {/* Card 2: Key Findings [DOCS] (ACTIVE & HIGHLIGHTED in #0055FF with lateral docking dots) */}
                        <div className="w-72 sm:w-80 bg-[#0d0d0f] border border-[#0055FF] px-4 py-2.5 rounded-none flex items-center justify-between relative z-10 shadow-[0_0_15px_rgba(0,85,255,0.15)]">
                          {/* Left Exterior Blue Docking Node */}
                          <div className="absolute -left-5 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-[#0055FF] shadow-[0_0_8px_#0055FF]" />
                          
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 bg-[#0055FF]/10 border border-[#0055FF]/40 flex items-center justify-center text-[#0055FF]">
                              <Lightbulb className="w-3.5 h-3.5 stroke-[2.2]" />
                            </div>
                            <span className="text-xs font-semibold text-[#0055FF] font-sans">Key Findings</span>
                          </div>
                          <div className="text-[10px] font-mono text-[#0055FF] font-bold px-1.5 py-0.5 bg-[#0055FF]/10 border border-[#0055FF]/40">
                            DOCS
                          </div>

                          {/* Right Exterior Blue Docking Node */}
                          <div className="absolute -right-5 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-[#0055FF] shadow-[0_0_8px_#0055FF]" />
                        </div>

                        {/* Card 3: Metrics [CSV] */}
                        <div className="w-72 sm:w-80 bg-[#0d0d0f] border border-[#222222] px-4 py-2.5 rounded-none flex items-center justify-between relative z-10">
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 bg-[#141416] border border-[#222222] flex items-center justify-center text-[#71717a]">
                              <BarChart3 className="w-3.5 h-3.5" />
                            </div>
                            <span className="text-xs font-medium text-[#71717a] font-sans">Metrics</span>
                          </div>
                          <div className="text-[10px] font-mono text-[#52525b] font-bold px-1.5 py-0.5 bg-[#141416] border border-[#222222]">
                            CSV
                          </div>
                        </div>

                        {/* Card 4: Recommendations [JSON] (Faded) */}
                        <div className="w-64 sm:w-72 bg-[#0a0a0c] border border-[#1f1f23] px-3.5 py-2 rounded-none flex items-center justify-between opacity-50 relative z-10">
                          <div className="flex items-center gap-3">
                            <div className="w-6 h-6 bg-[#111113] border border-[#1f1f23] flex items-center justify-center text-[#444444]">
                              <Flag className="w-3 h-3" />
                            </div>
                            <span className="text-[11px] font-medium text-[#52525b] font-sans">Recommendations</span>
                          </div>
                          <div className="text-[9px] font-mono text-[#3f3f46] font-bold px-1 py-0.5 bg-[#111113] border border-[#1f1f23]">
                            JSON
                          </div>
                        </div>
                      </motion.div>
                    )}
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
      {bottomFeatures.map((feat, idx) => (
        <motion.div
          key={idx}
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-20px" }}
          transition={{ duration: 0.4, delay: idx * 0.08 }}
          className="p-8 sm:p-10 flex flex-col justify-between hover:bg-[#111111] transition-none rounded-none cursor-default"
        >
          <div>
            <h4 className="text-xl font-medium text-white font-sans">
              {feat.title}
            </h4>
            <p className="mt-3 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
              {feat.desc}
            </p>
          </div>
        </motion.div>
      ))}
    </div>
  </div>
</section>
  );
}
