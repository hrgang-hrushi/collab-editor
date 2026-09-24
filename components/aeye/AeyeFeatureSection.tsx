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
  GitBranch,
  GitMerge,
  Smile,
  BarChart3,
  Bell,
  ChevronDown,
  CheckCircle2,
  Lightbulb,
  Flag,
  Code2,
  Terminal,
  Cpu,
  Zap,
  Network,
  Activity,
  ShieldCheck,
  Bot,
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
      title: "Works with your workflow",
      desc: "Connect seamlessly with your existing tools, systems, and data sources.",
    },
    {
      title: "Minimal by default",
      desc: "Focus only on what matters, no unnecessary complexity.",
    },
    {
      title: "Built to scale",
      desc: "Handle growing workflows, data, and outputs over time.",
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
                      /* TAB 1: Context Awareness (WORKSPACE INPUTS -> BRACKETS -> CRUX KERNEL -> DOUBLE CABLE -> TELEMETRY) */
                      <motion.div
                        key="tab-0"
                        initial={{ opacity: 0, scale: 0.96 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.96 }}
                        transition={{ duration: 0.25 }}
                        className="w-full flex flex-col items-center gap-6 relative"
                      >
                        {/* Upper Row: WORKSPACE INPUTS, BRACKET TRACES, CENTER CRUX CORE, EXECUTION CONTEXT */}
                        <div className="w-full flex items-center justify-between gap-2 sm:gap-4 relative">
                          {/* Left: WORKSPACE INPUTS Box */}
                          <div className="w-36 sm:w-44 p-3 bg-[#0d0d0f] border border-[#222222] rounded-none z-10 shadow-md">
                            <div className="text-[10px] font-mono uppercase text-[#71717a] font-semibold pb-1.5 border-b border-[#222222] mb-2 flex items-center justify-between">
                              <span>WORKSPACE INPUTS</span>
                            </div>
                            <ul className="space-y-2 text-xs font-sans text-[#d4d4d8] list-none p-0 m-0">
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Code2 className="w-3.5 h-3.5 text-[#0055FF] shrink-0" />
                                <span className="text-white text-[11px] truncate">Source Trees (.rs, .ts)</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Activity className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px] truncate">Keystroke Stream (&lt;15ms)</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <GitBranch className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px] truncate">Git HEAD &amp; Local Diffs</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Database className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px] truncate">AST Inodes &amp; Buffers</span>
                              </li>
                              <li className="pt-0.5 text-[#555555] font-mono text-[10px] tracking-widest pl-1">
                                ...
                              </li>
                            </ul>
                          </div>

                          {/* Left Circuit Bracket Trace (WORKSPACE INPUTS to Center) */}
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

                          {/* Right Circuit Bracket Trace (Center to EXECUTION CONTEXT) */}
                          <div className="flex-1 h-24 relative flex items-center justify-center">
                            <svg className="w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 80 80">
                              <line x1="0" y1="40" x2="45" y2="40" stroke="#333333" strokeWidth="1" />
                              <line x1="45" y1="15" x2="45" y2="65" stroke="#333333" strokeWidth="1" />
                              <line x1="35" y1="15" x2="45" y2="15" stroke="#333333" strokeWidth="1" />
                              <line x1="35" y1="65" x2="45" y2="65" stroke="#333333" strokeWidth="1" />
                              <line x1="45" y1="40" x2="80" y2="40" stroke="#333333" strokeWidth="1" />
                            </svg>
                          </div>

                          {/* Right: EXECUTION CONTEXT Box */}
                          <div className="w-36 sm:w-44 p-3 bg-[#0d0d0f] border border-[#222222] rounded-none z-10 shadow-md">
                            <div className="text-[10px] font-mono uppercase text-[#71717a] font-semibold pb-1.5 border-b border-[#222222] mb-2 flex items-center justify-between">
                              <span>EXECUTION CONTEXT</span>
                            </div>
                            <ul className="space-y-2 text-xs font-sans text-[#d4d4d8] list-none p-0 m-0">
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Cpu className="w-3.5 h-3.5 text-[#0055FF] shrink-0" />
                                <span className="text-white text-[11px] truncate">Rust Native Kernel</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Zap className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px] truncate">WebGPU (120 FPS)</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <GitFork className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px] truncate">AST-CRDT Engine</span>
                              </li>
                              <li className="flex items-center gap-2 pb-1.5 border-b border-[#222222]/60">
                                <Terminal className="w-3.5 h-3.5 text-[#888888] shrink-0" />
                                <span className="text-white text-[11px] truncate">@CruxAI Sandbox</span>
                              </li>
                              <li className="pt-0.5 text-[#555555] font-mono text-[10px] tracking-widest pl-1">
                                ...
                              </li>
                            </ul>
                          </div>
                        </div>

                        {/* Double Blue Vertical Cable from Center down to TELEMETRY */}
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

                        {/* Bottom: KERNEL TELEMETRY Box matching Screenshot 1 identically */}
                        <div className="border border-[#0055FF] bg-[#0c0c0e] p-3.5 sm:p-4 w-full max-w-sm rounded-none text-center relative shadow-[0_0_15px_rgba(0,85,255,0.15)]">
                          <div className="text-[10px] font-mono uppercase text-[#71717a] tracking-[0.2em] font-semibold mb-3">
                            KERNEL TELEMETRY
                          </div>
                          <div className="flex items-center justify-center gap-2.5 sm:gap-3.5">
                            <span className="w-1.5 h-1.5 bg-[#333333] rounded-none shrink-0" />
                            <div className="w-12 h-12 bg-[#111111] border border-[#222222] flex flex-col items-center justify-center gap-0.5 text-[#0055FF]">
                              <Activity className="w-4 h-4 stroke-[2.2]" />
                              <span className="text-[8px] font-mono text-[#888888]">0.4ms I/O</span>
                            </div>
                            <span className="w-1.5 h-1.5 bg-[#0055FF] rounded-full shrink-0 shadow-[0_0_6px_#0055FF]" />
                            <div className="w-12 h-12 bg-[#111111] border border-[#0055FF]/60 flex flex-col items-center justify-center gap-0.5 text-[#0055FF] shadow-[0_0_10px_rgba(0,85,255,0.2)]">
                              <Zap className="w-4 h-4 stroke-[2.2]" />
                              <span className="text-[8px] font-mono text-[#0055FF] font-bold">120 FPS</span>
                            </div>
                            <span className="w-1.5 h-1.5 bg-[#0055FF] rounded-full shrink-0 shadow-[0_0_6px_#0055FF]" />
                            <div className="w-12 h-12 bg-[#111111] border border-[#222222] flex flex-col items-center justify-center gap-0.5 text-[#0055FF]">
                              <Network className="w-4 h-4 stroke-[2.2]" />
                              <span className="text-[8px] font-mono text-[#888888]">P2P DTLS</span>
                            </div>
                            <span className="w-1.5 h-1.5 bg-[#333333] rounded-none shrink-0" />
                          </div>
                        </div>
                      </motion.div>
                    )}

                    {activeTab === 1 && (
                      /* TAB 2: Intelligent Processing (Autonomous Compiler Sandbox & Real-Time CRDT Mesh) */
                      <motion.div
                        key="tab-1"
                        initial={{ opacity: 0, scale: 0.96 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.96 }}
                        transition={{ duration: 0.25 }}
                        className="w-full relative flex items-center justify-center py-4"
                      >
                        {/* Main Background Sandbox Card matching Screenshot 2 */}
                        <div className="w-full max-w-[340px] bg-[#0e0e10] border border-[#222222] p-5 sm:p-6 rounded-none space-y-3.5 shadow-xl">
                          {/* Terminal command & status lines */}
                          <div className="space-y-1.5 pb-2 border-b border-[#222222]/80">
                            <div className="text-[10px] font-mono text-[#0055FF] font-semibold flex items-center gap-1.5">
                              <span>[@CruxAI]</span>
                              <span className="text-[#666666]">cargo check --target=arm64</span>
                            </div>
                            <div className="text-[11px] font-mono text-[#cccccc] truncate">
                              Compiling crux-kernel v0.4.2 [AST-CRDT]
                            </div>
                          </div>

                          {/* Skeleton AST token bars */}
                          <div className="space-y-2 pt-1">
                            <div className="w-3/5 h-2.5 bg-[#262626] rounded-none" />
                            <div className="w-2/5 h-2.5 bg-[#1f1f1f] rounded-none" />
                            <div className="w-4/5 h-2.5 bg-[#262626] rounded-none" />
                          </div>

                          {/* Sunflower Spinner: Resolving distributed AST state... */}
                          <div className="pt-4 flex items-center gap-2.5 text-xs font-mono text-white">
                            <SunflowerLoader className="w-4 h-4 text-[#0055FF]" />
                            <span className="text-[11px] text-[#e4e4e7]">Resolving distributed AST state...</span>
                          </div>

                          {/* Bottom row: Git Head & Symbols count */}
                          <div className="pt-4 flex items-center justify-between text-[10px] font-mono text-[#71717a] border-t border-[#222222]/60">
                            <div className="flex items-center gap-1.5">
                              <GitBranch className="w-3 h-3 text-[#71717a]" />
                              <span>main · 14,280 symbols</span>
                            </div>
                            <span className="text-[#0055FF] font-bold">0 CONFLICTS</span>
                          </div>
                        </div>

                        {/* Floating Foreground Multiplayer Task Card matching Screenshot 2 */}
                        <motion.div
                          initial={{ y: 20, opacity: 0 }}
                          animate={{ y: 0, opacity: 1 }}
                          transition={{ delay: 0.15 }}
                          className="absolute -bottom-4 right-2 sm:right-6 w-72 sm:w-80 bg-[#0a0a0a] border border-[#222222] p-4 rounded-none shadow-2xl z-20"
                        >
                          {/* Header: Check icon + P2P Mesh Converged, and [ 3 PEERS ] badge */}
                          <div className="flex items-center justify-between text-xs pb-2.5 border-b border-[#222222]">
                            <div className="flex items-center gap-2 text-white font-medium font-sans">
                              <CheckCircle2 className="w-4 h-4 text-[#0055FF]" />
                              <span className="font-semibold">P2P Mesh Converged</span>
                            </div>
                            <div className="px-2 py-0.5 bg-[#18181b] border border-[#27272a] text-[10px] font-mono text-[#0055FF] font-bold">
                              3 PEERS
                            </div>
                          </div>

                          {/* Peer chips: Alex, Sarah, and @CruxAI */}
                          <div className="mt-3 flex items-center gap-2 overflow-x-auto">
                            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#141416] border border-[#27272a] text-[11px] text-[#d4d4d8] font-mono shrink-0">
                              <User className="w-3 h-3 text-[#888888]" />
                              <span>Alex (Host)</span>
                            </div>
                            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#141416] border border-[#27272a] text-[11px] text-[#a1a1aa] font-mono shrink-0">
                              <User className="w-3 h-3 text-[#888888]" />
                              <span>Sarah</span>
                            </div>
                            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#0055FF]/10 border border-[#0055FF]/40 text-[11px] text-[#0055FF] font-mono shrink-0 font-bold">
                              <Bot className="w-3 h-3 text-[#0055FF]" />
                              <span>@CruxAI</span>
                            </div>
                          </div>

                          {/* Sub-10ms CRDT delta sync metric */}
                          <div className="mt-2.5 flex items-center justify-between text-[10px] font-mono text-[#71717a]">
                            <span>CRDT delta broadcast</span>
                            <span className="text-[#0055FF] font-semibold">4.2ms RTT</span>
                          </div>

                          {/* Electric Blue Progress Bar */}
                          <div className="mt-2 w-full h-1 bg-[#222222] overflow-hidden rounded-none">
                            <motion.div
                              animate={{ width: ["25%", "70%", "100%", "25%"] }}
                              transition={{ duration: 2.8, repeat: Infinity, ease: "easeInOut" }}
                              className="h-full bg-[#0055FF]"
                            />
                          </div>
                        </motion.div>
                      </motion.div>
                    )}

                    {activeTab === 2 && (
                      /* TAB 3: Actionable Output (Engineered Artifacts & Native Binaries matching Screenshot 3) */
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

                        {/* Card 1: Native Host Binary [ARM64 / x86_64] */}
                        <div className="w-72 sm:w-80 bg-[#0d0d0f] border border-[#222222] px-4 py-2.5 rounded-none flex items-center justify-between relative z-10">
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 bg-[#141416] border border-[#222222] flex items-center justify-center text-[#a1a1aa]">
                              <Cpu className="w-3.5 h-3.5" />
                            </div>
                            <span className="text-xs font-medium text-[#e4e4e7] font-sans">Native Host Binary</span>
                          </div>
                          <div className="text-[10px] font-mono text-[#71717a] font-bold px-1.5 py-0.5 bg-[#141416] border border-[#222222]">
                            ARM64
                          </div>
                        </div>

                        {/* Card 2: Atomic AST Git Diff [CRDT PATCH] (ACTIVE & HIGHLIGHTED in #0055FF with lateral docking dots) */}
                        <div className="w-72 sm:w-80 bg-[#0d0d0f] border border-[#0055FF] px-4 py-2.5 rounded-none flex items-center justify-between relative z-10 shadow-[0_0_15px_rgba(0,85,255,0.15)]">
                          {/* Left Exterior Blue Docking Node */}
                          <div className="absolute -left-5 top-1/2 -translate-y-1/2 w-2 h-2 rounded-none bg-[#0055FF] shadow-[0_0_8px_#0055FF]" />
                          
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 bg-[#0055FF]/10 border border-[#0055FF]/40 flex items-center justify-center text-[#0055FF]">
                              <GitMerge className="w-3.5 h-3.5 stroke-[2.2]" />
                            </div>
                            <span className="text-xs font-semibold text-[#0055FF] font-sans">Atomic AST Git Diff</span>
                          </div>
                          <div className="text-[10px] font-mono text-[#0055FF] font-bold px-1.5 py-0.5 bg-[#0055FF]/10 border border-[#0055FF]/40">
                            CRDT PATCH
                          </div>

                          {/* Right Exterior Blue Docking Node */}
                          <div className="absolute -right-5 top-1/2 -translate-y-1/2 w-2 h-2 rounded-none bg-[#0055FF] shadow-[0_0_8px_#0055FF]" />
                        </div>

                        {/* Card 3: WebGPU Render Pipeline [120 FPS] */}
                        <div className="w-72 sm:w-80 bg-[#0d0d0f] border border-[#222222] px-4 py-2.5 rounded-none flex items-center justify-between relative z-10">
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 bg-[#141416] border border-[#222222] flex items-center justify-center text-[#71717a]">
                              <Zap className="w-3.5 h-3.5 text-[#0055FF]" />
                            </div>
                            <span className="text-xs font-medium text-[#a1a1aa] font-sans">WebGPU Render Pipeline</span>
                          </div>
                          <div className="text-[10px] font-mono text-[#52525b] font-bold px-1.5 py-0.5 bg-[#141416] border border-[#222222]">
                            120 FPS
                          </div>
                        </div>

                        {/* Card 4: Encrypted P2P Session Token [SECP256K1] (Faded) */}
                        <div className="w-64 sm:w-72 bg-[#0a0a0c] border border-[#1f1f23] px-3.5 py-2 rounded-none flex items-center justify-between opacity-50 relative z-10">
                          <div className="flex items-center gap-3">
                            <div className="w-6 h-6 bg-[#111113] border border-[#1f1f23] flex items-center justify-center text-[#444444]">
                              <ShieldCheck className="w-3 h-3" />
                            </div>
                            <span className="text-[11px] font-medium text-[#52525b] font-sans">Encrypted P2P Session</span>
                          </div>
                          <div className="text-[9px] font-mono text-[#3f3f46] font-bold px-1 py-0.5 bg-[#111113] border border-[#1f1f23]">
                            SECP256K1
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

        {/* 2-row Toolchain Marquee */}
        <div className="mt-8 space-y-2 overflow-hidden relative">
          <div className="flex gap-2 animate-[marquee_20s_linear_infinite]">
            {["RUST", "GIT", "WEBGPU", "LLVM", "CLANG", "WEBRTC", "RUST", "GIT"].map((item, idx) => (
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
          </div>
          <div className="flex gap-2 animate-[marquee_25s_linear_infinite_reverse]">
            {["CARGO", "DOCKER", "NEOVIM", "ZSH", "TYPESCRIPT", "PYTHON", "CARGO", "DOCKER"].map((item, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2 px-3 py-1.5 border border-[#222222] bg-[#0a0a0c] text-white shrink-0 group-hover:border-[#333333]"
              >
                <div className="w-3.5 h-3.5 border border-white/40 flex items-center justify-center">
                  <div className="w-1.5 h-1.5 bg-[#0055FF]" />
                </div>
                <span className="text-[11px] font-bold tracking-wider uppercase font-mono">
                  {item}
                </span>
              </div>
            ))}
          </div>
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
