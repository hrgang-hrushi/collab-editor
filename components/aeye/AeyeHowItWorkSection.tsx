"use client";

import React, { useState, useRef } from "react";
import { motion, useScroll, useSpring, useTransform, useMotionValueEvent, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { Terminal, Cpu, Zap, Activity, ArrowRight, ShieldCheck, CheckCircle2, Play, Copy, Check, Sparkles } from "lucide-react";

interface AeyeHowItWorkSectionProps {
  onOpenTour?: (stepIndex?: number) => void;
}

export default function AeyeHowItWorkSection({ onOpenTour }: AeyeHowItWorkSectionProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [activeStep, setActiveStep] = useState(0);
  const isManualClickRef = useRef(false);
  const manualTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Interactive Live Pipeline Simulator State
  const [selectedPreset, setSelectedPreset] = useState<"crdt" | "webgpu" | "ipc">("crdt");
  const [pipelinePhase, setPipelinePhase] = useState<number>(0);
  const [isSimulating, setIsSimulating] = useState(false);
  const [pipelineCopied, setPipelineCopied] = useState(false);

  const presets = {
    crdt: {
      title: "AST-CRDT Peer Mesh Synchronization",
      inputTokens: "14.2 KB source buffer (TypeScript / Rust)",
      processMs: "0.42ms lock-free tokenization",
      generatedCode: `// Generated: Lock-Free CRDT Vector Ring Buffer
export class CRDTRingBuffer {
  private shm: SharedArrayBuffer;
  private vector: Int32Array;
  constructor(size: number = 64 * 1024) {
    this.shm = new SharedArrayBuffer(size);
    this.vector = new Int32Array(this.shm, 0, 4);
  }
  replicate(node: ASTNode): void {
    Atomics.add(this.vector, 0, 1);
    this.broadcastWebRTC(node);
  }
}`,
      refineStatus: "Attested 0-collision · Deterministic peer convergence",
    },
    webgpu: {
      title: "WebGPU Direct Metal Shader Pipeline",
      inputTokens: "250,000 LOC Syntax Stream",
      processMs: "0.18ms compute pass dispatch",
      generatedCode: `// Generated: WGSL Fast Syntax Highlighting Shader
@group(0) @binding(0) var<storage, read> tokenBuffer: array<u32>;
@group(0) @binding(1) var<storage, read_write> glyphColors: array<vec4<f32>>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let token = tokenBuffer[id.x];
    if (token == 0x01u) {
        glyphColors[id.x] = vec4<f32>(0.0, 0.33, 1.0, 1.0); // Crux Blue
    }
}`,
      refineStatus: "Metal 3.1 compiled · 120 FPS phosphor refresh verified",
    },
    ipc: {
      title: "Memory-Mapped Native POSIX IPC",
      inputTokens: "UNIX domain socket descriptor unix:///var/run/crux.sock",
      processMs: "0.08ms sub-microsecond roundtrip",
      generatedCode: `// Generated: Low-Latency Rust Unix Stream Bridge
use tokio::net::UnixStream;
use std::os::unix::io::AsRawFd;

pub async fn spawn_ipc_listener() -> Result<(), std::io::Error> {
    let stream = UnixStream::connect("/var/run/crux.sock").await?;
    let raw_fd = stream.as_raw_fd();
    unsafe { libc::fcntl(raw_fd, libc::F_SETFL, libc::O_NONBLOCK) };
    Ok(())
}`,
      refineStatus: "POSIX namespace verified · 0 cloud latency",
    },
  };

  const currentPresetData = presets[selectedPreset];

  const runPipelineSimulation = () => {
    if (isSimulating) return;
    setIsSimulating(true);
    setPipelinePhase(1);

    setTimeout(() => {
      setPipelinePhase(2);
      setTimeout(() => {
        setPipelinePhase(3);
        setTimeout(() => {
          setPipelinePhase(4);
          setIsSimulating(false);
        }, 500);
      }, 500);
    }, 500);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(currentPresetData.generatedCode);
    setPipelineCopied(true);
    setTimeout(() => setPipelineCopied(false), 2000);
  };

  // Smooth scroll interpolation using spring physics
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end end"],
  });

  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 140,
    damping: 26,
    mass: 0.2,
  });

  // Dedicated MotionValues for each cumulative progress bar
  const fill0 = useTransform(smoothProgress, [0.02, 0.25], ["0%", "100%"]);
  const fill1 = useTransform(smoothProgress, [0.25, 0.50], ["0%", "100%"]);
  const fill2 = useTransform(smoothProgress, [0.50, 0.75], ["0%", "100%"]);
  const fill3 = useTransform(smoothProgress, [0.75, 0.98], ["0%", "100%"]);
  const fills = [fill0, fill1, fill2, fill3];

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
          <path
            d="M18 20L10 15M24 16L18 10M40 16L46 10M46 20L54 15M50 36L58 41M46 44L52 50M18 44L12 50M14 36L6 41"
            stroke={isActive ? "#0055FF" : "#333333"}
            strokeWidth="1.5"
          />
        </svg>
      ),
    },
    {
      serial: "// 003",
      badge: "GENERATION",
      title: "Generate outputs",
      desc: "Receive structured, ready-to-use results built directly from your inputs.",
      renderIcon: (isActive: boolean) => (
        <svg
          viewBox="0 0 64 64"
          className="w-14 h-14 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <rect
            x="14"
            y="14"
            width="36"
            height="36"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#333333"}
            strokeWidth="1.5"
          />
          <line
            x1="22"
            y1="24"
            x2="42"
            y2="24"
            stroke={isActive ? "#FFFFFF" : "#555555"}
            strokeWidth="2"
          />
          <line
            x1="22"
            y1="32"
            x2="36"
            y2="32"
            stroke={isActive ? "#FFFFFF" : "#555555"}
            strokeWidth="2"
          />
          <line
            x1="22"
            y1="40"
            x2="42"
            y2="40"
            stroke={isActive ? "#FFFFFF" : "#555555"}
            strokeWidth="2"
          />
        </svg>
      ),
    },
    {
      serial: "// 004",
      badge: "OPTIMIZATION",
      title: "Refine & iterate",
      desc: "Easily adjust, fine-tune, or scale your workflow as needs evolve.",
      renderIcon: (isActive: boolean) => (
        <svg
          viewBox="0 0 64 64"
          className="w-14 h-14 transition-none"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <circle
            cx="32"
            cy="32"
            r="20"
            fill={isActive ? "#0055FF" : "#111111"}
            stroke={isActive ? "#0055FF" : "#333333"}
            strokeWidth="1.5"
          />
          <path
            d="M32 18V32L42 42"
            stroke={isActive ? "#FFFFFF" : "#555555"}
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      ),
    },
  ];

  return (
    <section id="features" className="relative w-full border-b border-[#222222] bg-[#000000]">
      {/* Scroll-driven Sticky Container */}
      <div ref={containerRef} className="relative lg:h-[260vh]">
        <div className="relative lg:sticky lg:top-0 lg:h-screen lg:flex lg:flex-col lg:justify-center overflow-visible lg:overflow-hidden py-12 lg:py-0">
          <div className="max-w-[1280px] w-full mx-auto px-6">
            {/* Section Header Meta */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#222222] text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="text-[#0055FF] font-bold">[N.04/11]</span>
                <span className="text-[#888888]">— &gt;</span>
                <span className="text-[#888888] uppercase">HOW IT WORKS</span>
                <span className="text-[#444444]">|</span>
                <span className="text-white font-medium">PIPELINE ARCHITECTURE</span>
              </div>
              <div className="flex items-center gap-3 pt-2 sm:pt-0">
                {onOpenTour && (
                  <button
                    onClick={() => onOpenTour(0)}
                    className="px-2.5 py-1 bg-[#111114] hover:bg-[#1a1a24] border border-[#0055FF]/60 hover:border-[#0055FF] text-white text-[11px] font-mono uppercase tracking-wider flex items-center gap-1.5 cursor-pointer rounded-none"
                  >
                    <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                    <span>TAKE PIPELINE TOUR</span>
                  </button>
                )}
                <span className="text-xs font-mono text-[#0055FF] font-bold">
                  [ 0{activeStep + 1} / 04 ]
                </span>
              </div>
            </div>

            {/* Headline and Action */}
            <div className="pt-6 pb-6 flex flex-col md:flex-row md:items-end justify-between gap-6">
              <div>
                <h2 className="text-3xl sm:text-4xl lg:text-[44px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
                  Understand the flow.
                  <span className="block text-[#888888]">See how it all connects.</span>
                </h2>
              </div>
              <div className="flex flex-wrap items-center gap-3 shrink-0">
                <a
                  href="/ide"
                  className="inline-flex items-center gap-2 px-3.5 py-2 bg-[#000000] border border-white text-white font-mono text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none no-underline"
                >
                  <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                  <span>LAUNCH WEB IDE ↵</span>
                </a>
                <button
                  onClick={runPipelineSimulation}
                  disabled={isSimulating}
                  className="inline-flex items-center gap-2 px-3.5 py-2 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono text-xs tracking-wider uppercase transition-none cursor-pointer rounded-none font-bold"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>{isSimulating ? "RUNNING SIMULATION..." : "SIMULATE PIPELINE ↵"}</span>
                </button>
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
                    className={`relative p-4 sm:p-5 flex flex-col justify-between min-h-[230px] sm:min-h-[250px] cursor-pointer transition-none select-none ${
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
                        className={`mt-3 text-xs font-sans leading-relaxed min-h-[36px] transition-none ${
                          isActive ? "text-white" : "text-[#777777]"
                        }`}
                      >
                        {step.desc}
                      </p>
                    </div>

                    {/* Middle Cumulative Blue Progress Rail */}
                    <div className="my-3 relative">
                      <div className="w-full h-1 bg-[#141418] relative overflow-hidden">
                        <motion.div
                          className="h-full bg-[#0055FF]"
                          style={{ width: fillMotionValue }}
                        />
                      </div>
                      <div className="w-full h-1 mt-1 opacity-20 bg-[radial-gradient(#ffffff_1px,transparent_1px)] [background-size:4px_4px]" />
                    </div>

                    {/* Bottom Section: Title + Graphic */}
                    <div className="flex items-end justify-between pt-1">
                      <div className="flex flex-col">
                        <span className="text-[9px] font-mono text-[#555555] uppercase">
                          PHASE 0{idx + 1}
                        </span>
                        <h3
                          className={`text-base font-medium font-sans transition-none ${
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

            {/* Live Interactive Pipeline Sandbox Console */}
            <div className="mt-4 border border-[#222222] bg-[#08080b] p-3 sm:p-4 rounded-none font-mono text-xs">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#222222]">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-[#0055FF] inline-block" />
                  <span className="text-white font-bold uppercase tracking-wider text-[11px]">
                    LIVE HARDWARE PIPELINE WORKBENCH
                  </span>
                  <span className="text-[#444444]">|</span>
                  <span className="text-[#71717a] text-[10px] hidden sm:inline">
                    SELECT WORKLOAD:
                  </span>
                </div>

                {/* Preset Switcher */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  {[
                    { id: "crdt" as const, label: "01 // CRDT MESH" },
                    { id: "webgpu" as const, label: "02 // WEBGPU SHADER" },
                    { id: "ipc" as const, label: "03 // POSIX IPC" },
                  ].map((p) => (
                    <button
                      key={p.id}
                      onClick={() => {
                        setSelectedPreset(p.id);
                        setPipelinePhase(0);
                      }}
                      className={`px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider transition-none cursor-pointer rounded-none border ${
                        selectedPreset === p.id
                          ? "bg-[#0055FF] text-white border-[#0055FF] font-bold"
                          : "bg-[#111114] text-[#888888] border-[#222222] hover:text-white"
                      }`}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Simulation State Grid */}
              <div className="pt-3 grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
                {/* Left: Real-time Phase Telemetry */}
                <div className="lg:col-span-4 space-y-2 text-[11px]">
                  <div className="p-2 border border-[#222222] bg-[#0c0c10]">
                    <span className="text-[#71717a] block text-[9.5px]">WORKLOAD SPECIFICATION</span>
                    <span className="text-white font-semibold">{currentPresetData.title}</span>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <div className="p-2 border border-[#222222] bg-[#0c0c10]">
                      <span className="text-[#71717a] block text-[9.5px]">INPUT CONTEXT</span>
                      <span className="text-[#0055FF] font-medium">{currentPresetData.inputTokens}</span>
                    </div>
                    <div className="p-2 border border-[#222222] bg-[#0c0c10]">
                      <span className="text-[#71717a] block text-[9.5px]">DISPATCH LATENCY</span>
                      <span className="text-[#22c55e] font-medium">{currentPresetData.processMs}</span>
                    </div>
                  </div>

                  <div className="p-2 border border-[#222222] bg-[#0c0c10]">
                    <span className="text-[#71717a] block text-[9.5px]">ATTESTATION VERIFICATION</span>
                    <span className="text-white text-[10px]">{currentPresetData.refineStatus}</span>
                  </div>
                </div>

                {/* Right: Generated Output Buffer with Copy Action */}
                <div className="lg:col-span-8 border border-[#222222] bg-[#040406] p-3 flex flex-col justify-between">
                  <div className="flex items-center justify-between pb-2 border-b border-[#1a1a20]">
                    <div className="flex items-center gap-2 text-[10px] text-[#71717a]">
                      <Terminal className="w-3 h-3 text-[#0055FF]" />
                      <span>SYNTHESIZED BARE-METAL OUTPUT</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleCopyCode}
                        className="px-2 py-0.5 bg-[#111116] hover:bg-[#1a1a24] border border-[#333333] hover:border-white text-white text-[10px] font-mono flex items-center gap-1 cursor-pointer rounded-none transition-none"
                      >
                        {pipelineCopied ? <Check className="w-3 h-3 text-[#22c55e]" /> : <Copy className="w-3 h-3" />}
                        <span>{pipelineCopied ? "COPIED" : "COPY CODE"}</span>
                      </button>
                      <a
                        href="/ide"
                        className="px-2 py-0.5 bg-[#0055FF] hover:bg-[#0044CC] text-white text-[10px] font-bold no-underline cursor-pointer rounded-none"
                      >
                        OPEN IN IDE ↵
                      </a>
                    </div>
                  </div>

                  <pre className="mt-2 text-[10.5px] font-mono text-[#a1a1aa] leading-relaxed overflow-x-auto max-h-[140px] whitespace-pre p-2 bg-[#000000]">
                    {currentPresetData.generatedCode}
                  </pre>
                </div>
              </div>
            </div>

          </div>
        </div>
      </div>
    </section>
  );
}
