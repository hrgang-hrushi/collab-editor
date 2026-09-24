"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

export default function AeyeHowItWorkSection() {
  const [activeStep, setActiveStep] = useState(0);

  const steps = [
    {
      step: "// 001",
      title: "Mount Local Workspace",
      desc: "Open any repository locally or stream a remote Git branch.",
      detail: "Crux reads your native filesystem with zero indexing lag using kernel-level epoll/kqueue file system watch events.",
      telemetry: {
        command: "crux mount /projects/collab-editor --watch=kqueue",
        log: "Indexed 14,280 files in 4.1ms · Inode cache initialized · 0MB Chromium memory overhead",
        status: "KERNEL WATCHER ACTIVE",
        latency: "0.4ms fsync",
      },
    },
    {
      step: "// 002",
      title: "Instant P2P Handshake",
      desc: "Share a cryptographic session token with team peers.",
      detail: "Direct WebRTC mesh connection established in <50ms with encrypted P2P CRDT stream synchronization.",
      telemetry: {
        command: "crux p2p join --mesh=secp256k1 --peers=8",
        log: "Handshake verified with 8 global peers · DTLS 1.3 encrypted mesh · Zero split-brain state",
        status: "P2P MESH CONVERGED",
        latency: "6.2ms avg ping",
      },
    },
    {
      step: "// 003",
      title: "Co-Author with @CruxAI",
      desc: "Trigger multi-agent terminal commands and inline AST generation.",
      detail: "Autonomous agent refactors across multiple files, tests code in background sandbox, and reports stdout directly in HyperTerminal.",
      telemetry: {
        command: "@CruxAI synthesize ast::Pipeline --fix-compiler-warnings",
        log: "Transformed 42 files across Rust & TS modules · Ran 188 unit tests [PASS: 188 / FAIL: 0]",
        status: "AGENTIC SYNTHESIS VERIFIED",
        latency: "18.4ms compile",
      },
    },
    {
      step: "// 004",
      title: "Ship with Machine Precision",
      desc: "Zero merge conflicts, sub-15ms typing feedback, zero battery drain.",
      detail: "Hardware brutalist efficiency ensures full mechanical keyboard responsiveness even under massive 100K-line monorepo loads.",
      telemetry: {
        command: "git push origin main --signoff --atomic",
        log: "Atomic CRDT delta tree committed · Build artifacts deployed to edge in 320ms",
        status: "MAIN BRANCH SYNCHRONIZED",
        latency: "120 FPS render",
      },
    },
  ];

  return (
    <section id="how-it-works" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono"
        >
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[n. 04 / 11 ]</span>
            <span className="text-[#0055FF] font-bold">&gt;</span>
            <span className="text-[#888888]">How It Work</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0">
            PEER COLLABORATION &amp; KERNEL LIFECYCLE
          </div>
        </motion.div>

        {/* Section Title & Subtitle */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
          className="pt-8 pb-14"
        >
          <h2 className="text-3xl sm:text-5xl lg:text-[54px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
            Understand the flow.{" "}
            <span className="text-[#71717a] block sm:inline">
              See how it all connects.
            </span>
          </h2>
        </motion.div>

        {/* 4 Connected Process Cards */}
        <div className="relative">
          {/* Connecting Progress Line behind cards */}
          <div className="hidden lg:block absolute top-[44px] left-[10%] right-[10%] h-[1px] bg-[#222222] z-0 overflow-hidden">
            <motion.div
              animate={{ width: `${(activeStep / (steps.length - 1)) * 100}%` }}
              transition={{ type: "spring", stiffness: 300, damping: 30 }}
              className="h-full bg-[#0055FF]"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 relative z-10">
            {steps.map((s, idx) => {
              const isSelected = activeStep === idx;
              return (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 25 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, margin: "-30px" }}
                  transition={{ duration: 0.5, delay: idx * 0.1 }}
                  onClick={() => setActiveStep(idx)}
                  className={`p-6 sm:p-7 border transition-none cursor-pointer rounded-none flex flex-col justify-between min-h-[300px] ${
                    isSelected
                      ? "border-[#0055FF] bg-[#0055FF]/5"
                      : "border-[#222222] bg-[#000000] hover:bg-[#111111]"
                  }`}
                >
                  <div>
                    {/* Step Icon Badge */}
                    <div className="flex items-center justify-between mb-6">
                      <div
                        className={`w-9 h-9 border flex items-center justify-center font-mono text-xs font-bold transition-none rounded-none ${
                          isSelected
                            ? "bg-[#0055FF] text-white border-[#0055FF]"
                            : "bg-[#111111] text-white border-[#222222]"
                        }`}
                      >
                        {idx + 1}
                      </div>
                      <span className="font-mono text-[11px] text-[#0055FF] font-bold">
                        {s.step}
                      </span>
                    </div>

                    <h3 className="text-xl font-medium text-white font-sans">
                      {s.title}
                    </h3>
                    <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
                      {s.desc}
                    </p>
                  </div>

                  <div className="mt-6 pt-4 border-t border-[#222222] text-[11px] font-sans text-[#71717a] leading-normal">
                    {s.detail}
                  </div>
                </motion.div>
              );
            })}
          </div>

          {/* Interactive Live Telemetry Console for Active Step */}
          <div className="mt-6 border border-[#222222] bg-[#000000] p-5 font-mono text-xs rounded-none">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#222222] gap-2">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-[#0055FF]" />
                <span className="text-white font-bold uppercase">
                  STEP {activeStep + 1} PIPELINE TELEMETRY // {steps[activeStep].title}
                </span>
              </div>
              <div className="flex items-center gap-4 text-[11px]">
                <span className="text-[#0055FF] font-bold">
                  ● {steps[activeStep].telemetry.status}
                </span>
                <span className="text-[#888888]">
                  LATENCY: <strong className="text-white">{steps[activeStep].telemetry.latency}</strong>
                </span>
              </div>
            </div>

            <div className="pt-3 space-y-1.5 text-[11px]">
              <div className="text-[#888888] flex items-center gap-2">
                <span className="text-[#0055FF] font-bold">&gt;</span>
                <span className="text-white font-semibold">
                  {steps[activeStep].telemetry.command}
                </span>
              </div>
              <div className="text-[#71717a] pl-4">
                {steps[activeStep].telemetry.log}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
