"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FileText,
  Terminal,
  Command,
  Database,
  Cpu,
  Compass,
  GitBranch,
  Activity,
  BarChart3,
  AlertTriangle,
  Bell,
  Check,
  User,
  FileCode2,
} from "lucide-react";
import { CruxLogo } from "./AeyeIcons";

export default function AeyeFeatureSection() {
  const [activeTab, setActiveTab] = useState<number>(0);

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
    <section id="features" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          className="flex items-center gap-3 pb-6 text-xs font-mono"
        >
          <span className="text-[#0055FF] font-semibold tracking-wider">[N.03/11]</span>
          <span className="w-8 h-[1px] bg-[#222222]" />
          <span className="text-[#0055FF] font-bold">&gt;</span>
          <span className="text-[#888888] uppercase tracking-wider font-semibold">CORE CAPABILITIES</span>
          <div className="flex-1 h-[1px] bg-[#222222] ml-2" />
        </motion.div>

        {/* Main Split Architecture matching Video Recording */}
        <div className="pt-6 grid grid-cols-1 lg:grid-cols-12 border border-[#222222] bg-[#000000]">
          {/* Left Column: 3 Interactive Capability Tabs + Bottom Headline */}
          <div className="lg:col-span-5 p-8 sm:p-12 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-[#222222] bg-[#000000]">
            {/* Top Interactive Tabs List */}
            <div className="space-y-8">
              {tabs.map((tab, idx) => {
                const isActive = activeTab === idx;
                return (
                  <div
                    key={idx}
                    onClick={() => setActiveTab(idx)}
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
            <div className="pt-16 mt-12 border-t border-[#222222]">
              <h2 className="text-3xl sm:text-4xl lg:text-[46px] font-normal tracking-[-0.05em] text-white font-sans leading-[1.1]">
                Three core layers.<br />
                <span className="text-[#888888]">One seamless system.</span>
              </h2>
            </div>
          </div>

          {/* Right Column: Visual Diagram Canvas matching Video Recording */}
          <div className="lg:col-span-7 relative min-h-[560px] p-6 sm:p-10 flex items-center justify-center bg-[#000000] overflow-hidden">
            {/* Dot Matrix Canvas Texture */}
            <div className="absolute inset-0 aeye-dot-bg invert opacity-20 pointer-events-none" />

            {/* Interactive Canvas Content */}
            <div className="relative z-10 w-full max-w-[520px]">
              <AnimatePresence mode="wait">
                {activeTab === 0 && (
                  /* TAB 1: Context Awareness (RAW INPUTS -> CORE -> CONTEXTS -> SIGNALS) */
                  <motion.div
                    key="tab-0"
                    initial={{ opacity: 0, scale: 0.96 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.96 }}
                    transition={{ duration: 0.25 }}
                    className="w-full flex flex-col items-center gap-8"
                  >
                    {/* Upper Row: RAW INPUTS, CENTER CORE, CONTEXTS */}
                    <div className="w-full flex items-center justify-between gap-4 relative">
                      {/* Left: RAW INPUTS Box */}
                      <div className="w-40 sm:w-44 p-3.5 bg-[#111111] border border-[#222222] rounded-none z-10">
                        <div className="text-[10px] font-mono uppercase text-[#71717a] font-semibold pb-2 border-b border-[#222222] mb-2.5">
                          RAW INPUTS
                        </div>
                        <ul className="space-y-2.5 text-xs font-sans text-[#d4d4d8] list-none p-0 m-0">
                          <li className="flex items-center gap-2">
                            <FileText className="w-3.5 h-3.5 text-white shrink-0" />
                            <span>Text</span>
                          </li>
                          <li className="flex items-center gap-2">
                            <Terminal className="w-3.5 h-3.5 text-white shrink-0" />
                            <span>Logs</span>
                          </li>
                          <li className="flex items-center gap-2">
                            <Command className="w-3.5 h-3.5 text-white shrink-0" />
                            <span>User Actions</span>
                          </li>
                          <li className="flex items-center gap-2">
                            <Database className="w-3.5 h-3.5 text-white shrink-0" />
                            <span>Metadata</span>
                          </li>
                        </ul>
                      </div>

                      {/* Connecting Line (Left to Center) */}
                      <div className="flex-1 h-[1px] bg-[#222222] relative">
                        <motion.div
                          animate={{ x: ["0%", "100%"] }}
                          transition={{ repeat: Infinity, duration: 1.8, ease: "linear" }}
                          className="w-2 h-[2px] bg-white"
                        />
                      </div>

                      {/* Center Core: Crux Logo */}
                      <div className="px-3 h-12 bg-[#111111] border border-[#222222] flex items-center justify-center relative flex-shrink-0 z-10">
                        <CruxLogo size={18} />
                        <div className="absolute -top-1 -right-1 w-2 h-2 bg-white" />
                      </div>

                      {/* Connecting Line (Center to Right) */}
                      <div className="flex-1 h-[1px] bg-[#222222] relative">
                        <motion.div
                          animate={{ x: ["0%", "100%"] }}
                          transition={{ repeat: Infinity, duration: 1.8, ease: "linear", delay: 0.5 }}
                          className="w-2 h-[2px] bg-white"
                        />
                      </div>

                      {/* Right: CONTEXTS Box */}
                      <div className="w-40 sm:w-44 p-3.5 bg-[#111111] border border-[#222222] rounded-none z-10">
                        <div className="text-[10px] font-mono uppercase text-[#71717a] font-semibold pb-2 border-b border-[#222222] mb-2.5">
                          CONTEXTS
                        </div>
                        <ul className="space-y-2.5 text-xs font-sans text-[#d4d4d8] list-none p-0 m-0">
                          <li className="flex items-center gap-2">
                            <Cpu className="w-3.5 h-3.5 text-white shrink-0" />
                            <span>Entities</span>
                          </li>
                          <li className="flex items-center gap-2">
                            <Compass className="w-3.5 h-3.5 text-white shrink-0" />
                            <span>Intent</span>
                          </li>
                          <li className="flex items-center gap-2">
                            <GitBranch className="w-3.5 h-3.5 text-white shrink-0" />
                            <span>Relationships</span>
                          </li>
                          <li className="flex items-center gap-2">
                            <Activity className="w-3.5 h-3.5 text-white shrink-0" />
                            <span>Sentiment</span>
                          </li>
                        </ul>
                      </div>
                    </div>

                    {/* Vertical Connecting Cable from Core down to Signals */}
                    <div className="w-[2px] h-10 bg-[#444444] relative">
                      <motion.div
                        animate={{ y: ["0%", "100%"] }}
                        transition={{ repeat: Infinity, duration: 1.2, ease: "linear" }}
                        className="w-[2px] h-3 bg-white"
                      />
                    </div>

                    {/* Bottom: SIGNALS Box with 3 Metric Icons */}
                    <div className="border border-[#222222] bg-[#111111] p-5 w-full max-w-sm rounded-none text-center relative">
                      <div className="text-[10px] font-mono uppercase text-[#888888] tracking-wider mb-3">
                        SIGNALS // KERNEL DISPATCH
                      </div>
                      <div className="flex items-center justify-center gap-4">
                        <div className="w-12 h-12 bg-[#000000] border border-[#222222] flex items-center justify-center text-white">
                          <BarChart3 className="w-5 h-5" />
                        </div>
                        <div className="w-12 h-12 bg-[#000000] border border-white flex items-center justify-center text-white">
                          <AlertTriangle className="w-5 h-5 text-white" />
                        </div>
                        <div className="w-12 h-12 bg-[#000000] border border-[#222222] flex items-center justify-center text-white">
                          <Bell className="w-5 h-5" />
                        </div>
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
                    className="w-full relative"
                  >
                    {/* Main Background Workflow Card */}
                    <div className="w-full bg-[#111111] border border-[#222222] p-6 rounded-none space-y-4">
                      {/* Fake Skeleton Code Lines */}
                      <div className="space-y-2">
                        <div className="w-3/4 h-3 bg-[#222222] rounded-none animate-pulse" />
                        <div className="w-1/2 h-3 bg-[#1e1e20] rounded-none" />
                        <div className="w-5/6 h-3 bg-[#222222] rounded-none" />
                      </div>

                      {/* Spinning Loader: Analyzing workflow */}
                      <div className="pt-4 flex items-center gap-3 text-xs font-mono text-[#888888]">
                        <motion.div
                          animate={{ rotate: 360 }}
                          transition={{ repeat: Infinity, duration: 2, ease: "linear" }}
                          className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-none"
                        />
                        <span>Analyzing workflow &amp; tree-sitter AST...</span>
                      </div>

                      <div className="pt-2 text-[11px] font-mono text-[#71717a]">
                        #project01 · CRDT State Synced
                      </div>
                    </div>

                    {/* Floating Foreground Task Card (Matching Frame 010) */}
                    <motion.div
                      initial={{ y: 20, opacity: 0 }}
                      animate={{ y: 0, opacity: 1 }}
                      transition={{ delay: 0.15 }}
                      className="absolute -bottom-6 -right-2 sm:-right-4 w-72 bg-[#111111] border border-[#222222] p-4 rounded-none"
                    >
                      <div className="flex items-center justify-between text-xs font-mono pb-2 border-b border-[#222222]">
                        <span className="text-white font-bold flex items-center gap-1.5">
                          <Check className="w-3.5 h-3.5 text-white stroke-[3]" />
                          <span>To-do 5</span>
                        </span>
                        <span className="text-white">● RUNNING</span>
                      </div>

                      <div className="mt-3 flex items-center gap-3 text-xs font-sans text-[#888888]">
                        <span className="flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5 text-[#888888]" />
                          <span className="text-white">Anna</span>
                        </span>
                        <span className="flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5 text-[#888888]" />
                          <span className="text-white">John</span>
                        </span>
                      </div>

                      {/* White Progress Bar */}
                      <div className="mt-4 w-full h-1.5 bg-[#222222] overflow-hidden">
                        <motion.div
                          initial={{ width: "20%" }}
                          animate={{ width: "100%" }}
                          transition={{ duration: 2.5, repeat: Infinity, ease: "easeInOut" }}
                          className="h-full bg-white"
                        />
                      </div>
                    </motion.div>
                  </motion.div>
                )}

                {activeTab === 2 && (
                  /* TAB 3: Actionable Output (Core connecting to Verified Summary / PDF) */
                  <motion.div
                    key="tab-2"
                    initial={{ opacity: 0, scale: 0.96 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.96 }}
                    transition={{ duration: 0.25 }}
                    className="w-full flex flex-col items-center gap-6"
                  >
                    {/* Top Core Box: Crux Logo */}
                    <div className="px-3 h-12 bg-[#111111] border border-[#222222] flex items-center justify-center relative">
                      <CruxLogo size={18} />
                      <div className="absolute -top-1 -right-1 w-2 h-2 bg-white" />
                    </div>

                    {/* Vertical Laser Line */}
                    <div className="w-[2px] h-12 bg-[#444444] relative">
                      <motion.div
                        animate={{ y: ["0%", "100%"] }}
                        transition={{ repeat: Infinity, duration: 1, ease: "linear" }}
                        className="w-[2px] h-4 bg-white"
                      />
                    </div>

                    {/* Output Document Card (Matching Frame 018) */}
                    <div className="w-full max-w-sm bg-[#111111] border border-[#222222] p-5 rounded-none flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="w-8 h-8 bg-[#000000] border border-[#222222] flex items-center justify-center text-white">
                          <FileCode2 className="w-4 h-4" />
                        </span>
                        <div>
                          <div className="text-xs font-semibold text-white font-sans">
                            Structured Summary
                          </div>
                          <div className="text-[10px] font-mono text-[#71717a]">
                            42 files synthesized · 0 compiler errors
                          </div>
                        </div>
                      </div>

                      <div className="px-2 py-0.5 border border-[#222222] bg-[#000000] text-[10px] font-mono text-white font-bold">
                        PDF
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 text-[11px] font-mono text-white">
                      <Check className="w-3.5 h-3.5 text-white stroke-[3]" />
                      <span>PIPELINE EXPORT VERIFIED</span>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </div>

        {/* 3 Secondary Capability Cards matching Video Recording */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-3 border border-[#222222] divide-y md:divide-y-0 md:divide-x divide-[#222222] bg-[#000000]">
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
