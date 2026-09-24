"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Code2, Sliders, CheckCircle2, ChevronRight, Sparkles, Terminal } from "lucide-react";
import Link from "next/link";

export default function AeyeChangelogSection() {
  const [selectedRelease, setSelectedRelease] = useState<number | null>(null);

  const releases = [
    {
      date: "SEP 23, 2026",
      version: "v0.1.0",
      title: "Native WebGPU & Bare-Metal Rust Kernel Launch",
      desc: "Architecture preview release of Crux. Sub-15ms typing latency, AST-CRDT real-time sync, and universal Apple Silicon / Linux binary builds.",
      tags: ["WebGPU", "Rust", "AST-CRDT"],
      commitSha: "commit 8f2a41d",
      renderIcon: () => (
        <svg viewBox="0 0 24 24" className="w-4 h-4 text-white" fill="none" stroke="currentColor" strokeWidth="1.8">
          <polyline points="16 18 22 12 16 6" />
          <polyline points="8 6 2 12 8 18" />
        </svg>
      ),
      notes: [
        "Implemented WebGPU direct compute shader pipeline for text glyph rasterization at 120 FPS.",
        "Integrated decentralized AST-CRDT replication protocol with sub-10ms peer convergence.",
        "Universal binary build targets for macOS Apple Silicon (arm64), Intel (x86_64), and Linux.",
        "Memory footprint benchmark: 38MB on initial cold boot with 10K-line file open.",
      ],
    },
    {
      date: "AUG 14, 2026",
      version: "v0.0.9",
      title: "Autonomous @CruxAI HyperTerminal Integration",
      desc: "Integrated multi-agent background executor. Terminal agents can autonomously invoke tests, stream stdout, and apply buffer AST transforms.",
      tags: ["Agentic AI", "Terminal", "Sandboxed Exec"],
      commitSha: "commit 3c79e02",
      renderIcon: () => (
        <svg viewBox="0 0 24 24" className="w-4 h-4 text-white" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path d="M4 7h16M4 12h16M4 17h10" />
          <rect x="17" y="15" width="4" height="4" fill="#0055FF" stroke="none" />
        </svg>
      ),
      notes: [
        "Added isolated OS namespace sandbox for executing `@CruxAI` compiler repairs.",
        "Real-time stdout streaming directly alongside editor gutter and tab panes.",
        "Multi-file diff preview buffer before executing destructive git operations.",
      ],
    },
    {
      date: "JUL 02, 2026",
      version: "v0.0.8",
      title: "Instant VS Code & Cursor Settings Importer",
      desc: "One-click migration pipeline for keybindings, themes, language server protocols (LSP), and extensions.",
      tags: ["Migration", "LSP", "Keybindings"],
      commitSha: "commit 1e99f5b",
      renderIcon: () => (
        <svg viewBox="0 0 24 24" className="w-4 h-4 text-white" fill="none" stroke="currentColor" strokeWidth="1.8">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ),
      notes: [
        "CLI command `crux migrate --from=vscode` automatically imports keybindings.json and settings.json.",
        "Zero-configuration LSP support for Rust (rust-analyzer), TypeScript/JavaScript (vtsls), Python (pyright), and Go (gopls).",
      ],
    },
  ];

  return (
    <section id="changelog" className="relative w-full border-b border-[#222222] bg-[#000000]">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[N.09/11]</span>
            <span className="text-[#888888]">— &gt;</span>
            <span className="text-[#888888] uppercase">CHANGELOGS</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            CONTINUOUS PRODUCT VELOCITY // ARCHITECTURE RELEASES
          </div>
        </div>

        {/* 2-Column Section Layout matching Screenshot 1 */}
        <div className="pt-12 grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-14 items-start">
          {/* Left Column: Headline, View All Button, Bottom Sub-info */}
          <div className="lg:col-span-5 flex flex-col justify-between h-full lg:pr-8 lg:border-r border-[#222222]">
            <div>
              <h2 className="text-3xl sm:text-5xl lg:text-[54px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
                We ship fast.
                <span className="block text-[#888888]">Always improve.</span>
              </h2>

              <div className="mt-8">
                <Link
                  href="#pricing"
                  className="inline-flex items-center gap-2.5 px-4 py-2.5 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none"
                >
                  <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                  VIEW ALL
                </Link>
              </div>
            </div>

            {/* Bottom Sub-info matching Screenshot 1 */}
            <div className="mt-16 pt-8 border-t border-[#1a1a1e]">
              <h4 className="text-white font-sans font-medium text-sm">
                Everything you need to get started.
              </h4>
              <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
                Explore features, and integrate smoothly, without unnecessary complexity.
              </p>
            </div>
          </div>

          {/* Right Column: Timeline rows with Date, Dotted Connector, Square Icon, and Release details */}
          <div className="lg:col-span-7 divide-y divide-dotted divide-[#222222]">
            {releases.map((item, idx) => {
              const isExpanded = selectedRelease === idx;

              return (
                <div
                  key={idx}
                  onClick={() => setSelectedRelease(isExpanded ? null : idx)}
                  className={`py-8 first:pt-0 last:pb-0 cursor-pointer group transition-none ${
                    isExpanded ? "bg-[#050507]" : ""
                  }`}
                >
                  {/* Top Row: Date + Dotted Connector Line + Square Icon Node */}
                  <div className="flex items-center gap-3 sm:gap-4 mb-4">
                    {/* Date */}
                    <div className="font-mono text-xs sm:text-[13px] text-[#888888] font-medium tracking-wider whitespace-nowrap">
                      {item.date}
                    </div>

                    {/* Dotted horizontal leader line connecting Date to Square Icon */}
                    <div className="flex-1 border-b border-dotted border-[#333333]" />

                    {/* Square Icon Node matching Screenshot 1 */}
                    <div className="w-8 h-8 border border-[#222222] bg-[#0c0c0e] flex items-center justify-center shrink-0 group-hover:border-[#0055FF] transition-none">
                      {item.renderIcon()}
                    </div>
                  </div>

                  {/* Release Content Block */}
                  <div className="pl-0 sm:pl-2">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <h3 className="text-xl sm:text-[22px] font-medium text-white font-sans tracking-tight transition-none group-hover:text-[#0055FF]">
                          {item.title}
                        </h3>
                        <div className="mt-1 text-[11px] font-mono text-[#71717a]">
                          Release <span className="text-[#0055FF] font-semibold">{item.version}</span> · {item.commitSha}
                        </div>
                      </div>
                    </div>

                    <p className="mt-3 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
                      {item.desc}
                    </p>

                    {/* Tags */}
                    <div className="mt-4 flex flex-wrap items-center gap-2">
                      {item.tags.map((tag, tidx) => (
                        <span
                          key={tidx}
                          className="px-2 py-0.5 border border-[#222222] bg-[#0d0d10] text-[10px] font-mono text-[#888888] rounded-none group-hover:border-[#333333] transition-none"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>

                    {/* Expandable Release Notes */}
                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.2 }}
                          className="mt-6 pt-4 border-t border-[#222222] space-y-2 overflow-hidden"
                        >
                          <div className="text-[11px] font-mono text-[#0055FF] uppercase font-bold">
                            // RELEASE MANIFEST HIGHLIGHTS
                          </div>
                          <ul className="space-y-1.5 m-0 p-0 list-none text-xs font-sans text-[#d4d4d8]">
                            {item.notes.map((note, nidx) => (
                              <li key={nidx} className="flex items-start gap-2">
                                <ChevronRight className="w-3.5 h-3.5 text-[#0055FF] shrink-0 mt-0.5" />
                                <span>{note}</span>
                              </li>
                            ))}
                          </ul>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
