"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronRight, ChevronUp, ChevronDown } from "lucide-react";

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
      notes: [
        "Implemented WebGPU direct compute shader pipeline for text glyph rasterization at 120 FPS.",
        "Integrated decentralized AST-CRDT replication protocol with sub-10ms peer convergence.",
        "Universal binary build targets for macOS Apple Silicon (arm64), Intel (x86_64), and Linux.",
        "Memory footprint benchmark: 85MB on initial cold boot with 10K-line file open.",
      ],
    },
    {
      date: "AUG 14, 2026",
      version: "v0.0.9",
      title: "Autonomous @CruxAI HyperTerminal Integration",
      desc: "Integrated multi-agent background executor. Terminal agents can autonomously invoke tests, stream stdout, and apply buffer AST transforms.",
      tags: ["Agentic AI", "Terminal", "Sandboxed Exec"],
      commitSha: "commit 3c79e02",
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
      notes: [
        "CLI command `crux migrate --from=vscode` automatically imports keybindings.json and settings.json.",
        "Zero-configuration LSP support for Rust (rust-analyzer), TypeScript/JavaScript (vtsls), Python (pyright), and Go (gopls).",
      ],
    },
  ];

  return (
    <section id="changelog" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
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
            <span className="text-[#0055FF] font-bold">[n. 09 / 11 ]</span>
            <span className="text-[#0055FF]">&gt;</span>
            <span className="text-[#888888]">Changelogs</span>
          </div>
          <div className="text-[11px] text-[#444444] pt-1 sm:pt-0">
            CONTINUOUS PRODUCT VELOCITY // ARCHITECTURE RELEASES
          </div>
        </motion.div>

        {/* Section Title & Subtitle */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
          className="pt-8 pb-4"
        >
          <h2 className="text-3xl sm:text-5xl lg:text-[54px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
            We ship fast.{" "}
            <span className="text-[#444444] block sm:inline">
              Hardware-grade velocity.
            </span>
          </h2>
          <p className="mt-4 text-xs sm:text-sm text-[#888888] font-sans max-w-xl">
            Tracking every commit, native binary optimization, and AST synchronization milestone.
          </p>
        </motion.div>

        {/* Changelog Timeline List */}
        <div className="mt-12 border border-[#222222] divide-y divide-[#222222] bg-[#000000]">
          {releases.map((item, idx) => (
            <div
              key={idx}
              onClick={() => setSelectedRelease(selectedRelease === idx ? null : idx)}
              className="p-8 flex flex-col md:flex-row md:items-start justify-between gap-6 transition-none group cursor-pointer bg-[#000000] hover:bg-[#111111] rounded-none"
            >
              {/* Left Date & Version */}
              <div className="md:w-56 flex-shrink-0">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-[#0055FF]" />
                  <span className="font-mono text-xs font-bold uppercase tracking-wider text-white">
                    {item.date}
                  </span>
                </div>
                <div className="mt-1.5 pl-4 font-mono text-[11px] text-[#888888]">
                  Release <span className="text-[#0055FF] font-semibold">{item.version}</span> · {item.commitSha}
                </div>
              </div>

              {/* Center Content */}
              <div className="flex-1">
                <h3 className="text-xl font-medium tracking-tight text-white font-sans transition-none">
                  {item.title}
                </h3>
                <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
                  {item.desc}
                </p>

                {/* Tags */}
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  {item.tags.map((tag, tidx) => (
                    <span
                      key={tidx}
                      className="px-2.5 py-0.5 border border-[#222222] bg-[#111111] text-[10px] font-mono text-[#888888] rounded-none group-hover:border-[#0055FF] group-hover:text-[#0055FF] transition-none"
                    >
                      {tag}
                    </span>
                  ))}
                </div>

                {/* Expanded Detailed Notes */}
                <AnimatePresence>
                  {selectedRelease === idx && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className="mt-6 pt-4 border-t border-[#222222] space-y-2 overflow-hidden"
                    >
                      <div className="text-[11px] font-mono text-[#0055FF] uppercase font-bold">
                        // RELEASE MANIFEST HIGHLIGHTS
                      </div>
                      <ul className="space-y-1.5 m-0 p-0 list-none text-xs font-sans text-[#d4d4d8]">
                        {item.notes.map((note, nidx) => (
                          <li key={nidx} className="flex items-start gap-2">
                            <ChevronRight className="w-3.5 h-3.5 text-[#0055FF] flex-shrink-0 mt-0.5" />
                            <span>{note}</span>
                          </li>
                        ))}
                      </ul>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Right Action */}
              <div className="flex md:items-center">
                <span className="font-mono text-xs text-white group-hover:text-[#0055FF] cursor-pointer flex items-center gap-1.5 transition-none">
                  <span>{selectedRelease === idx ? "Hide Notes" : "View Notes"}</span>
                  {selectedRelease === idx ? (
                    <ChevronUp className="w-3.5 h-3.5 text-[#0055FF]" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5 group-hover:text-[#0055FF]" />
                  )}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
