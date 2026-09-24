"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronRight, ChevronUp, ArrowRight } from "lucide-react";

export default function AeyeBlogSection() {
  const [expandedArticle, setExpandedArticle] = useState<number | null>(null);

  const articles = [
    {
      category: "Architecture",
      date: "SEP 18, 2026",
      title: "Why We Abandoned Electron for Bare-Metal Rust",
      excerpt:
        "The physics of 120 FPS text editing. How direct WebGPU rendering eliminates input lag, garbage collection stutter, and memory bloat.",
      imgSrc:
        "https://framerusercontent.com/images/2mTa20dlvcvXtGym8SYd5W4QWg.webp?width=790&height=480",
      keyTakeaways: [
        "V8 garbage collection sweeps introduce unpredictable 16-50ms frame drops during rapid typing.",
        "Chromium DOM rendering creates 300MB+ memory baseline before a single file buffer is parsed.",
        "WebGPU compute shaders enable parallel font atlas glyph rendering directly on the GPU pipeline.",
      ],
    },
    {
      category: "Distributed",
      date: "AUG 29, 2026",
      title: "Decentralized AST-CRDT: Beyond Operational Transformation",
      excerpt:
        "Why linear text OT breaks code semantics. Implementing conflict-free abstract syntax tree replication over WebRTC mesh networks.",
      imgSrc:
        "https://framerusercontent.com/images/19Muz3bdQfgheUsNSwbsCl2dKjs.webp?width=790&height=480",
      keyTakeaways: [
        "Linear character offsets fail when concurrent refactorings alter syntax node parentage.",
        "AST-CRDT preserves grammar hierarchy, preventing syntax corruption during multi-peer edits.",
        "Sub-10ms peer sync achieved via encrypted WebRTC data channels with DTLS 1.3 encryption.",
      ],
    },
    {
      category: "Agentic AI",
      date: "JUL 12, 2026",
      title: "The Agentic Terminal: Sandboxed Execution at the Kernel",
      excerpt:
        "How @CruxAI navigates repository topologies, runs compiler passes in background namespaces, and verifies edits before committing.",
      imgSrc:
        "https://framerusercontent.com/images/WS0m1XNzTirshd6yjZiVGu1ehnA.webp?width=790&height=480",
      keyTakeaways: [
        "OS-level namespace isolation prevents untrusted scripts from altering host environment.",
        "Multi-agent loop compiles, checks linter diagnostics, and auto-repairs syntax errors in memory.",
        "Atomic delta commit protocol enables 1-click rollback of any multi-file AI transformation.",
      ],
    },
  ];

  return (
    <section id="blog" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
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
            <span className="text-[#0055FF] font-bold">[n. 10 / 11 ]</span>
            <span className="text-[#0055FF]">&gt;</span>
            <span className="text-[#888888]">Engineering Essays</span>
          </div>
          <div className="text-[11px] text-[#444444] pt-1 sm:pt-0">
            ENGINEERING ESSAYS &amp; ARCHITECTURAL PATTERNS
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
            Deep engineering.{" "}
            <span className="text-[#444444] block sm:inline">
              Real-world silicon.
            </span>
          </h2>
        </motion.div>

        {/* 3 Blog Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 border border-[#222222] divide-y md:divide-y-0 md:divide-x divide-[#222222] bg-[#000000]">
          {articles.map((post, idx) => {
            const isExpanded = expandedArticle === idx;
            return (
              <article
                key={idx}
                onClick={() => setExpandedArticle(isExpanded ? null : idx)}
                className="p-8 sm:p-9 flex flex-col justify-between group bg-[#000000] hover:bg-[#111111] transition-none cursor-pointer rounded-none"
              >
                <div>
                  {/* Image */}
                  <div className="border border-[#222222] bg-[#111111] aspect-[16/10] overflow-hidden relative mb-6 rounded-none group-hover:border-[#0055FF] transition-none">
                    <img
                      src={post.imgSrc}
                      alt={post.title}
                      className="w-full h-full object-cover rounded-none grayscale contrast-125 opacity-80 group-hover:opacity-100 transition-none"
                    />
                    <div className="absolute top-3 left-3 px-2.5 py-0.5 bg-[#000000] border border-[#222222] text-[10px] font-mono font-semibold text-white group-hover:border-[#0055FF] group-hover:text-[#0055FF] rounded-none transition-none">
                      {post.category}
                    </div>
                  </div>

                  <div className="text-[11px] font-mono text-[#0055FF] font-semibold">
                    // {post.date}
                  </div>

                  <h3 className="mt-3 text-xl font-medium tracking-tight text-white font-sans leading-snug group-hover:text-white transition-none">
                    {post.title}
                  </h3>

                  <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
                    {post.excerpt}
                  </p>

                  {/* Expanded Key Takeaways */}
                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                        className="mt-6 pt-4 border-t border-[#222222] space-y-2 overflow-hidden"
                      >
                        <div className="text-[10px] font-mono text-[#0055FF] uppercase font-bold">
                          KEY ARCHITECTURAL TAKEAWAYS
                        </div>
                        <ul className="space-y-1.5 m-0 p-0 list-none text-xs font-sans text-[#d4d4d8]">
                          {post.keyTakeaways.map((takeaway, tidx) => (
                            <li key={tidx} className="flex items-start gap-2">
                              <ChevronRight className="w-3.5 h-3.5 text-[#0055FF] flex-shrink-0 mt-0.5" />
                              <span>{takeaway}</span>
                            </li>
                          ))}
                        </ul>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>

                {/* Action */}
                <div className="mt-8 pt-4 border-t border-[#222222] flex items-center justify-between text-xs font-mono text-white group-hover:text-[#0055FF] transition-none">
                  <span className="font-semibold uppercase tracking-wider">
                    {isExpanded ? "hide details" : "read abstract"}
                  </span>
                  {isExpanded ? (
                    <ChevronUp className="w-3.5 h-3.5 text-[#0055FF]" />
                  ) : (
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 group-hover:text-[#0055FF] transition-transform" />
                  )}
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
