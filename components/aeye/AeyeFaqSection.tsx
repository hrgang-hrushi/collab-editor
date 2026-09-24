"use client";

import React, { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Plus, Minus } from "lucide-react";

export default function AeyeFaqSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandAll, setExpandAll] = useState(false);

  const faqs = [
    {
      num: "001",
      question: "How is Crux different from VS Code or Cursor?",
      answer:
        "Crux is built with native Rust and WebGPU rather than Electron and Chromium. This gives you instant cold boot (<0.08s), 85MB memory footprint instead of 650MB+, and true hardware-accelerated 120 FPS text rendering. It also features decentralized AST-CRDT real-time collaboration out of the box.",
      tags: ["Performance", "WebGPU", "Rust"],
    },
    {
      num: "002",
      question: "Can I migrate my VS Code keybindings, extensions, and themes?",
      answer:
        "Yes. Crux includes a 1-click migration importer that parses your VS Code and Cursor settings, keybindings, and snippet files. Language servers (LSP) run out of the box.",
      tags: ["Migration", "VS Code", "Extensions"],
    },
    {
      num: "003",
      question: "How does multiplayer collaboration work without a central server?",
      answer:
        "Crux uses an encrypted P2P WebRTC mesh network with conflict-free replicated abstract syntax trees (AST-CRDT). Edits converge deterministically with sub-10ms latency across global peers.",
      tags: ["Multiplayer", "P2P", "CRDT"],
    },
    {
      num: "004",
      question: "What is the @CruxAI agent and how is it sandboxed?",
      answer:
        "The @CruxAI agent runs directly alongside the HyperTerminal. It can run test suites, check linter diagnostics, execute bash commands, and propose multi-file atomic diffs inside an isolated OS namespace.",
      tags: ["AI", "Sandbox", "Terminal"],
    },
    {
      num: "005",
      question: "Does Crux work completely offline?",
      answer:
        "Yes. Crux is a native desktop binary with full local filesystem access. All buffer manipulation, syntax highlighting, and local model inference (via Ollama or Llama.cpp) operate with zero network dependencies.",
      tags: ["Offline", "Local LLM", "Security"],
    },
  ];

  const filteredFaqs = useMemo(() => {
    if (!searchQuery.trim()) return faqs;
    const q = searchQuery.toLowerCase();
    return faqs.filter(
      (f) =>
        f.question.toLowerCase().includes(q) ||
        f.answer.toLowerCase().includes(q) ||
        f.tags.some((t) => t.toLowerCase().includes(q))
    );
  }, [searchQuery]);

  const toggle = (idx: number) => {
    if (expandAll) setExpandAll(false);
    setOpenIndex(openIndex === idx ? null : idx);
  };

  const handleToggleExpandAll = () => {
    setExpandAll((prev) => !prev);
    setOpenIndex(null);
  };

  return (
    <section id="faqs" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
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
            <span className="text-[#0055FF] font-bold">[n. 11 / 11 ]</span>
            <span className="text-[#0055FF]">&gt;</span>
            <span className="text-[#888888]">FAQs</span>
          </div>
          <div className="text-[11px] text-[#444444] pt-1 sm:pt-0">
            FREQUENTLY ASKED QUESTIONS
          </div>
        </motion.div>

        {/* Section Title & Search Filter */}
        <div className="pt-8 pb-10 flex flex-col md:flex-row md:items-end justify-between gap-6">
          <div>
            <h2 className="text-3xl sm:text-5xl lg:text-[54px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
              We’ve got answers.
            </h2>
            <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans">
              Architecture, migration, offline execution, and peer sync questions.
            </p>
          </div>

          {/* Interactive Search + Expand Controls */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 w-full md:w-auto">
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="[SEARCH FAQS...]"
                className="w-full sm:w-64 px-3.5 py-2 border border-[#222222] bg-[#111111] text-xs font-mono text-white placeholder:text-[#444444] focus:outline-none focus:border-[#0055FF] rounded-none"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2.5 top-2.5 text-xs font-mono text-[#888888] hover:text-[#0055FF]"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            <button
              onClick={handleToggleExpandAll}
              className="px-3.5 py-2 border border-[#222222] bg-[#111111] hover:bg-[#0055FF] hover:border-[#0055FF] hover:text-white text-white text-xs font-mono uppercase tracking-wider transition-none cursor-pointer rounded-none whitespace-nowrap"
            >
              {expandAll ? "COLLAPSE ALL" : "EXPAND ALL"}
            </button>
          </div>
        </div>

        {/* FAQ Count Telemetry */}
        <div className="pb-4 flex items-center justify-between text-[11px] font-mono text-[#888888]">
          <span>MATCHING ENTRIES: {filteredFaqs.length} / {faqs.length}</span>
          <span className="text-[#0055FF] font-bold">STATUS // VERIFIED</span>
        </div>

        {/* Accordion List with Smooth Height Transition */}
        <div className="border border-[#222222] divide-y divide-[#222222] bg-[#000000]">
          {filteredFaqs.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-[#888888]">
              No questions found matching "{searchQuery}". Try searching for "Rust", "WebGPU", or "Offline".
            </div>
          ) : (
            filteredFaqs.map((faq, idx) => {
              const isOpen = expandAll || openIndex === idx;
              return (
                <div key={idx} className="transition-none bg-[#000000]">
                  <button
                    onClick={() => toggle(idx)}
                    className="w-full p-6 sm:p-8 flex items-center justify-between text-left cursor-pointer focus:outline-none hover:bg-[#111111] transition-none rounded-none"
                    aria-expanded={isOpen}
                  >
                    <div className="flex items-center gap-4 sm:gap-8">
                      <span
                        className={`font-mono text-xs font-semibold ${
                          isOpen ? "text-[#0055FF]" : "text-[#444444]"
                        }`}
                      >
                        {faq.num}
                      </span>
                      <span className="text-base sm:text-lg font-medium text-white font-sans">
                        {faq.question}
                      </span>
                    </div>
                    <div
                      className={`w-7 h-7 border flex items-center justify-center font-mono text-xs transition-none flex-shrink-0 rounded-none ${
                        isOpen
                          ? "bg-[#0055FF] text-white border-[#0055FF]"
                          : "bg-[#111111] text-white border-[#222222]"
                      }`}
                    >
                      {isOpen ? (
                        <Minus className="w-3.5 h-3.5 stroke-[2.5]" />
                      ) : (
                        <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
                      )}
                    </div>
                  </button>

                  <AnimatePresence initial={false}>
                    {isOpen && (
                      <motion.div
                        key="content"
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2, ease: "easeOut" }}
                        className="overflow-hidden bg-[#000000]"
                      >
                        <div className="px-6 sm:px-8 pb-8 pt-0">
                          <div className="pl-8 sm:pl-14 border-l-2 border-[#0055FF] text-xs sm:text-sm text-[#d4d4d8] font-sans leading-relaxed">
                            {faq.answer}
                            <div className="mt-3 flex items-center gap-2">
                              {faq.tags.map((t, tidx) => (
                                <span
                                  key={tidx}
                                  className="px-2 py-0.5 border border-[#222222] bg-[#111111] text-[10px] font-mono text-[#0055FF]"
                                >
                                  #{t}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })
          )}
        </div>
      </div>
    </section>
  );
}
