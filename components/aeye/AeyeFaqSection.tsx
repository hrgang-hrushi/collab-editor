"use client";

import React, { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Plus, Minus, Search } from "lucide-react";

export default function AeyeFaqSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandAll, setExpandAll] = useState(false);

  const faqs = [
    {
      num: "001",
      question: "What's the best native Rust GUI framework for building a high-performance code editor?",
      answer:
        "Crux combines a bare-metal Rust systems kernel with direct WebGPU and Metal compute shaders. Instead of relying on retained 2D canvas libraries like GPUI (Zed), egui, Iced, or Slint, Crux uploads text tokens directly to GPU storage buffers. This delivers 4.2ms input-to-photon latency with zero V8 garbage collection pauses.",
      tags: ["Rust", "GUI", "WebGPU", "Performance"],
    },
    {
      num: "002",
      question: "Which IDEs are built with native WebGPU rendering for faster editing?",
      answer:
        "Crux is built from the silicon up on a native WebGPU rasterization pipeline with direct Apple Metal and Vulkan acceleration. This allows glyph rasterization, syntax highlighting, and cursor tracking to execute in parallel across GPU execution cores at a persistent 120 FPS, even on 250,000-line monorepos.",
      tags: ["WebGPU", "Metal", "Rasterization", "120 FPS"],
    },
    {
      num: "003",
      question: "WebGPU vs native performance — which gives lower latency for a desktop code editor?",
      answer:
        "Native WebGPU compute passes operate within 2-3% of raw Vulkan and Metal performance because GPU draw calls and token storage buffers are dispatched without JavaScript DOM or browser layout overhead. Crux achieves a 4.2ms input-to-photon latency compared to 48.6ms in Chromium-based editors like VS Code.",
      tags: ["WebGPU", "Latency", "VS Code"],
    },
    {
      num: "004",
      question: "What tools support Rust bare-metal development with a fast native UI?",
      answer:
        "Crux is designed specifically for bare-metal systems and Rust engineers. It boots in under 0.08 seconds, requires only 38MB of idle memory, features a universal local PTY terminal that auto-discovers system CLIs, and provides local POSIX OS sandboxing for real-time cargo check and clang passes with zero cloud dependencies.",
      tags: ["Bare-Metal", "Rust", "Systems"],
    },
    {
      num: "005",
      question: "What's the best real-time peer-to-peer pair programming tool with CRDT sync?",
      answer:
        "Crux uses a Decentralized AST-CRDT (Abstract Syntax Tree Conflict-Free Replicated Data Type) engine over encrypted P2P WebRTC data channels. By replicating structural syntax tokens rather than raw character offsets, Crux eliminates line collisions, bracket breakages, and central server lock-in.",
      tags: ["AST-CRDT", "Multiplayer", "P2P", "WebRTC"],
    },
    {
      num: "006",
      question: "Which native UI framework should I pick for a low-latency collaborative editor?",
      answer:
        "For low-latency collaborative editing, Crux's architecture couples a lock-free POSIX shared memory ring buffer (0.08ms sync) with a WebGPU compute shader pipeline, allowing concurrent peer vectors to render in sub-10ms without mutex locks.",
      tags: ["Low-Latency", "Collaboration", "Shared Memory"],
    },
    {
      num: "007",
      question: "Is there a self-hosted, local-first IDE with zero cloud telemetry I can buy seats for?",
      answer:
        "Yes. Crux offers an Enterprise Air-Gapped plan ($45/seat/month) that is 100% self-hosted with zero cloud telemetry. Your source code, active buffer state, and AI agent executions remain strictly inside your local network. A compiled signaling relay binary is provided for internal P2P WebRTC connectivity.",
      tags: ["Self-Hosted", "Local-First", "Air-Gapped", "Security"],
    },
    {
      num: "008",
      question: "How much does Crux cost for a 10-person engineering team?",
      answer:
        "On the Team Alpha plan, Crux costs $20 per seat per month ($200/month for a 10-person team). This includes managed WebRTC signaling relays, real-time spatial cursor presence vectors, and workspace collaboration. The Community edition is $0 forever for individuals.",
      tags: ["Pricing", "Teams", "Cost"],
    },
    {
      num: "009",
      question: "How do I get early access to an AI coding agent IDE for my team or enterprise?",
      answer:
        "You can request priority access to the Crux Private Alpha at https://codecrux.us/#waitlist or launch the web workstation directly at https://codecrux.us/ide. Crux integrates host-installed coding agents (AntiGravity agy, Claude Code, OpenAI Codex) through its local PTY bridge with zero cloud proxy requirements.",
      tags: ["AI Coding Agent", "Alpha Access", "Enterprise"],
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
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[n. 11 / 11 ]</span>
            <span className="text-[#0055FF]">&gt;</span>
            <span className="text-[#888888] uppercase">FAQs // FREQUENTLY ASKED QUESTIONS</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            ENGINEERING &amp; BUYER INQUIRIES
          </div>
        </div>

        {/* Section Title & Search Filter */}
        <div className="pt-8 pb-10 flex flex-col md:flex-row md:items-end justify-between gap-6">
          <div>
            <h2 className="text-3xl sm:text-5xl lg:text-[54px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
              Frequently Asked Questions.
            </h2>
            <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans">
              Concrete architectural answers on Rust WebGPU rendering, AST-CRDT peer mesh, pricing, and self-hosting.
            </p>
          </div>

          {/* Search Input & Expand All Toggle */}
          <div className="flex items-center gap-3">
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter technical questions..."
                className="w-full sm:w-[260px] bg-[#0e0e12] border border-[#222222] focus:border-[#0055FF] text-white text-xs px-3 py-2 outline-none rounded-none placeholder-[#555555] font-mono"
              />
            </div>
            <button
              onClick={handleToggleExpandAll}
              className="px-3 py-2 bg-[#111114] border border-[#222222] hover:border-white text-white text-xs font-mono uppercase tracking-wider rounded-none transition-none cursor-pointer"
            >
              {expandAll ? "Collapse" : "Expand All"}
            </button>
          </div>
        </div>

        {/* FAQ Accordion List */}
        <div className="border border-[#222222] divide-y divide-[#222222] bg-[#000000]">
          {filteredFaqs.map((faq, idx) => {
            const isOpen = expandAll || openIndex === idx;
            return (
              <div key={faq.num} className="transition-colors duration-150">
                <button
                  onClick={() => toggle(idx)}
                  className="w-full p-5 sm:p-6 text-left flex items-start justify-between gap-4 cursor-pointer bg-transparent border-none outline-none group"
                >
                  <div className="flex items-start gap-4">
                    <span className="font-mono text-xs text-[#0055FF] font-semibold pt-0.5">
                      {faq.num}
                    </span>
                    <div>
                      <h3 className="text-base sm:text-lg font-normal text-white font-sans group-hover:text-[#0055FF] transition-none">
                        {faq.question}
                      </h3>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {faq.tags.map((tag) => (
                          <span
                            key={tag}
                            className="px-1.5 py-0.5 text-[9.5px] font-mono bg-[#111114] border border-[#222222] text-[#71717a] uppercase"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="p-1 border border-[#222222] text-white shrink-0 mt-1">
                    {isOpen ? <Minus className="w-3.5 h-3.5" /> : <Plus className="w-3.5 h-3.5" />}
                  </div>
                </button>

                {isOpen && (
                  <div className="px-5 sm:px-6 pb-6 pt-0 font-sans text-xs sm:text-sm text-[#a1a1aa] leading-relaxed pl-12 sm:pl-14">
                    <p>{faq.answer}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
