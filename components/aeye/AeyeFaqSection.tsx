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
      question: "What is Crux IDE?",
      answer:
        "Crux is a collaborative code editor with a spatial canvas for exploring connected files, shared editing, and an integrated terminal. You can try the browser IDE or join the desktop waitlist.",
      tags: ["Collaborative IDE", "Code Editor"],
    },
    {
      num: "002",
      question: "Can teammates edit code together in real time?",
      answer:
        "Yes. Crux shows shared edits and collaborator presence in the workspace so teammates can work on the same codebase together.",
      tags: ["Real-Time Collaboration", "Pair Programming"],
    },
    {
      num: "003",
      question: "What is a spatial code canvas?",
      answer:
        "It is a visual workspace for arranging files and seeing their relationships while you work. The canvas helps keep related code in view across a multi-file task.",
      tags: ["Spatial Code Editor", "Codebase Context"],
    },
    {
      num: "004",
      question: "How is Crux different from Cursor or VS Code Live Share?",
      answer:
        "Crux focuses on shared editing and spatial codebase context in one IDE. Cursor focuses on AI-assisted editing, while VS Code Live Share adds collaboration sessions to VS Code. See our comparison page for a workflow-by-workflow guide.",
      tags: ["Cursor Alternative", "VS Code Live Share Alternative"],
    },
    {
      num: "005",
      question: "Can I use coding agents alongside Crux?",
      answer:
        "Crux includes a terminal for command-line workflows. Availability of a particular agent depends on its installation and the environment where you run Crux.",
      tags: ["Coding Agents", "Integrated Terminal"],
    },
    {
      num: "006",
      question: "Can I try Crux in my browser?",
      answer:
        "Yes. Open the browser IDE at codecrux.us/ide to explore the editor and spatial canvas. You can also join the waitlist for desktop access.",
      tags: ["Browser IDE", "Online Code Editor"],
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
              Clear answers about collaborative editing, the spatial canvas, and trying Crux.
            </p>
            <a href="/compare" className="inline-block mt-3 text-sm text-[#74a8ff] underline underline-offset-4">
              Compare Crux with Cursor, VS Code Live Share, and Zed →
            </a>
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
