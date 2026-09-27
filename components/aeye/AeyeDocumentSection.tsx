"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import { ArrowUpRight } from "lucide-react";
import Link from "next/link";

export default function AeyeDocumentSection() {
  const [activeCard, setActiveCard] = useState<number>(1); // Card 2 is active by default as in screenshot

  const docs = [
    {
      serial: "// 001",
      title: "Getting Started",
      tags: ["SETUP", "QUICK START", "BASICS"],
      preview: {
        heading: "Inputs & Context",
        subheading: "What is an input?",
        desc: "An input is any data passed into an AI workflow at runtime: text, structured JSON, file content, API responses, or user-submitted forms. Inputs are the raw materials your workflow acts on.",
        bullets: [
          "1. Text & Prompt — Natural language strings passed directly to the AI step.",
          "2. Structured Data — JSON objects, CSV rows, or key-value pairs.",
          "3. File & Media — PDFs, images, and documents uploaded directly.",
        ],
      },
    },
    {
      serial: "// 002",
      title: "Core Concepts",
      tags: ["USAGE", "WORKFLOW", "ADVANCED"],
      preview: {
        heading: "Custom Workflows",
        subheading: "Anatomy of a workflow",
        desc: "A custom workflow is a directed sequence of steps. Each step takes an input, does something — call an AI model, transform data, hit an API — and passes its output to the next step via context.",
        bullets: [
          "1. Trigger — Defines when the workflow runs: an API call, webhook event, or schedule.",
          "2. Steps — The logic of your workflow: chain AI steps, conditions (if / else), and loops.",
          "3. Output — What the workflow returns: a structured response or side effect.",
        ],
      },
    },
  ];

  return (
    <section id="document" className="relative w-full border-b border-[#222222] bg-[#000000]">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[N.06/11]</span>
            <span className="text-[#888888]">— &gt;</span>
            <span className="text-[#888888] uppercase">DOCUMENT</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            TECHNICAL DOCUMENTATION &amp; GUIDES
          </div>
        </div>

        {/* 2-Column Section Layout matching Frame 042 */}
        <div className="pt-12 grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-14 items-start">
          {/* Left Column: Title, Learn More Button, and Subtitle */}
          <div className="lg:col-span-5 flex flex-col justify-between h-full">
            <div>
              <h2 className="text-3xl sm:text-5xl lg:text-[52px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
                Everything documented.
                <span className="block text-[#888888]">Clear and practical.</span>
              </h2>

              <div className="mt-8">
                <Link
                  href="#pricing"
                  className="inline-flex items-center gap-2.5 px-4 py-2.5 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none"
                >
                  <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                  LEARN MORE
                </Link>
              </div>
            </div>

            <div className="mt-16 pt-8 border-t border-[#1a1a1e]">
              <h4 className="text-white font-sans font-medium text-sm">
                Everything you need to get started.
              </h4>
              <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
                Explore features, and integrate smoothly, without unnecessary complexity.
              </p>
            </div>
          </div>

          {/* Right Column: 2 Side-by-Side Doc Cards matching Frame 042 */}
          <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6">
            {docs.map((doc, idx) => {
              const isActive = activeCard === idx;
              return (
                <div
                  key={idx}
                  onClick={() => setActiveCard(idx)}
                  className={`border flex flex-col justify-between transition-none cursor-pointer relative bg-[#000000] ${
                    isActive ? "border-[#0055FF]" : "border-[#222222] hover:border-[#444444]"
                  }`}
                >
                  {/* Card Content Top */}
                  <div className="p-6">
                    <h3
                      className={`text-2xl font-medium font-sans transition-none ${
                        isActive ? "text-[#0055FF]" : "text-white"
                      }`}
                    >
                      {doc.title}
                    </h3>

                    {/* Tags */}
                    <div className="mt-4 flex flex-wrap gap-2 text-[10px] font-mono tracking-wider text-[#888888]">
                      {doc.tags.map((tag, tIdx) => (
                        <span key={tIdx} className="uppercase">
                          {tag}
                        </span>
                      ))}
                    </div>

                    <div className="mt-6 font-mono text-xs text-[#666666]">
                      {doc.serial}
                    </div>

                    {/* Doc Blueprint Document Sheet Preview matching screenshot */}
                    <div className="mt-4 border border-[#222222] bg-[#0c0c0e] p-4 text-[10px] font-mono text-[#a1a1aa] leading-relaxed select-none overflow-hidden h-[220px]">
                      <div className="text-[11px] font-bold text-white mb-1">
                        {doc.preview.heading}
                      </div>
                      <div className="text-[10px] text-[#0055FF] mb-2">
                        {doc.preview.subheading}
                      </div>
                      <p className="text-[#888888] line-clamp-3 mb-3 text-[9px]">
                        {doc.preview.desc}
                      </p>
                      <div className="space-y-1 text-[8.5px] text-[#71717a] border-t border-[#1a1a1e] pt-2">
                        {doc.preview.bullets.map((b, bIdx) => (
                          <div key={bIdx} className="truncate">
                            {b}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Card Bottom: View Link */}
                  <div className="px-6 py-4 border-t border-[#222222] flex items-center justify-between text-xs font-mono text-white">
                    <ArrowUpRight
                      className={`w-4 h-4 ${isActive ? "text-[#0055FF]" : "text-white"}`}
                    />
                    <span className={`tracking-wider ${isActive ? "text-[#0055FF] font-bold" : ""}`}>
                      VIEW
                    </span>
                  </div>

                  {/* Active Bottom Indicator Line matching screenshot */}
                  {isActive && (
                    <div className="absolute bottom-0 left-0 right-0 h-1 bg-[#0055FF]" />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
