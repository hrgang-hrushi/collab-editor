"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Cpu, Workflow, Gauge, ArrowRight, Terminal, Check } from "lucide-react";

interface AeyeBenefitSectionProps {
  onOpenTour?: (stepIndex?: number) => void;
}

export default function AeyeBenefitSection({ onOpenTour }: AeyeBenefitSectionProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [activeBlueprintIdx, setActiveBlueprintIdx] = useState<number | null>(0);

  const cards = [
    {
      serial: "// 001",
      title: "Smart Processing",
      description:
        "Automatically analyze inputs and transform them into structured, usable outputs in real time.",
      tag: "LESS WORK, MORE OUTPUT",
      badgeIcon: Cpu,
      iconLine: "/icons/card1_line.png",
      iconPixel: "/icons/card1_pixel.png",
      blueprint: {
        engine: "Rust SIMD Vector Parser",
        latency: "0.14ms input-to-AST",
        spec: "Direct token streaming into WebGPU buffers. Bypasses JavaScript V8 serialization overhead completely.",
      },
    },
    {
      serial: "// 002",
      title: "Adaptive Workflows",
      description:
        "Create flexible workflows that adapt to your data, context, and user intent — without rigid rules or manual setup.",
      tag: "AI HANDLES THE HEAVY LIFTING",
      badgeIcon: Workflow,
      iconLine: "/icons/card2_line.png",
      iconPixel: "/icons/card2_pixel.png",
      blueprint: {
        engine: "Decentralized AST-CRDT Mesh",
        latency: "Sub-10ms peer sync",
        spec: "P2P WebRTC data channels with lock-free vector clocks. 0-collision merge guarantees across remote teams.",
      },
    },
    {
      serial: "// 003",
      title: "Better Results",
      description:
        "Generate consistent, high-quality results that you can use, refine, and scale across your product.",
      tag: "PLUG IN, GET RESULTS",
      badgeIcon: Gauge,
      iconLine: "/icons/card3_line.png",
      iconPixel: "/icons/card3_pixel.png",
      blueprint: {
        engine: "@CruxAI Autonomous Kernel",
        latency: "0ms cloud latency",
        spec: "Isolated host POSIX OS namespace for cargo check, clang compiles, and multi-file atomic git diffs.",
      },
    },
  ];

  return (
    <section id="benefit" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Line */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          className="flex items-center justify-between pb-6 text-xs font-mono"
        >
          <div className="flex items-center gap-3">
            <span className="text-[#0055FF] font-semibold tracking-wider">[N.01/11]</span>
            <span className="w-8 h-[1px] bg-[#222222]" />
            <span className="text-[#0055FF] font-bold">&gt;</span>
            <span className="text-[#888888] uppercase tracking-wider font-semibold">KEY VALUE</span>
          </div>
          {onOpenTour && (
            <button
              onClick={() => onOpenTour(0)}
              className="px-2.5 py-1 bg-[#111114] hover:bg-[#1a1a24] border border-[#0055FF]/60 hover:border-[#0055FF] text-white text-[11px] font-mono uppercase tracking-wider flex items-center gap-1.5 cursor-pointer rounded-none"
            >
              <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
              <span>EXPLORE VIA TOUR</span>
            </button>
          )}
        </motion.div>

        {/* Section Headline & Actions */}
        <div className="pt-6 pb-14 flex flex-col md:flex-row md:items-end justify-between gap-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-40px" }}
            transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
          >
            <h2 className="text-4xl sm:text-5xl lg:text-[56px] font-normal tracking-[-0.05em] text-white font-sans leading-[1.08]">
              Less manual work.<br />
              More intelligent execution.
            </h2>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-40px" }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="flex-shrink-0 flex items-center gap-3 flex-wrap"
          >
            <a
              href="/ide"
              className="px-5 py-3.5 bg-[#000000] hover:bg-white hover:text-black text-white border border-white text-xs font-mono uppercase tracking-wider flex items-center gap-2 transition-none cursor-pointer rounded-none font-bold no-underline"
            >
              <span>LAUNCH WEB IDE ↵</span>
            </a>
            <a
              href="#waitlist"
              className="px-6 py-3.5 bg-[#0055FF] hover:bg-[#0044CC] text-white border border-[#0055FF] text-xs font-mono uppercase tracking-wider flex items-center gap-3 transition-none cursor-pointer rounded-none font-bold no-underline group"
            >
              <span className="w-2.5 h-2.5 bg-white inline-block transition-none" />
              <span>GET STARTED</span>
            </a>
          </motion.div>
        </div>

        {/* 3 Value Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {cards.map((card, idx) => {
            const isHovered = hoveredIndex === idx;
            const isSelected = activeBlueprintIdx === idx;
            const BadgeIcon = card.badgeIcon;
            return (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 25 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-30px" }}
                transition={{ duration: 0.5, delay: idx * 0.1 }}
                onMouseEnter={() => setHoveredIndex(idx)}
                onMouseLeave={() => setHoveredIndex(null)}
                onClick={() => setActiveBlueprintIdx(idx)}
                className={`p-6 sm:p-8 flex flex-col justify-between min-h-[480px] transition-colors duration-200 relative cursor-pointer rounded-none border ${
                  isSelected || isHovered ? "border-[#0055FF] bg-[#0055FF]/5" : "border-[#222222] bg-[#000000]"
                }`}
              >
                {/* Top Row: Serial Number & Status Indicator */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`w-1.5 h-1.5 transition-colors duration-200 rounded-none ${
                        isSelected || isHovered ? "bg-[#0055FF]" : "bg-[#333333]"
                      }`}
                    />
                    <span className="font-mono text-[10px] text-[#555555] uppercase">
                      MODULE_{idx + 1}
                    </span>
                  </div>
                  <span className="font-mono text-xs text-[#0055FF] font-bold">
                    {card.serial}
                  </span>
                </div>

                {/* Center Wireframe-to-Pixel Hover Transition */}
                <div className="flex-1 flex items-center justify-center my-4 relative min-h-[180px] select-none">
                  <span
                    className={`absolute top-2 left-2 font-mono text-[10px] leading-none transition-colors duration-200 select-none ${
                      isSelected || isHovered ? "text-[#0055FF]" : "text-[#222222]"
                    }`}
                  >
                    +
                  </span>
                  <span
                    className={`absolute top-2 right-2 font-mono text-[10px] leading-none transition-colors duration-200 select-none ${
                      isSelected || isHovered ? "text-[#0055FF]" : "text-[#222222]"
                    }`}
                  >
                    +
                  </span>
                  <span
                    className={`absolute bottom-2 left-2 font-mono text-[10px] leading-none transition-colors duration-200 select-none ${
                      isSelected || isHovered ? "text-[#0055FF]" : "text-[#222222]"
                    }`}
                  >
                    +
                  </span>
                  <span
                    className={`absolute bottom-2 right-2 font-mono text-[10px] leading-none transition-colors duration-200 select-none ${
                      isSelected || isHovered ? "text-[#0055FF]" : "text-[#222222]"
                    }`}
                  >
                    +
                  </span>

                  <div className="relative w-36 h-36 flex items-center justify-center">
                    <img
                      src={card.iconLine}
                      alt={card.title}
                      className={`absolute inset-0 w-full h-full object-contain filter invert transition-opacity duration-300 pointer-events-none ${
                        isHovered || isSelected ? "opacity-0" : "opacity-80"
                      }`}
                    />
                    <img
                      src={card.iconPixel}
                      alt={card.title}
                      className={`absolute inset-0 w-full h-full object-contain filter invert transition-opacity duration-300 pointer-events-none ${
                        isHovered || isSelected ? "opacity-100 scale-105" : "opacity-0 scale-95"
                      }`}
                    />
                  </div>
                </div>

                {/* Bottom Content Area */}
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <BadgeIcon className="w-3.5 h-3.5 text-[#0055FF]" />
                    <span className="text-[10px] font-mono tracking-wider text-[#71717a] uppercase font-semibold">
                      {card.tag}
                    </span>
                  </div>

                  <h3 className="text-xl sm:text-2xl font-normal text-white font-sans tracking-tight mb-2">
                    {card.title}
                  </h3>

                  <p className="text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
                    {card.description}
                  </p>

                  {/* Expandable Architecture Blueprint Inspector */}
                  <div className="mt-4 pt-3 border-t border-[#222222] font-mono text-[10.5px]">
                    <div className="flex items-center justify-between text-[#71717a]">
                      <span className="text-white font-semibold">{card.blueprint.engine}</span>
                      <span className="text-[#0055FF]">{card.blueprint.latency}</span>
                    </div>
                    <p className="mt-1 text-[#666666] text-[10px] leading-relaxed">
                      {card.blueprint.spec}
                    </p>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
