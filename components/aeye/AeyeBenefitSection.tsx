"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import { Cpu, Workflow, Gauge } from "lucide-react";

export default function AeyeBenefitSection() {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

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
          className="flex items-center gap-3 pb-6 text-xs font-mono"
        >
          <span className="text-[#0055FF] font-semibold tracking-wider">[N.01/11]</span>
          <span className="w-8 h-[1px] bg-[#222222]" />
          <span className="text-[#0055FF] font-bold">&gt;</span>
          <span className="text-[#888888] uppercase tracking-wider font-semibold">KEY VALUE</span>
          <div className="flex-1 h-[1px] bg-[#222222] ml-2" />
        </motion.div>

        {/* Section Headline & GET STARTED Action */}
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
            className="flex-shrink-0"
          >
            <a
              href="/?app=true"
              className="px-6 py-3.5 bg-[#0055FF] hover:bg-[#0044CC] text-white border border-[#0055FF] text-xs font-mono uppercase tracking-wider flex items-center gap-3 transition-none cursor-pointer rounded-none font-bold group"
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
                className={`p-8 sm:p-10 flex flex-col justify-between min-h-[520px] transition-colors duration-200 relative cursor-pointer rounded-none border ${
                  isHovered ? "border-[#0055FF] bg-[#0055FF]/5" : "border-[#222222] bg-[#000000]"
                }`}
              >
                {/* Top Row: Serial Number & Status Indicator */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`w-1.5 h-1.5 transition-colors duration-200 rounded-none ${
                        isHovered ? "bg-[#0055FF]" : "bg-[#333333]"
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

                {/* Center Wireframe-to-Pixel Hover Transition (Exact match to reference recording) */}
                <div className="flex-1 flex items-center justify-center my-6 relative min-h-[240px] select-none">
                  {/* Subtle 1px background grid corner ticks */}
                  <span
                    className={`absolute top-2 left-2 font-mono text-[10px] leading-none transition-colors duration-200 select-none ${
                      isHovered ? "text-[#0055FF]" : "text-[#222222]"
                    }`}
                  >
                    +
                  </span>
                  <span
                    className={`absolute top-2 right-2 font-mono text-[10px] leading-none transition-colors duration-200 select-none ${
                      isHovered ? "text-[#0055FF]" : "text-[#222222]"
                    }`}
                  >
                    +
                  </span>
                  <span
                    className={`absolute bottom-2 left-2 font-mono text-[10px] leading-none transition-colors duration-200 select-none ${
                      isHovered ? "text-[#0055FF]" : "text-[#222222]"
                    }`}
                  >
                    +
                  </span>
                  <span
                    className={`absolute bottom-2 right-2 font-mono text-[10px] leading-none transition-colors duration-200 select-none ${
                      isHovered ? "text-[#0055FF]" : "text-[#222222]"
                    }`}
                  >
                    +
                  </span>

                  {/* Line illustration (default wireframe, stays subtly visible under pixel overlay) */}
                  <img
                    src={card.iconLine}
                    alt={card.title}
                    className={`w-48 h-48 object-contain filter invert transition-all duration-300 pointer-events-none ${
                      isHovered ? "opacity-35 scale-100" : "opacity-90 scale-100"
                    }`}
                  />

                  {/* Full Electric Blue Pixel Art Graphic (Hover State) */}
                  <img
                    src={card.iconPixel}
                    alt={`${card.title} Pixel`}
                    className={`w-48 h-48 object-contain absolute transition-all duration-300 pointer-events-none ${
                      isHovered
                        ? "opacity-100 scale-100"
                        : "opacity-0 scale-95"
                    }`}
                  />
                </div>

                {/* Bottom Content: Title & Tag */}
                <div className="pt-4 border-t border-[#222222]">
                  <h3 className="text-2xl font-normal tracking-tight text-white font-sans">
                    {card.title}
                  </h3>
                  <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed min-h-[40px]">
                    {card.description}
                  </p>

                  <div className="mt-6">
                    <span
                      className={`px-3 py-1.5 bg-[#111111] border text-[10px] sm:text-[11px] font-mono uppercase tracking-wider transition-colors duration-200 rounded-none inline-flex items-center gap-1.5 ${
                        isHovered
                          ? "border-[#0055FF] text-[#0055FF]"
                          : "border-[#222222] text-[#888888]"
                      }`}
                    >
                      <BadgeIcon className="w-3 h-3 stroke-[2]" />
                      <span>{card.tag}</span>
                    </span>
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
