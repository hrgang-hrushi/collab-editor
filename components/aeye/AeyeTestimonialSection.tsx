"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import { ChevronLeft, ChevronRight } from "lucide-react";

export default function AeyeTestimonialSection() {
  const [currentIndex, setCurrentIndex] = useState(0);

  const testimonials = [
    {
      name: "Jaron Smith",
      handle: "@jaronsmith8802",
      role: "Staff Infrastructure Engineer",
      avatar: "https://framerusercontent.com/images/uPisnCzbMF4Eo0nQfMhIBrPUxQ.png?width=192&height=192",
      quote:
        "Crux makes VS Code feel like an antiquated web browser. Keystroke latency is sub-15ms, and the AST-CRDT pair programming has completely replaced screen-share lag.",
      timestamp: "12:08 AM - Dec 12, 2025",
    },
    {
      name: "Taylor Reed",
      handle: "@taylor_reed4214",
      role: "DevOps Lead",
      avatar: "https://framerusercontent.com/images/1kXU3rjhScV9xir02qUMAV1mWE.png?width=96&height=96",
      quote:
        "The @CruxAI agent in the HyperTerminal refactored our entire Rust async pipeline across 42 files while we watched live in the buffer. Zero merge conflicts.",
      timestamp: "9:03 PM - Jul 08, 2026",
    },
    {
      name: "Emily Carter",
      handle: "@emilycarter_ui",
      role: "Systems Architect",
      avatar: "https://framerusercontent.com/images/wVqHxfFshrHoLSPLLa99DTZLetc.png?width=128&height=128",
      quote:
        "We replaced our sluggish Electron setups with native Crux. My MacBook battery now lasts a full 12-hour coding marathon. Crux is pure mechanical perfection.",
      timestamp: "3:45 PM - Apr 19, 2026",
    },
    {
      name: "Ryan Mercer",
      handle: "@ryan_mercer",
      role: "Full-Stack Developer",
      avatar: "https://framerusercontent.com/images/vkyTOqT6hnr3j3e4DIPRMm6c.png?width=237&height=237",
      quote:
        "The conflict-free AST multiplayer sync is wizardry. Three of us were hacking on the exact same parser module simultaneously with zero locks.",
      timestamp: "10:14 AM - May 02, 2026",
    },
    {
      name: "Marcus Webb",
      handle: "@marcuswebb_dev",
      role: "VP Engineering",
      avatar: "https://framerusercontent.com/images/5zsAOZHi3SGre4j8VBkCqJfKk.png?width=237&height=237",
      quote:
        "Replaced our fragmented team editor setup with Crux. Sub-10ms peer synchronization, zero split-brain AST states, and native WebGPU rendering.",
      timestamp: "4:17 PM - MAR 14, 2025",
    },
    {
      name: "Priya Nair",
      handle: "@priya_builds",
      role: "Founding Engineer",
      avatar: "https://framerusercontent.com/images/hvmRpjdg9l4E8TWrx1Sne7iiE.png?width=800&height=1066",
      quote:
        "Crux boots in 0.08s and uses 85MB of RAM. The mechanical tactile feedback and instant keyboard responsiveness make it impossible to go back to Electron.",
      timestamp: "11:42 AM - Feb 08, 2025",
    },
  ];

  const handlePrev = () => {
    setCurrentIndex((prev) => (prev === 0 ? testimonials.length - 1 : prev - 1));
  };

  const handleNext = () => {
    setCurrentIndex((prev) => (prev === testimonials.length - 1 ? 0 : prev + 1));
  };

  return (
    <section id="testimonials" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
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
            <span className="text-[#0055FF] font-bold">[n. 07 / 11 ]</span>
            <span className="text-[#0055FF]">&gt;</span>
            <span className="text-[#888888]">Testimonial</span>
          </div>
          <div className="flex items-center gap-3 pt-2 sm:pt-0">
            {/* Brutalist Chevron Controls */}
            <button
              onClick={handlePrev}
              className="w-8 h-8 rounded-none border border-[#222222] bg-[#000000] text-white hover:bg-white hover:text-black hover:border-white transition-none flex items-center justify-center cursor-pointer"
              aria-label="Previous testimonial"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-xs font-mono text-[#888888]">
              0{currentIndex + 1} / 0{testimonials.length}
            </span>
            <button
              onClick={handleNext}
              className="w-8 h-8 rounded-none border border-[#222222] bg-[#000000] text-white hover:bg-white hover:text-black hover:border-white transition-none flex items-center justify-center cursor-pointer"
              aria-label="Next testimonial"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
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
            Less talk, more shipping.{" "}
            <span className="text-[#444444] block sm:inline">
              See what they are saying.
            </span>
          </h2>
        </motion.div>

        {/* Testimonials Deck */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {testimonials.map((item, idx) => {
            const isFeatured = idx === currentIndex;
            return (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-20px" }}
                transition={{ duration: 0.4, delay: (idx % 3) * 0.1 }}
                onClick={() => setCurrentIndex(idx)}
                className={`p-8 border transition-none cursor-pointer flex flex-col justify-between min-h-[320px] rounded-none ${
                  isFeatured
                    ? "border-[#0055FF] bg-[#0055FF]/5"
                    : "border-[#222222] bg-[#000000] hover:bg-[#111111]"
                }`}
              >
                <div>
                  {/* User Header */}
                  <div className="flex items-center gap-3">
                    <img
                      src={item.avatar}
                      alt={item.name}
                      className="w-10 h-10 border border-[#222222] object-cover rounded-none grayscale contrast-125"
                    />
                    <div>
                      <div className="text-sm font-semibold text-white font-sans">
                        {item.name}
                      </div>
                      <div className="text-[11px] text-[#888888] font-mono">
                        {item.handle} · {item.role}
                      </div>
                    </div>
                  </div>

                  {/* Quote */}
                  <p className="mt-6 text-sm text-[#d4d4d8] font-sans leading-relaxed">
                    "{item.quote}"
                  </p>
                </div>

                {/* Timestamp */}
                <div className="mt-6 pt-4 border-t border-[#222222] flex items-center justify-between text-[11px] font-mono text-[#888888]">
                  <span>{item.timestamp}</span>
                  <span className={isFeatured ? "text-[#0055FF] font-bold" : "text-[#444444]"}>
                    ● VERIFIED DEPLOY
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
