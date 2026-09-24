"use client";

import React, { useState, useRef } from "react";
import { ChevronLeft, ChevronRight, Play, ArrowUpRight } from "lucide-react";

export default function AeyeTestimonialSection() {
  const scrollRef = useRef<HTMLDivElement>(null);

  const testimonials = [
    {
      type: "tweet" as const,
      name: "Jaron Smith",
      handle: "@jaronsmith8802",
      avatar: "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=128&h=128&fit=crop&crop=face",
      quote:
        "We reduced hours of manual work into a few automated steps. The workflow feels seamless — and the results are consistently reliable.",
      timestamp: "12:08 AM · DEC 12, 2025",
    },
    {
      type: "video" as const,
      tag: "@DAVID_COREW",
      duration: "1:30 min",
      image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=600&h=750&fit=crop&crop=face",
    },
    {
      type: "tweet" as const,
      name: "Taylor Reed",
      handle: "@taylor_reed4214",
      avatar: "https://images.unsplash.com/photo-1570295999919-56ceb5ecca61?w=128&h=128&fit=crop&crop=face",
      quote:
        "We replaced three internal scripts with one automated workflow. Setup took minutes. Maintenance takes none!!!",
      timestamp: "9:03 PM · JUL 08, 2026",
    },
    {
      type: "video" as const,
      tag: "@ELENA_SYS",
      duration: "2:15 min",
      image: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=600&h=750&fit=crop&crop=face",
    },
    {
      type: "tweet" as const,
      name: "Emily Carter",
      handle: "@emilycarter_ui",
      avatar: "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=128&h=128&fit=crop&crop=face",
      quote:
        "Crux makes multi-agent workflows feel instantaneous. The typing latency and AST-CRDT pair sync are unmatched.",
      timestamp: "3:45 PM · APR 19, 2026",
    },
  ];

  const scrollLeft = () => {
    if (scrollRef.current) {
      scrollRef.current.scrollBy({ left: -360, behavior: "smooth" });
    }
  };

  const scrollRight = () => {
    if (scrollRef.current) {
      scrollRef.current.scrollBy({ left: 360, behavior: "smooth" });
    }
  };

  return (
    <section id="testimonials" className="relative w-full border-b border-[#222222] bg-[#000000]">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[N.07/11]</span>
            <span className="text-[#888888]">— &gt;</span>
            <span className="text-[#888888] uppercase">TESTIMONIAL</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            ENGINEERING &amp; PRODUCTION FEEDBACK
          </div>
        </div>

        {/* Section Title & Subtitle + Carousel Arrows matching Frame 062 */}
        <div className="pt-10 pb-12 flex flex-col sm:flex-row sm:items-end justify-between gap-6">
          <div>
            <h2 className="text-3xl sm:text-5xl lg:text-[52px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
              Less talk, more shipping.
              <span className="block text-[#888888]">See what they are saying.</span>
            </h2>
          </div>

          {/* Carousel Arrows matching video */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={scrollLeft}
              className="w-10 h-10 border border-[#333333] bg-[#000000] text-white flex items-center justify-center hover:bg-white hover:text-black transition-none cursor-pointer"
              aria-label="Previous"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={scrollRight}
              className="w-10 h-10 border border-[#333333] bg-[#000000] text-white flex items-center justify-center hover:bg-white hover:text-black transition-none cursor-pointer"
              aria-label="Next"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Horizontal Scroll Testimonial Strip */}
        <div
          ref={scrollRef}
          className="flex gap-6 overflow-x-auto pb-6 scrollbar-none snap-x snap-mandatory"
          style={{ scrollbarWidth: "none", msOverflowStyle: "none" }}
        >
          {testimonials.map((item, idx) => {
            if (item.type === "video") {
              return (
                <div
                  key={idx}
                  className="w-[300px] sm:w-[340px] h-[400px] shrink-0 border border-[#222222] relative group overflow-hidden bg-[#0c0c0e] snap-start"
                >
                  <img
                    src={item.image}
                    alt={item.tag}
                    className="w-full h-full object-cover grayscale contrast-125 group-hover:scale-105 transition-all duration-300"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-black/30" />

                  {/* Handle Tag */}
                  <div className="absolute top-4 right-4 bg-black/80 border border-[#333333] px-2.5 py-1 text-[10px] font-mono text-white">
                    {item.tag}
                  </div>

                  {/* Play Button Overlay */}
                  <div className="absolute bottom-4 left-4 bg-black/80 border border-[#333333] px-3 py-1.5 flex items-center gap-2 text-white font-mono text-xs">
                    <Play className="w-3.5 h-3.5 fill-white" />
                    <span>{item.duration}</span>
                  </div>
                </div>
              );
            }

            return (
              <div
                key={idx}
                className="w-[300px] sm:w-[340px] h-[400px] shrink-0 border border-[#222222] bg-[#0a0a0c] p-6 flex flex-col justify-between hover:bg-[#111114] transition-none snap-start"
              >
                <div>
                  {/* Author Header */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <img
                        src={item.avatar}
                        alt={item.name}
                        className="w-10 h-10 border border-[#222222] object-cover grayscale"
                      />
                      <div>
                        <div className="text-sm font-medium text-white font-sans">
                          {item.name}
                        </div>
                        <div className="text-xs text-[#71717a] font-mono">
                          {item.handle}
                        </div>
                      </div>
                    </div>
                    {/* X Logo */}
                    <svg viewBox="0 0 24 24" className="w-4 h-4 fill-white opacity-60">
                      <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 24.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
                    </svg>
                  </div>

                  {/* Quote */}
                  <p className="mt-8 text-sm text-[#cccccc] font-sans leading-relaxed">
                    {item.quote}
                  </p>
                </div>

                {/* Footer Timestamp + Read More */}
                <div className="pt-6 border-t border-[#1a1a1e]">
                  <div className="text-[11px] font-mono text-[#666666]">
                    {item.timestamp}
                  </div>
                  <div className="mt-3 flex items-center justify-between text-xs font-mono text-white group cursor-pointer">
                    <ArrowUpRight className="w-3.5 h-3.5 text-[#0055FF]" />
                    <span className="text-[#888888] hover:text-white tracking-wider">
                      READ MORE
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
