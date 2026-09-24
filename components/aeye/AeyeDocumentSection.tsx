"use client";

import React from "react";
import { motion } from "framer-motion";
import { ArrowRight } from "lucide-react";

export default function AeyeDocumentSection() {
  const docCards = [
    {
      serial: "// 001",
      title: "Kernel Architecture & WebGPU",
      description:
        "Step-by-step internals of Crux's native Rust execution canvas, zero-copy buffer shaders, and sub-15ms frame dispatch.",
      tags: ["Rust", "WebGPU", "Memory"],
      imgSrc:
        "https://framerusercontent.com/images/qCjWRSRbmNNk7YaLt75Pyig0U.png?width=780&height=780",
    },
    {
      serial: "// 002",
      title: "Decentralized AST-CRDT & @CruxAI",
      description:
        "Conflict-free real-time syntax tree replication over encrypted P2P mesh networks and autonomous terminal agent orchestration.",
      tags: ["AST-CRDT", "P2P WebRTC", "Agentic"],
      imgSrc:
        "https://framerusercontent.com/images/FwtNfhGoQ8kzb1yOwMX76zzLgQ.png?width=780&height=780",
    },
  ];

  return (
    <section id="document" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
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
            <span className="text-[#0055FF] font-bold">[n. 06 / 11 ]</span>
            <span className="text-[#0055FF] font-bold">&gt;</span>
            <span className="text-[#888888]">Documentation</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0">
            CRUX KERNEL &amp; AGENT ARCHITECTURE SPECS
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
            Complete system architecture.{" "}
            <span className="text-[#444444] block sm:inline">
              Documented for builders.
            </span>
          </h2>
          <p className="mt-4 text-xs sm:text-sm text-[#888888] font-sans max-w-xl">
            Deep dive into WebGPU rendering primitives, decentralized AST-CRDT algorithms, and @CruxAI terminal agents.
          </p>
        </motion.div>

        {/* 2 Doc Cards Grid */}
        <div className="mt-12 grid grid-cols-1 md:grid-cols-2 border border-[#222222] divide-y md:divide-y-0 md:divide-x divide-[#222222] bg-[#000000]">
          {docCards.map((doc, idx) => (
            <div
              key={idx}
              className="p-8 sm:p-10 flex flex-col justify-between group bg-[#000000] hover:bg-[#111111] transition-none cursor-pointer rounded-none"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold text-[#0055FF]">
                    {doc.serial}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {doc.tags.map((t, tidx) => (
                      <span
                        key={tidx}
                        className="px-2.5 py-0.5 bg-[#111111] border border-[#222222] text-[10px] font-mono text-[#888888] rounded-none"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                <h3 className="mt-8 text-2xl font-medium tracking-tight text-white font-sans">
                  {doc.title}
                </h3>
                <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed">
                  {doc.description}
                </p>

                {/* Blueprint illustration image */}
                <div className="mt-8 border border-[#222222] bg-[#111111] overflow-hidden aspect-video relative rounded-none">
                  <img
                    src={doc.imgSrc}
                    alt={doc.title}
                    className="w-full h-full object-cover rounded-none grayscale contrast-125 opacity-80 group-hover:opacity-100 transition-none"
                  />
                </div>
              </div>

              {/* Bottom Action Link */}
              <div className="mt-8 pt-4 border-t border-[#222222] flex items-center justify-between text-xs font-mono text-white group-hover:text-white">
                <span className="font-semibold uppercase tracking-wider">View Documentation</span>
                <ArrowRight className="w-3.5 h-3.5 text-white transition-none group-hover:translate-x-1" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
