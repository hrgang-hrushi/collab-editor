"use client";

import React from "react";
import { MessageSquare, Check, ArrowRight } from "lucide-react";
import CruxBrandLogo from "../CruxBrandLogo";

interface Endorsement {
  name: string;
  handle: string;
  role: string;
  avatarText: string;
  text: string;
  highlight: string;
  stats: string;
}

const ENDORSEMENTS: Endorsement[] = [
  {
    name: "Alex V.",
    handle: "@alexv_systems",
    role: "Staff Infrastructure Engineer · YC W23",
    avatarText: "AV",
    text: "Switched from Cursor to Crux for our core Rust engine. The difference in latency is visceral. You hit a key and the pixels are on screen before your finger even lifts from the mechanical switch.",
    highlight: "4.2ms input-to-photon latency is real.",
    stats: "342 repos migrated",
  },
  {
    name: "Dr. Elena Rostova",
    handle: "@elena_systems",
    role: "Principal Compiler Architect",
    avatarText: "ER",
    text: "Electron editors have been draining 16GB RAM for a decade. Crux idling at 38MB on my M3 Max while rendering a 250,000-line monorepo at 120 FPS feels like alien technology.",
    highlight: "38MB idle memory vs 1.2GB in Chromium.",
    stats: "120 FPS locked",
  },
  {
    name: "Marcus Chen",
    handle: "@mchen_ai",
    role: "Founder & CTO · a16z Portfolio",
    avatarText: "MC",
    text: "The 1-click migration scanned my ~/.config/Code and imported my entire 80-item keybinding set and custom .cursorrules in 140 milliseconds. Zero muscle memory lost. That alone sold the whole team.",
    highlight: "Zero muscle memory loss.",
    stats: "140ms instant ingest",
  },
  {
    name: "Soren K.",
    handle: "@soren_kernel",
    role: "Senior Systems Dev · High-Frequency Trading",
    avatarText: "SK",
    text: "The decentralized AST-CRDT model means our remote engineers pair-program across Tokyo and San Francisco with zero typing collisions. The code diff never breaks syntax tree validity.",
    highlight: "AST-level merge determinism.",
    stats: "Sub-1ms delta sync",
  },
];

interface EngineeringWallProps {
  onOpenWaitlist: () => void;
}

export default function EngineeringWall({ onOpenWaitlist }: EngineeringWallProps) {
  return (
    <section className="py-24 px-6 max-w-6xl mx-auto border-t border-[#222222]">
      {/* Header */}
      <div className="text-center max-w-2xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-none bg-[#111111] border border-[#222222] text-white text-xs font-mono mb-4">
          <MessageSquare className="w-3.5 h-3.5 text-white" />
          <span>[FIELD-TESTED AT HIGH-VELOCITY STARTUPS]</span>
        </div>
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-white mb-4 font-sans">
          Endorsed by Engineers Who Value Every Millisecond.
        </h2>
        <p className="text-sm sm:text-base text-[#888888] leading-relaxed font-sans">
          From YC-backed founders to compiler architects, here is what high-throughput teams say
          after migrating their primary daily driver to Crux.
        </p>
      </div>

      {/* Grid of Hardware Window Testimonial Cards */}
      <div
        className="grid grid-cols-1 md:grid-cols-2 gap-6"
        style={{
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
        }}
      >
        {ENDORSEMENTS.map((item, idx) => (
          <div
            key={idx}
            className="rounded-none border border-[#222222] bg-[#000000] overflow-hidden hover:border-white transition-none group flex flex-col justify-between"
          >
            {/* Window Titlebar */}
            <div className="px-4 py-2.5 bg-[#111111] border-b border-[#222222] flex items-center justify-between select-none">
              <div className="flex items-center gap-2">
                <CruxBrandLogo size={12} />
                <span className="ml-1 text-[10px] font-mono text-[#888888]">
                  {item.handle}
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-none border border-[#222222] bg-[#000000] text-white">
                {item.stats}
              </span>
            </div>

            {/* Testimonial Body */}
            <div className="p-6 space-y-4">
              <p className="text-xs sm:text-sm text-[#888888] leading-relaxed font-sans">
                "{item.text}"
              </p>

              <div className="p-2.5 rounded-none bg-[#111111] border border-[#222222] text-[11px] font-mono text-white">
                <span className="text-[#888888]">Key Result:</span> {item.highlight}
              </div>
            </div>

            {/* Author Footer */}
            <div className="px-6 py-3.5 bg-[#0a0a0a] border-t border-[#222222] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-none bg-[#111111] border border-[#222222] flex items-center justify-center font-bold text-xs text-white font-mono">
                  {item.avatarText}
                </div>
                <div>
                  <div className="text-xs font-bold text-white font-sans">{item.name}</div>
                  <div className="text-[10px] text-[#888888] font-mono">{item.role}</div>
                </div>
              </div>

              <Check className="w-4 h-4 text-white stroke-[3]" />
            </div>
          </div>
        ))}
      </div>

      {/* Social Banner CTA */}
      <div className="mt-12 text-center">
        <button
          onClick={onOpenWaitlist}
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#000000] hover:bg-white text-[#888888] hover:text-black border border-[#222222] hover:border-white text-xs font-mono uppercase tracking-wider transition-none cursor-pointer rounded-none"
        >
          <span>Join 3,200+ engineers on the private Waitlist</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </section>
  );
}
