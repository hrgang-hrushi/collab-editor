"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import { ArrowRight, Check } from "lucide-react";

export default function AeyeCtaSection() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (email.trim()) {
      setSubmitted(true);
      setTimeout(() => {
        setEmail("");
        setSubmitted(false);
      }, 3500);
    }
  };

  const tickerText = (
    <div className="flex items-center gap-8 font-mono text-xs text-white tracking-widest uppercase py-4">
      <span className="text-[#0055FF] font-semibold">// [#CRUX] &amp; [#RUST]</span>
      <span className="text-[#444444]">●</span>
      <span className="font-bold text-white">BARE-METAL IDE</span>
      <span className="text-[#444444]">●</span>
      <span>SUB-15MS WEBGPU LATENCY</span>
      <span className="text-[#444444]">●</span>
      <span className="text-[#0055FF] font-semibold">// [#DECENTRALIZED] &amp; [#AST-CRDT]</span>
      <span className="text-[#444444]">●</span>
      <span className="font-bold text-white">ZERO CHROMIUM OVERHEAD</span>
      <span className="text-[#444444]">●</span>
      <span className="text-[#0055FF]">TRY CRUX FREE TODAY!</span>
    </div>
  );

  return (
    <section className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
      {/* Background Dot Texture */}
      <div className="absolute inset-0 aeye-dot-bg invert opacity-15 pointer-events-none" />

      {/* Retro Headline Ticker */}
      <div className="border-b border-[#222222] bg-[#000000] overflow-hidden whitespace-nowrap">
        <div className="flex w-max animate-aeye-marquee hover:[animation-play-state:paused]">
          {tickerText}
          {tickerText}
        </div>
      </div>

      <div className="max-w-[1280px] mx-auto px-6 py-20 relative z-10">
        <div className="border border-[#222222] bg-[#000000] p-8 sm:p-14 max-w-4xl mx-auto rounded-none">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-8">
            {/* Left Copy */}
            <div className="max-w-md">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-[#0055FF] font-bold">
                  @
                </span>
                <span className="font-mono text-xs tracking-wider uppercase text-[#0055FF] font-bold">
                  CRUX INSIDER DISPATCH
                </span>
              </div>
              <h3 className="mt-4 text-2xl sm:text-3xl font-normal tracking-tight text-white font-sans">
                Get priority builds, alpha features, and architecture release notes.
              </h3>
              <p className="mt-2 text-xs sm:text-sm text-[#888888] font-sans">
                Straight from the kernel engineers. No spam, ever.
              </p>
            </div>

            {/* Right Form */}
            <div className="flex-1 max-w-md w-full">
              <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-2">
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="your.email@company.com"
                  className="flex-1 px-4 py-3 border border-[#222222] bg-[#111111] text-xs font-sans text-white placeholder:text-[#444444] focus:outline-none focus:border-[#0055FF] transition-none rounded-none"
                />
                <button
                  type="submit"
                  className="px-6 py-3 bg-[#0055FF] hover:bg-[#0044CC] text-white border border-[#0055FF] text-xs font-mono uppercase tracking-wider flex items-center justify-center gap-2 transition-none cursor-pointer flex-shrink-0 rounded-none font-bold"
                >
                  <span>{submitted ? "Subscribed!" : "Join"}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </form>
              {submitted && (
                <div className="mt-3 text-[11px] font-mono text-[#0055FF] font-semibold flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5 text-[#0055FF] stroke-[3]" />
                  <span>You’re on the priority Crux developer release list.</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
