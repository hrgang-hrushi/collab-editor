"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, ArrowRight, ArrowDown, Play } from "lucide-react";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";
import {
  CruxLogo,
  StarPixelIcon,
  ThreeSquaresIcon,
  PartnerLogo1,
  PartnerLogo2,
  PartnerLogo3,
  PartnerLogo4,
  PartnerLogo5,
  PartnerLogo6,
} from "./AeyeIcons";
import InteractivePixelGrid from "./InteractivePixelGrid";

const TYPEWRITER_WORDS = ["[Collaborative IDE]", "[Bare-Metal Kernel]", "[WebGPU Engine]"];

const PARTNER_ITEMS = [
  { Component: PartnerLogo1, name: "Javast" },
  { Component: PartnerLogo2, name: "Urban Tribe" },
  { Component: PartnerLogo3, name: "LOOO" },
  { Component: PartnerLogo4, name: "Logoipsum" },
  { Component: PartnerLogo5, name: "Logoipsum" },
  { Component: PartnerLogo6, name: "IPSUM" },
];

export default function AeyeHero() {
  const [currentWordIndex, setCurrentWordIndex] = useState(0);
  const [displayedText, setDisplayedText] = useState("");
  const [isDeleting, setIsDeleting] = useState(false);
  const [isWatchDemoOpen, setIsWatchDemoOpen] = useState(false);
  const [isPlayingDemo, setIsPlayingDemo] = useState(false);

  useEffect(() => {
    const currentWord = TYPEWRITER_WORDS[currentWordIndex];
    let timeout: NodeJS.Timeout;

    if (!isDeleting) {
      if (displayedText.length < currentWord.length) {
        timeout = setTimeout(() => {
          setDisplayedText(currentWord.slice(0, displayedText.length + 1));
        }, 100);
      } else {
        timeout = setTimeout(() => {
          setIsDeleting(true);
        }, 1200);
      }
    } else {
      if (displayedText.length > 0) {
        timeout = setTimeout(() => {
          setDisplayedText(currentWord.slice(0, displayedText.length - 1));
        }, 50);
      } else {
        setIsDeleting(false);
        setCurrentWordIndex((prev) => (prev + 1) % TYPEWRITER_WORDS.length);
      }
    }

    return () => clearTimeout(timeout);
  }, [displayedText, isDeleting, currentWordIndex]);

  return (
    <section id="hero" className="relative w-full bg-[#000000] overflow-hidden">
      {/* 1. Hero Header with Interactive 3D Pixel Grid */}
      <div className="relative w-full h-[380px] bg-[#000000] border-b border-[#222222] overflow-hidden flex flex-col justify-end pb-12 px-6 sm:px-12 md:px-20 lg:px-[120px]">
        {/* Interactive 3D Pixel Grid Background */}
        <div className="absolute inset-0 z-0 pointer-events-auto">
          <InteractivePixelGrid
            backgroundColor="#000000"
            borderColor="#222222"
            borderWidth={1}
            boxSize={48}
            outDuration={1}
          />
        </div>

        {/* Header Content: Crux Official Logo + V0.1.0 // RUST + WEBGPU & SCROLL FOR ARCHITECTURE */}
        <div className="relative z-10 w-full max-w-[1280px] mx-auto flex items-center justify-between pointer-events-none">
          {/* Logo & Version Pill */}
          <div className="flex items-center gap-3 pointer-events-auto">
            <a href="#" className="hover:opacity-90 transition-none no-underline">
              <CruxBrandLogo size={28} />
            </a>
            <div className="px-2.5 py-0.5 border border-[#0055FF]/40 bg-[#0055FF]/10 text-[11px] font-mono text-[#0055FF] uppercase tracking-wider select-none rounded-none font-semibold">
              v0.1.0 // RUST + WEBGPU
            </div>
          </div>

          {/* Scroll Text with Bouncing Arrow */}
          <a
            href="#benefit"
            className="flex items-center gap-2 text-[11px] font-mono text-[#888888] hover:text-[#0055FF] transition-none cursor-pointer no-underline pointer-events-auto group"
          >
            <span className="tracking-widest">SCROLL FOR ARCHITECTURE</span>
            <motion.div
              animate={{ y: [0, 4, 0] }}
              transition={{ repeat: Infinity, duration: 1.5, ease: "easeInOut" }}
            >
              <ArrowDown className="w-3.5 h-3.5 text-[#888888] group-hover:text-[#0055FF] transition-none" />
            </motion.div>
          </a>
        </div>
      </div>

      {/* 2. Hero Main Content Area */}
      <div className="relative z-20 w-full bg-[#000000] border-t border-[#222222] px-6 sm:px-12 md:px-20 lg:px-[120px] pt-14 sm:pt-16 pb-20">
        {/* Dot Matrix Texture Background */}
        <div className="absolute inset-0 aeye-dot-bg invert opacity-15 pointer-events-none" />

        <div className="relative z-10 max-w-[1280px] mx-auto">
          {/* Main H1 Area */}
          <div className="pb-12">
            <h1 className="text-4xl sm:text-6xl md:text-7xl lg:text-[76px] font-normal tracking-[-0.06em] leading-[1.08] text-white font-sans">
              <motion.div
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
              >
                A Native Bare-Metal
              </motion.div>

              <div className="inline-flex items-center gap-1 min-h-[48px] sm:min-h-[82px] font-mono text-[#0055FF] tracking-tight">
                <span className="text-[#0055FF]">{displayedText}</span>
                <motion.span
                  animate={{ opacity: [1, 0, 1] }}
                  transition={{ repeat: Infinity, duration: 0.5 }}
                  className="inline-block w-[18px] sm:w-[26px] h-[34px] sm:h-[48px] bg-[#0055FF] ml-1 align-baseline"
                />
              </div>

              <motion.div
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
              >
                for High-Velocity Teams.
              </motion.div>
            </h1>
          </div>

          {/* Hero Meta Description, Social Proof & Actions */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1], delay: 0.2 }}
            className="grid grid-cols-1 lg:grid-cols-12 gap-8 pt-8 pb-14 border-t border-[#222222] items-end"
          >
            {/* Left Social Proof & Copy */}
            <div className="lg:col-span-7 flex flex-col gap-4">
              <div className="flex flex-wrap items-center gap-3 sm:gap-4 text-sm font-sans">
                {/* Stacked Avatars */}
                <div className="flex items-center -space-x-2">
                  {[
                    "https://framerusercontent.com/images/bCXMojdPVkmoes2tDd7ja8MzUNk.png?width=112&height=112",
                    "https://framerusercontent.com/images/9kcBxw1gwBwDex0T3vDioEe98.png?width=112&height=112",
                    "https://framerusercontent.com/images/2Ubnrf1r6MyNyZ1Y5NQMqnS770.png?width=112&height=112",
                  ].map((src, i) => (
                    <motion.img
                      key={i}
                      whileHover={{ scale: 1.15, zIndex: 10 }}
                      transition={{ type: "spring", stiffness: 400, damping: 20 }}
                      src={src}
                      alt="User avatar"
                      className="w-7 h-7 rounded-none border border-[#222222] object-cover cursor-pointer relative"
                    />
                  ))}
                </div>

                {/* Trusted by 10K+ */}
                <div className="text-[#888888]">
                  Trusted by <span className="font-semibold text-white">10K+</span> Engineers
                </div>

                {/* Vertical Divider */}
                <div className="w-[1px] h-3.5 bg-[#222222]" />

                {/* Rating */}
                <div className="flex items-center gap-1.5">
                  <StarPixelIcon className="w-3.5 h-3.5 text-[#0055FF]" />
                  <span className="font-mono font-bold text-white">4.9</span>
                  <span className="font-mono text-[#71717a]">/5</span>
                </div>

                {/* Vertical Divider */}
                <div className="w-[1px] h-3.5 bg-[#222222]" />

                {/* Live Telemetry Ping */}
                <div className="hidden sm:flex items-center gap-1.5 px-2 py-0.5 border border-[#0055FF]/30 bg-[#0055FF]/10 text-[10px] font-mono text-[#888888] rounded-none">
                  <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                  <span className="text-[#0055FF] font-medium">120 FPS</span>
                  <span className="text-[#71717a]">·</span>
                  <span className="text-[#0055FF]">8.4ms</span>
                </div>
              </div>

              <p className="text-sm sm:text-base text-[#888888] font-sans max-w-[460px] leading-relaxed">
                Engineered from bare silicon with Rust and WebGPU. Sub-15ms rendering latency, decentralized AST-CRDT real-time sync, and zero Chromium overhead.
              </p>
            </div>

            {/* Right CTAs (Hardware Brutalist Mechanical Switches) */}
            <div className="lg:col-span-5 flex flex-col sm:flex-row items-stretch sm:items-center justify-start lg:justify-end gap-3.5">
              {/* Primary Action Button: LAUNCH CRUX */}
              <motion.a
                href="/?app=true"
                whileTap={{ scale: 0.98 }}
                className="w-full sm:w-[180px] h-[48px] bg-[#0055FF] hover:bg-[#0044CC] text-white border border-[#0055FF] text-xs font-mono uppercase font-bold tracking-wider flex items-center justify-between px-5 transition-none no-underline group cursor-pointer rounded-none"
              >
                <div className="flex items-center gap-2.5">
                  <span className="w-1.5 h-1.5 bg-white inline-block transition-none" />
                  <span>LAUNCH CRUX</span>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-white transition-none" />
              </motion.a>

              {/* Watch Demo Action Button: WATCH DEMO */}
              <motion.button
                onClick={() => setIsWatchDemoOpen(true)}
                whileTap={{ scale: 0.98 }}
                className="w-full sm:w-[180px] h-[48px] bg-transparent border border-[#222222] text-white hover:bg-white hover:text-black hover:border-white text-xs font-mono uppercase font-bold tracking-wider flex items-center justify-center gap-3 transition-none rounded-none group cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>WATCH DEMO</span>
              </motion.button>
            </div>
          </motion.div>

          {/* 3. Partner Logos Grid (Exact 6-cell desktop grid + seamless mobile ticker) */}
          <div className="mt-4 border border-[#222222] bg-[#000000] overflow-hidden rounded-none">
            {/* Desktop View: Exact 6 Column Grid */}
            <div className="hidden lg:grid grid-cols-6 divide-x divide-[#222222]">
              {PARTNER_ITEMS.map(({ Component, name }, idx) => (
                <div
                  key={idx}
                  className="h-[132px] flex items-center justify-center p-4 hover:bg-[#111111] transition-none group cursor-default"
                >
                  <Component className="h-6 w-auto max-w-[120px] transition-none filter brightness-90 group-hover:brightness-100" />
                </div>
              ))}
            </div>

            {/* Mobile & Tablet View: Infinite Marquee Ticker */}
            <div className="lg:hidden flex w-max animate-aeye-ticker hover:[animation-play-state:paused]">
              {[...PARTNER_ITEMS, ...PARTNER_ITEMS, ...PARTNER_ITEMS].map(({ Component }, idx) => (
                <div
                  key={idx}
                  className="h-[100px] px-8 flex items-center justify-center border-r border-[#222222] min-w-[160px]"
                >
                  <Component className="h-5 w-auto max-w-[110px]" />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 4. Blueprint Positioning Ribbon */}
      <div className="w-full bg-[#000000] border-y border-[#222222] py-10 px-6 sm:px-12 relative overflow-hidden">
        {/* Dot Texture Overlay */}
        <div className="absolute inset-0 aeye-dot-bg invert opacity-10 pointer-events-none" />

        <div className="relative z-10 max-w-[1280px] mx-auto flex flex-wrap items-center justify-center gap-4 sm:gap-6 text-center select-none text-white">
          <ThreeSquaresIcon className="w-[33px] h-[4px] hidden sm:block text-white" />

          <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-3 text-lg sm:text-2xl md:text-3xl font-mono">
            <span className="text-white font-bold">&gt;</span>
            <span className="text-white font-bold tracking-tight">CRUX</span>
            <ArrowRight className="w-4 h-4 text-white inline-block align-middle mx-1" />
            <span className="text-white font-normal tracking-tight">
              BARE-METAL COLLABORATIVE IDE FOR
            </span>
            <CruxLogo size={18} className="inline-block align-middle mx-1.5" />
            <span className="text-white font-bold tracking-tight">
              HIGH-VELOCITY ENGINEERING
            </span>
            <span className="text-[#71717a]">&lt;</span>
          </div>

          <ThreeSquaresIcon className="w-[33px] h-[4px] hidden sm:block text-white" />
        </div>
      </div>

      {/* 5. Interactive Video Walkthrough Modal */}
      <AnimatePresence>
        {isWatchDemoOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setIsWatchDemoOpen(false)}
            className="fixed inset-0 z-50 bg-black/90 flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ scale: 0.98, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.98, opacity: 0 }}
              transition={{ duration: 0.15 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-[#000000] rounded-none border border-[#222222] max-w-3xl w-full p-4 sm:p-6 relative overflow-hidden"
            >
              <div className="flex items-center justify-between pb-4 border-b border-[#222222]">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-white" />
                  <span className="font-mono text-xs font-semibold text-white">
                    Crux Architecture &amp; WebGPU Demo
                  </span>
                </div>
                <button
                  onClick={() => setIsWatchDemoOpen(false)}
                  className="w-7 h-7 rounded-none border border-[#222222] bg-[#111111] text-white text-xs font-mono flex items-center justify-center hover:bg-white hover:text-black hover:border-white transition-none cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="aspect-video w-full bg-[#000000] border border-[#222222] mt-4 rounded-none text-white relative overflow-hidden">
                <video
                  src="/demo.mp4"
                  controls
                  autoPlay
                  loop
                  playsInline
                  className="w-full h-full object-contain bg-black"
                />
              </div>

              <div className="pt-4 flex items-center justify-between text-[11px] font-mono text-[#71717a]">
                <span>Resolution: 3024x1654 60FPS · Crux Native Core</span>
                <a
                  href="/?app=true"
                  onClick={() => setIsWatchDemoOpen(false)}
                  className="text-white hover:underline font-semibold flex items-center gap-1.5"
                >
                  <span>Launch Crux IDE</span>
                  <ArrowRight className="w-3.5 h-3.5 inline" />
                </a>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}
