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
import CallChip from "@/components/ui/CallChip";

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
  const [preCruxEmail, setPreCruxEmail] = useState("");
  const [preCruxSubmitted, setPreCruxSubmitted] = useState(false);
  const [chipStage, setChipStage] = useState<"idle" | "almost" | "gone" | "done">("idle");

  const handlePreCruxSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (preCruxEmail && preCruxEmail.includes("@")) {
      try {
        localStorage.setItem("pre_crux_email", preCruxEmail);
      } catch (_) {}

      setChipStage("almost");

      setTimeout(() => {
        setChipStage("gone");
      }, 900);

      setTimeout(() => {
        setChipStage("done");
        setPreCruxSubmitted(true);
      }, 2000);
    }
  };

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
          {/* Main Hero Split Grid: Left Heading vs Right Social Proof, Copy & Actions */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-12 items-start pb-14">
            {/* Left Column: Heading */}
            <div className="lg:col-span-7">
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

            {/* Right Column: Social Proof, Subtitle Copy, and Actions matching Screenshot */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1], delay: 0.15 }}
              className="lg:col-span-5 flex flex-col justify-between pt-2 sm:pt-4"
            >
              {/* Stacked Avatars + Trusted by + Rating */}
              <div className="flex flex-wrap items-center gap-3 sm:gap-4 text-xs sm:text-sm font-sans">
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

                <div className="text-[#888888]">
                  Trusted by <span className="font-semibold text-white">10K+</span> Teams
                </div>

                <div className="w-[1px] h-3.5 bg-[#333333]" />

                <div className="flex items-center gap-1.5">
                  <StarPixelIcon className="w-3.5 h-3.5 text-[#0055FF]" />
                  <span className="font-mono font-bold text-white">4.9</span>
                  <span className="font-mono text-[#71717a]">/5</span>
                </div>
              </div>

              {/* Description Paragraph matching Screenshot 1 */}
              <p className="mt-5 text-sm sm:text-base text-[#888888] font-sans leading-relaxed max-w-[480px]">
                Automate complex tasks, streamline your workflows, and deliver better results faster — with AI handling the heavy lifting behind the scenes.
              </p>

              {/* Email Input & Lets Crux it Action Form / CallChip */}
              {chipStage !== "idle" ? (
                <motion.div
                  initial={{ opacity: 0, y: 8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                  className="mt-8 flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-2 pl-3 pr-4 border border-[#222222] bg-[#0c0c0e]/90 max-w-[540px] rounded-none"
                >
                  <div className="flex items-center">
                    <CallChip
                      icon="terminal"
                      name="Waitlist"
                      argument={
                        chipStage === "almost"
                          ? "Almost there..."
                          : chipStage === "gone"
                          ? "Going through..."
                          : "Done! See ya at Crux!"
                      }
                      status={chipStage === "done" ? "done" : "running"}
                      expectedMs={2000}
                      size={35}
                      radius={10}
                      color="currentColor"
                      surfaceColor="#27272a"
                      progressColor="currentColor"
                      progressOpacity={0.18}
                      doneColor="#22c55e"
                      errorColor="#ef4444"
                      washOpacity={0.12}
                      shake={9}
                      showTimer
                    />
                  </div>

                  {/* Telemetry metadata utilizing all space on the side */}
                  <div className="flex items-center gap-3 font-mono text-[11px] text-[#71717a] shrink-0 pl-1 sm:pl-0 select-none">
                    <span className="flex items-center gap-1.5 text-white font-medium">
                      <span
                        className={`w-1.5 h-1.5 ${
                          chipStage === "done" ? "bg-[#22c55e]" : "bg-[#0055FF] animate-pulse"
                        }`}
                      />
                      {chipStage === "done" ? "CONFIRMED" : "DISPATCH"}
                    </span>
                    <span className="text-[#333333]">/</span>
                    <span className="text-[#888888] tracking-wider uppercase">
                      {chipStage === "done" ? "BATCH #14" : "ROUTING"}
                    </span>
                    <span className="hidden sm:inline text-[#333333]">/</span>
                    <span className="hidden sm:inline text-[#555555] font-mono">&lt;0.2ms</span>
                  </div>
                </motion.div>
              ) : (
                <form
                  onSubmit={handlePreCruxSubmit}
                  className="mt-8 flex flex-col sm:flex-row items-stretch sm:items-center gap-4"
                >
                  {/* Left: Email input with the exact underline border style as Watch Demo */}
                  <div className="relative">
                    <input
                      type="email"
                      required
                      value={preCruxEmail}
                      onChange={(e) => setPreCruxEmail(e.target.value)}
                      placeholder="Get on Pre-Crux"
                      className="w-full sm:w-[240px] md:w-[280px] bg-transparent text-white placeholder-[#888888] font-sans text-xs sm:text-sm tracking-wider border-0 border-b border-white focus:border-[#0055FF] focus:outline-none px-2 py-3 transition-none rounded-none"
                    />
                  </div>

                  {/* Right: Lets Crux it Action Button */}
                  <button
                    type="submit"
                    className="inline-flex items-center justify-center gap-2.5 px-6 py-3.5 bg-[#0e0e11] border border-[#333333] hover:border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none cursor-pointer rounded-none font-medium shrink-0 group"
                  >
                    <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block transition-none" />
                    <span>Lets Crux it</span>
                  </button>
                </form>
              )}
            </motion.div>
          </div>

          {/* 3. Partner Logos Grid (Exact 6-cell desktop grid + seamless mobile ticker) */}
          <div className="border border-[#222222] bg-[#000000] overflow-hidden rounded-none">
            {/* Desktop View: Exact 6 Column Grid */}
            <div className="hidden lg:grid grid-cols-6 divide-x divide-[#222222]">
              {PARTNER_ITEMS.map(({ Component, name }, idx) => (
                <div
                  key={idx}
                  className="h-[120px] flex items-center justify-center p-4 hover:bg-[#111111] transition-none group cursor-default"
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
                  className="h-[90px] px-8 flex items-center justify-center border-r border-[#222222] min-w-[150px]"
                >
                  <Component className="h-5 w-auto max-w-[100px]" />
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
