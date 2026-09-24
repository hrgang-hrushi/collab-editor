"use client";

import React, { useState, useEffect } from "react";
import { ArrowRight, ChevronRight } from "lucide-react";
import CruxBrandLogo from "../CruxBrandLogo";

interface CruxNavbarProps {
  onOpenWaitlist: () => void;
  onLaunchWebEditor?: () => void;
}

export default function CruxNavbar({ onOpenWaitlist, onLaunchWebEditor }: CruxNavbarProps) {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <header className="fixed top-0 md:top-4 left-0 right-0 z-40 flex justify-center px-4 pt-3 sm:pt-4 pointer-events-none">
      <div
        className={`pointer-events-auto flex items-center justify-between gap-4 sm:gap-8 px-4 sm:px-6 py-2.5 rounded-none border border-[#222222] transition-none ${
          scrolled ? "bg-[#000000]" : "bg-[#000000]"
        }`}
        style={{
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
          maxWidth: "1024px",
          width: "100%",
        }}
      >
        {/* Left: Logotype in Etna with status */}
        <div className="flex items-center gap-3">
          <CruxBrandLogo size={20} withText={true} />
          <div className="hidden sm:flex items-center gap-1.5 px-2 py-0.5 rounded-none bg-[#111111] border border-[#222222] text-[10px] font-mono text-[#888888]">
            <span className="w-1.5 h-1.5 rounded-none bg-white" />
            <span>v0.1.0 // RUST + WEBGPU</span>
          </div>
        </div>

        {/* Center: Navigation Links */}
        <nav className="hidden md:flex items-center gap-7 text-xs font-mono text-[#888888]">
          <a
            href="#architecture"
            className="hover:text-white transition-none no-underline"
          >
            Architecture
          </a>
          <a
            href="#migration"
            className="hover:text-white transition-none no-underline"
          >
            Migration
          </a>
          <a
            href="#benchmarks"
            className="hover:text-white transition-none no-underline"
          >
            Benchmarks
          </a>
          <a
            href="#terminal"
            className="hover:text-white transition-none no-underline"
          >
            Agentic Terminal
          </a>
          <a
            href="#pricing"
            className="hover:text-white transition-none no-underline"
          >
            Pricing
          </a>
        </nav>

        {/* Right: Actions */}
        <div className="flex items-center gap-2.5">
          {onLaunchWebEditor && (
            <button
              onClick={onLaunchWebEditor}
              className="hidden lg:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-none text-xs font-mono text-white bg-[#000000] hover:bg-white hover:text-black border border-[#222222] transition-none cursor-pointer"
            >
              <span>Launch Studio</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Primary Action Button */}
          <button
            onClick={onOpenWaitlist}
            className="inline-flex items-center gap-2 px-4 py-1.5 sm:py-2 rounded-none text-xs font-mono uppercase font-bold text-black bg-white hover:bg-[#111111] hover:text-white border border-white transition-none cursor-pointer"
          >
            <span>Join Waitlist</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      </div>
    </header>
  );
}
