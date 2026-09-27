"use client";

import React, { useState, useEffect } from "react";

export default function AeyeCtaSection() {
  const words = ["accelerated", "collaborative", "bare-metal", "decentralized", "uncompromised"];
  const [wordIndex, setWordIndex] = useState(0);
  const [charIndex, setCharIndex] = useState(words[0].length);
  const [isDeleting, setIsDeleting] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;

    const currentWord = words[wordIndex];
    let timeout: NodeJS.Timeout;

    if (!isDeleting && charIndex === currentWord.length) {
      // Pause when the word is fully typed
      timeout = setTimeout(() => {
        setIsDeleting(true);
      }, 2400);
    } else if (isDeleting && charIndex === 0) {
      // Move to next word when completely erased
      setIsDeleting(false);
      setWordIndex((prev) => (prev + 1) % words.length);
    } else {
      // Typing or deleting characters
      const speed = isDeleting ? 45 : 90;
      timeout = setTimeout(() => {
        setCharIndex((prev) => prev + (isDeleting ? -1 : 1));
      }, speed);
    }

    return () => clearTimeout(timeout);
  }, [charIndex, isDeleting, wordIndex, mounted, words]);

  const currentDisplay = mounted ? words[wordIndex].substring(0, charIndex) : "accelerated";
  const isCompleteWord = mounted ? (!isDeleting && charIndex === words[wordIndex].length) : true;

  return (
    <section id="cta" className="relative w-full bg-[#000000] select-none overflow-hidden scroll-mt-14 border-t border-[#222222]">

      {/* 2. DARK GRID WORKSPACE CANVAS */}
      <div
        className="relative w-full py-20 sm:py-24 md:py-28 px-4 sm:px-8 bg-[#0d0e12] overflow-hidden"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(255, 255, 255, 0.07) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255, 255, 255, 0.07) 1px, transparent 1px)
          `,
          backgroundSize: "64px 64px",
          backgroundPosition: "center center",
        }}
      >
        {/* 3. CENTER CTA CARD (Pure White, 0px border-radius, 4 Corner Notch Squares) */}
        <div className="relative w-full max-w-[1140px] mx-auto bg-[#FFFFFF] py-16 sm:py-20 md:py-24 px-6 sm:px-12 text-center">
          {/* 4 SOLID CORNER NOTCH SQUARES */}
          <div
            className="absolute top-4 left-4 sm:top-5 sm:left-5 w-5 h-5 sm:w-6 sm:h-6 bg-[#000000] pointer-events-none"
            aria-hidden="true"
          />
          <div
            className="absolute top-4 right-4 sm:top-5 sm:right-5 w-5 h-5 sm:w-6 sm:h-6 bg-[#000000] pointer-events-none"
            aria-hidden="true"
          />
          <div
            className="absolute bottom-4 left-4 sm:bottom-5 sm:left-5 w-5 h-5 sm:w-6 sm:h-6 bg-[#000000] pointer-events-none"
            aria-hidden="true"
          />
          <div
            className="absolute bottom-4 right-4 sm:bottom-5 sm:right-5 w-5 h-5 sm:w-6 sm:h-6 bg-[#000000] pointer-events-none"
            aria-hidden="true"
          />

          {/* TOP TAG / BADGE */}
          <div className="inline-block mb-7 sm:mb-9">
            <span className="bg-[#EDEDED] text-[#444444] font-mono text-[11px] sm:text-xs tracking-wider uppercase px-3.5 py-1.5 inline-block">
              GET STARTED IN SECONDS
            </span>
          </div>

          {/* 3-LINE DISPLAY HEADLINE */}
          <div className="flex flex-col items-center justify-center leading-[1.05] tracking-[-0.05em]">
            {/* LINE 1 */}
            <h2 className="font-geist text-5xl sm:text-6xl md:text-7xl lg:text-[86px] font-normal text-[#111111] m-0">
              Engineering,
            </h2>

            {/* LINE 2: [word] in Geist Pixel Square with solid blue block cursor */}
            <div className="font-pixel text-5xl sm:text-6xl md:text-7xl lg:text-[86px] font-normal text-[#0055FF] flex items-center justify-center my-0.5 sm:my-1">
              <span>[{currentDisplay}{isCompleteWord ? "]" : ""}</span>
              <span
                className="inline-block bg-[#0055FF] w-[0.38em] h-[0.84em] ml-1.5 align-baseline"
                aria-hidden="true"
              />
            </div>

            {/* LINE 3 */}
            <h2 className="font-geist text-5xl sm:text-6xl md:text-7xl lg:text-[86px] font-normal text-[#111111] m-0">
              Built for raw silicon.
            </h2>
          </div>

          {/* ACTION BUTTON (Exact mechanical switch: pure black container, white square dot, GET ON WAITLIST NOW uppercase text) */}
          <div className="mt-8 sm:mt-12 flex justify-center">
            <a
              href="#waitlist"
              onClick={(e) => {
                const el = document.getElementById("waitlist") || document.getElementById("dispatch");
                if (el) {
                  e.preventDefault();
                  el.scrollIntoView({ behavior: "smooth" });
                }
              }}
              className="group inline-flex items-center gap-3.5 bg-[#141414] hover:bg-[#000000] text-white px-8 py-3.5 sm:px-9 sm:py-4 transition-all duration-150 cursor-pointer shadow-none"
            >
              {/* Left Solid White Square Dot */}
              <span className="w-2 h-2 sm:w-2.5 sm:h-2.5 bg-white shrink-0 group-hover:scale-95 transition-transform" />
              {/* Monospace Uppercase Text */}
              <span className="font-mono font-semibold text-xs sm:text-sm tracking-wider uppercase text-white">
                GET ON WAITLIST NOW
              </span>
            </a>
          </div>
        </div>
      </div>

    </section>
  );
}
