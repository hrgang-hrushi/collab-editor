"use client";

import React, { useState, useEffect } from "react";
import { ArrowRight, Terminal, Check, ShieldCheck } from "lucide-react";
import confetti from "canvas-confetti";
import { BorderBeam } from "@/components/ui/BorderBeam";

interface CruxCtaSectionProps {
  onOpenWaitlist?: () => void;
  onLaunchWebEditor?: () => void;
}

export default function CruxCtaSection({
  onOpenWaitlist,
  onLaunchWebEditor,
}: CruxCtaSectionProps) {
  const words = ["COLLABORATIVE", "BARE-METAL", "DECENTRALIZED", "UNCOMPROMISED"];
  const [wordIndex, setWordIndex] = useState(0);
  const [charIndex, setCharIndex] = useState(words[0].length);
  const [isDeleting, setIsDeleting] = useState(false);
  const [mounted, setMounted] = useState(false);

  // Quick email form state
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [queuePosition, setQueuePosition] = useState<number | null>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;

    const currentWord = words[wordIndex];
    let timeout: NodeJS.Timeout;

    if (!isDeleting && charIndex === currentWord.length) {
      timeout = setTimeout(() => {
        setIsDeleting(true);
      }, 2400);
    } else if (isDeleting && charIndex === 0) {
      setIsDeleting(false);
      setWordIndex((prev) => (prev + 1) % words.length);
    } else {
      const speed = isDeleting ? 45 : 85;
      timeout = setTimeout(() => {
        setCharIndex((prev) => prev + (isDeleting ? -1 : 1));
      }, speed);
    }

    return () => clearTimeout(timeout);
  }, [charIndex, isDeleting, wordIndex, mounted, words]);

  const currentDisplay = mounted ? words[wordIndex].substring(0, charIndex) : "COLLABORATIVE";

  const handleQuickSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes("@")) return;

    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, role: "systems", arch: "apple_silicon" }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Unable to join right now.");
      if (data.success) {
        setQueuePosition(data.queuePosition);
        setSubmitted(true);
        try {
          confetti({
            particleCount: 70,
            spread: 60,
            origin: { y: 0.7 },
            colors: ["#ffffff", "#cccccc", "#888888", "#222222"],
          });
        } catch {}
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to join right now.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section
      id="cta"
      className="relative w-full bg-[#000000] select-none overflow-hidden scroll-mt-14 border-t border-[#222222]"
      style={{
        fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
      }}
    >
      {/* Background Hairline Grid */}
      <div className="relative w-full py-20 sm:py-28 px-4 sm:px-8 bg-[#000000]">
        {/* Center Hardware Brutalist Card (White on Black contrast) */}
        <div className="relative w-full max-w-[1080px] mx-auto bg-white text-black py-16 sm:py-20 px-6 sm:px-12 text-center rounded-none border border-white">
          {/* Corner Notch Marks (Strict brutalism) */}
          <div className="absolute top-3 left-3 w-4 h-4 bg-black pointer-events-none" />
          <div className="absolute top-3 right-3 w-4 h-4 bg-black pointer-events-none" />
          <div className="absolute bottom-3 left-3 w-4 h-4 bg-black pointer-events-none" />
          <div className="absolute bottom-3 right-3 w-4 h-4 bg-black pointer-events-none" />

          {/* Top Tag */}
          <div className="inline-block mb-6">
            <span className="bg-black text-white font-mono text-[11px] uppercase tracking-widest px-3 py-1 inline-block">
              PUBLIC ARCHITECTURE PREVIEW · SEATS AVAILABLE
            </span>
          </div>

          {/* Main Headline */}
          <h2 className="text-4xl sm:text-6xl md:text-7xl font-bold tracking-tight text-black m-0 font-sans leading-[1.05]">
            Engineering,
          </h2>

          <div className="text-3xl sm:text-5xl md:text-6xl font-mono font-bold text-black flex items-center justify-center my-3 tracking-tight whitespace-nowrap h-[1.25em] leading-none overflow-hidden">
            <span className="whitespace-nowrap">[{currentDisplay}]</span>
            <span className="inline-block bg-black w-[16px] sm:w-[22px] h-[30px] sm:h-[42px] ml-1.5 align-baseline animate-pulse shrink-0" />
          </div>

          <p className="mt-6 text-sm sm:text-base text-[#444444] max-w-xl mx-auto font-sans leading-relaxed">
            Experience the native code editor built from bare silicon. Sub-15ms rendering, decentralized AST-CRDT peer mesh, and zero Chromium pauses.
          </p>

          {/* Direct Waitlist Fast Track */}
          <div className="mt-8 max-w-md mx-auto">
            {!submitted ? (
              <form onSubmit={handleQuickSubmit} className="flex flex-col sm:flex-row items-stretch gap-2">
                <BorderBeam
                  size="pulse-outside"
                  colorVariant="ocean"
                  strength={0.8}
                  theme="dark"
                  borderRadius={0}
                  className="flex-1 relative"
                >
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="Enter your email to reserve seat..."
                    className="w-full px-4 py-3 bg-[#000000] text-white placeholder-[#888888] font-mono text-xs outline-none rounded-none border border-[#222222] focus:border-white block"
                  />
                </BorderBeam>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-6 py-3 bg-black hover:bg-[#222222] text-white font-mono text-xs font-bold uppercase transition-none cursor-pointer rounded-none flex items-center justify-center gap-1.5 shrink-0"
                >
                  <span>{loading ? "Registering..." : "Join Waitlist"}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-white" />
                </button>
                {error && <p role="alert" className="text-xs text-[#A00000]">{error}</p>}
              </form>
            ) : (
              <div className="p-3 bg-black text-white font-mono text-xs flex items-center justify-center gap-3">
                <Check className="w-4 h-4 text-white stroke-[3]" />
                <span>
                  RESERVED: SPOT <strong>#{queuePosition}</strong> CONFIRMED
                </span>
              </div>
            )}
          </div>

          {/* Secondary Actions */}
          <div className="mt-8 pt-6 border-t border-[#DDDDDD] flex flex-wrap items-center justify-center gap-6 text-xs font-mono text-[#555555]">
            <span className="flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-black" />
              <span>100% Host Memory Safe</span>
            </span>
            <span>·</span>
            <span>Zero Cloud Telemetry Lock-In</span>
            <span>·</span>
            {onLaunchWebEditor && (
              <button
                type="button"
                onClick={onLaunchWebEditor}
                className="text-black font-bold underline hover:no-underline cursor-pointer"
              >
                Launch Studio In Browser &rarr;
              </button>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
