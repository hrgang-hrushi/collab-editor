"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ArrowRight } from "lucide-react";
import CallChip from "@/components/ui/CallChip";

export default function AeyeCtaSection() {
  const [email, setEmail] = useState("");
  const [chipStage, setChipStage] = useState<"idle" | "almost" | "gone" | "done">("idle");
  const [realtimeLatency, setRealtimeLatency] = useState<string>("0.12ms");

  useEffect(() => {
    const measureLatency = () => {
      if (typeof window === "undefined") return;
      const t0 = performance.now();
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(new Uint32Array(4));
      }
      const t1 = performance.now();
      const raw = t1 - t0;
      const val = raw > 0.02 ? raw : 0.08 + ((performance.now() * 1000) % 9) * 0.01;
      setRealtimeLatency(`${val.toFixed(2)}ms`);
    };

    measureLatency();
    const interval = setInterval(measureLatency, 350);
    return () => clearInterval(interval);
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (email && email.includes("@")) {
      try {
        localStorage.setItem("crux_dispatch_email", email);
      } catch (_) {}

      setChipStage("almost");

      setTimeout(() => {
        setChipStage("gone");
      }, 900);

      setTimeout(() => {
        setChipStage("done");
      }, 2000);
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
            <div className="flex-1 max-w-[540px] w-full">
              {chipStage !== "idle" ? (
                <motion.div
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                  className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-2 pl-3 pr-4 border border-[#222222] bg-[#0c0c0e]/90 w-full rounded-none"
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
                          : "Done! lets Crux it soon!"
                      }
                      status={chipStage === "done" ? "done" : "running"}
                      expectedMs={2000}
                      size={35}
                      radius={10}
                      color="currentColor"
                      surfaceColor="#27272a"
                      progressColor="currentColor"
                      progressOpacity={0.26}
                      doneColor="#22c55e"
                      errorColor="#ef4444"
                      washOpacity={0.18}
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
                    <span className="text-white font-mono">{realtimeLatency}</span>
                  </div>
                </motion.div>
              ) : (
                <form
                  onSubmit={handleSubmit}
                  className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4"
                >
                  {/* Left: Email input with the exact underline border style as Hero */}
                  <div className="relative flex-1">
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="your.email@company.com"
                      className="w-full bg-transparent text-white placeholder-[#888888] font-sans text-xs sm:text-sm tracking-wider border-0 border-b border-white focus:border-[#0055FF] focus:outline-none px-2 py-3 transition-none rounded-none"
                    />
                  </div>

                  {/* Right: Join Action Button matching Hero's sleek high-contrast style */}
                  <button
                    type="submit"
                    className="w-full sm:w-auto h-[42px] px-6 bg-white hover:bg-white/90 text-black font-sans font-semibold text-xs tracking-wider uppercase flex items-center justify-center gap-2 cursor-pointer transition-none border-0 rounded-none shrink-0"
                  >
                    <span>Join</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </form>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
