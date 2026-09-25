"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ArrowUpRight } from "lucide-react";
import CallChip from "@/components/ui/CallChip";

export default function AeyeFooter() {
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

  const pagesCol1 = [
    { label: "Home", href: "#hero" },
    { label: "Docs", href: "#document" },
    { label: "Blog", href: "#blog" },
    { label: "Waitlist", href: "#waitlist" },
    { label: "Changelog", href: "#changelog" },
    { label: "Terms", href: "#terms" },
  ];

  const pagesCol2 = [
    { label: "About", href: "#benefit" },
    { label: "Pricing", href: "#pricing" },
    { label: "Careers (4)", href: "#careers" },
    { label: "Contact", href: "#dispatch" },
    { label: "Architecture", href: "#performance" },
    { label: "Privacy", href: "#privacy" },
  ];

  const social = [
    { label: "X Twitter", href: "https://twitter.com" },
    { label: "GitHub", href: "https://github.com/hrgang-hrushi/collab-editor" },
    { label: "Discord", href: "https://discord.com" },
    { label: "Facebook", href: "https://facebook.com" },
    { label: "LinkedIn", href: "https://linkedin.com" },
  ];

  return (
    <footer id="dispatch" className="relative w-full bg-[#000000] font-sans scroll-mt-20 border-t border-[#222222]">
      <div className="max-w-[1280px] mx-auto px-4 sm:px-6 pt-12 pb-16">
        {/* Section Header Meta */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#222222] text-xs font-mono mb-8">
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[N.12/12]</span>
            <span className="text-[#888888]">— &gt;</span>
            <span className="text-[#888888] uppercase">CRUX INSIDER DISPATCH</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            DIRECT KERNEL NOTES · BI-WEEKLY
          </div>
        </div>

        {/* 2. Unified Master Grid Container (Exact Framer Blueprint) */}
        <div className="border border-[#222222] bg-[#000000] grid grid-cols-1 lg:grid-cols-12 rounded-none">
          {/* ============================================================ */}
          {/* LEFT HALF: DISPATCH NEWSLETTER & MASSIVE BRAND DISPLAY LOGO  */}
          {/* ============================================================ */}
          <div className="lg:col-span-6 p-8 sm:p-12 lg:p-14 border-b lg:border-b-0 lg:border-r border-[#222222] flex flex-col justify-between">
            <div>
              {/* Header Meta */}
              <div className="flex items-center gap-2 mb-3">
                <span className="font-mono text-base text-[#0055FF] font-bold">@</span>
                <span className="text-2xl sm:text-3xl font-medium tracking-tight text-white font-sans">
                  CRUX INSIDER DISPATCH
                </span>
              </div>

              {/* Sub-copy */}
              <p className="text-sm text-white font-sans leading-relaxed">
                Get priority builds, alpha features, and architecture release notes.
              </p>
              <p className="mt-1 text-xs text-[#888888] font-sans">
                Straight from the kernel engineers. No spam, ever.
              </p>

              {/* Form / CallChip Rail */}
              <div className="mt-8 max-w-md">
                {chipStage !== "idle" ? (
                  <motion.div
                    initial={{ opacity: 0, y: 8, scale: 0.98 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-2 pl-3 pr-4 border border-[#222222] bg-[#0c0c0e]/90 w-full rounded-none"
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

                    {/* Telemetry metadata */}
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
                    className="bg-[#111111] border border-[#222222] p-1.5 flex items-center justify-between gap-2 w-full rounded-none group focus-within:border-white transition-none"
                  >
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="your.email@company.com"
                      className="w-full bg-transparent text-white placeholder-[#555555] font-sans text-xs px-3 py-2 focus:outline-none rounded-none"
                    />

                    <button
                      type="submit"
                      className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-[#0e0e11] border border-[#333333] hover:border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none cursor-pointer rounded-none font-medium shrink-0 group/btn"
                    >
                      <span className="w-1.5 h-1.5 bg-white group-hover/btn:bg-black inline-block transition-none" />
                      <span>Join</span>
                    </button>
                  </form>
                )}
              </div>
            </div>

            {/* Massive Brand Wordmark anchoring the bottom left (matching Framer reference) */}
            <div className="mt-14 sm:mt-20 pt-6 flex items-baseline gap-2 select-none">
              <span
                className="font-brand font-black text-6xl sm:text-7xl lg:text-[84px] tracking-[0px] text-white leading-none select-none inline-block"
                style={{
                  fontFamily: "'Etna Sans Serif', 'Etna', sans-serif",
                }}
              >
                Crux
              </span>
              <span className="font-mono text-sm text-[#0055FF] font-bold">®</span>
            </div>
          </div>

          {/* ============================================================ */}
          {/* RIGHT HALF: PAGES, FOLLOW US & GET IN TOUCH                   */}
          {/* ============================================================ */}
          <div className="lg:col-span-6 flex flex-col justify-between">
            {/* Top Grid: Pages vs Follow Us */}
            <div className="grid grid-cols-1 sm:grid-cols-2 border-b border-[#222222] flex-1">
              {/* Pages Column */}
              <div className="p-8 border-b sm:border-b-0 sm:border-r border-[#222222]">
                <div className="text-xs font-mono uppercase tracking-wider text-white font-bold mb-6">
                  PAGES
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-3">
                  <div className="space-y-3">
                    {pagesCol1.map((p, idx) => (
                      <div key={idx}>
                        <a
                          href={p.href}
                          className="text-xs font-sans text-[#888888] hover:text-[#0055FF] transition-none no-underline block"
                        >
                          {p.label}
                        </a>
                      </div>
                    ))}
                  </div>
                  <div className="space-y-3">
                    {pagesCol2.map((p, idx) => (
                      <div key={idx}>
                        <a
                          href={p.href}
                          className="text-xs font-sans text-[#888888] hover:text-[#0055FF] transition-none no-underline block"
                        >
                          {p.label}
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Follow Us Column with dotted leader lines */}
              <div className="p-8">
                <div className="text-xs font-mono uppercase tracking-wider text-white font-bold mb-6">
                  FOLLOW US
                </div>
                <div className="space-y-4">
                  {social.map((s, idx) => (
                    <a
                      key={idx}
                      href={s.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-between text-xs font-mono text-[#888888] hover:text-white transition-none no-underline group"
                    >
                      <span className="shrink-0 group-hover:text-white transition-none">{s.label}</span>
                      <span className="flex-1 border-b border-dotted border-[#333333] mx-2 group-hover:border-white transition-none" />
                      <ArrowUpRight className="w-3.5 h-3.5 text-[#555555] group-hover:text-[#0055FF] transition-none shrink-0" />
                    </a>
                  ))}
                </div>
              </div>
            </div>

            {/* Bottom Row: GET IN TOUCH */}
            <div className="p-8 sm:p-10 bg-[#08080a] flex flex-col justify-center space-y-2 text-xs font-mono">
              <div className="text-xs uppercase tracking-wider text-white font-bold mb-1">
                GET IN TOUCH
              </div>
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[#888888]">
                <div>
                  <span className="text-[#444444]">MAIL // </span>
                  <a href="mailto:core@codecrux.us" className="text-white hover:text-[#0055FF] transition-none underline">
                    core@codecrux.us
                  </a>
                </div>
                <div>
                  <span className="text-[#444444]">LOC // </span>
                  <span className="text-[#cccccc]">San Francisco, CA &amp; Global Mesh</span>
                </div>
                <div>
                  <span className="text-[#444444]">STATUS // </span>
                  <span className="text-[#0055FF] font-semibold">● KERNEL ONLINE</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* 3. Bottom Bar: Copyright & Attribution */}
        <div className="pt-8 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-[11px] font-mono text-[#555555]">
          <div>
            © Crux 2026 | Built for High-Velocity Engineering · All rights reserved.
          </div>
          <div className="flex items-center gap-4">
            <a href="#privacy" className="hover:text-[#0055FF] transition-none no-underline">
              Privacy Policy
            </a>
            <span>/</span>
            <a href="#terms" className="hover:text-[#0055FF] transition-none no-underline">
              Terms of Service
            </a>
            <span>/</span>
            <span>
              Engineered by <strong className="text-[#0055FF]">Crux Team</strong>
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}
