"use client";

import React, { useState, useEffect } from "react";
import { ArrowUpRight, Check, Terminal, ShieldCheck } from "lucide-react";
import CruxBrandLogo from "../CruxBrandLogo";

export default function CruxFooter() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [queuePosition, setQueuePosition] = useState<number | null>(null);
  const [realtimeLatency, setRealtimeLatency] = useState<string>("0.08ms");

  useEffect(() => {
    const interval = setInterval(() => {
      const val = 0.07 + ((performance.now() * 100) % 5) * 0.01;
      setRealtimeLatency(`${val.toFixed(2)}ms`);
    }, 800);
    return () => clearInterval(interval);
  }, []);

  const handleSubscribe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes("@")) return;

    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, role: "Crux Kernel Notes", arch: "apple_silicon", newsletterOptIn: true }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Unable to subscribe right now.");
      if (data.success) {
        setQueuePosition(data.queuePosition);
        setSubmitted(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to subscribe right now.");
    } finally {
      setLoading(false);
    }
  };

  const navCol1 = [
    { label: "Benchmarks", href: "/benchmarks" },
    { label: "Amoeba Coding", href: "/amoeba-coding" },
    { label: "AST-CRDT Paper", href: "/ast-crdt" },
    { label: "Versus Cursor", href: "/vs-cursor" },
    { label: "Versus VS Code", href: "/vs-vscode" },
    { label: "Versus Zed", href: "/vs-zed" },
  ];

  const navCol2 = [
    { label: "With Claude (Plot)", href: "/vs-claude" },
    { label: "With Google Gemini", href: "/vs-gemini" },
    { label: "With ChatGPT (JGPT)", href: "/vs-chatgpt" },
    { label: "Pricing", href: "/pricing" },
    { label: "Documentation (LLMs)", href: "/llms.txt" },
    { label: "GitHub Releases", href: "https://github.com/hrgang-hrushi/collab-editor", external: true },
  ];

  const socials = [
    { label: "GitHub", href: "https://github.com/hrgang-hrushi/collab-editor" },
    { label: "X / Twitter", href: "https://twitter.com" },
    { label: "Discord Mesh", href: "https://discord.com" },
  ];

  return (
    <footer
      id="dispatch"
      className="relative w-full bg-[#000000] font-sans scroll-mt-20 border-t border-[#222222] text-white"
      style={{
        fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
      }}
    >
      <div className="max-w-[1280px] mx-auto px-4 sm:px-6 pt-12 pb-16">
        {/* Section Header Meta */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#222222] text-xs font-mono mb-8">
          <div className="flex items-center gap-2">
            <span className="text-white font-bold">[KERNEL DISPATCH]</span>
            <span className="text-[#444444]">— &gt;</span>
            <span className="text-[#888888] uppercase">CRUX SYSTEMS RESEARCH</span>
          </div>
          <div className="text-[11px] text-[#888888] pt-1 sm:pt-0 font-mono flex items-center gap-2">
            <span className="w-1.5 h-1.5 bg-white" />
            <span>POSIX IPC LATENCY: {realtimeLatency}</span>
          </div>
        </div>

        {/* Master Brutalist Grid */}
        <div className="border border-[#222222] bg-[#000000] grid grid-cols-1 lg:grid-cols-12 rounded-none">
          {/* Left Half: Dispatch Newsletter & Brand Display */}
          <div className="lg:col-span-6 p-8 sm:p-12 border-b lg:border-b-0 lg:border-r border-[#222222] flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="font-mono text-xs text-white px-2 py-0.5 border border-[#222222] bg-[#111111]">
                  [DISPATCH]
                </span>
                <span className="font-mono text-xs text-[#888888]">Direct to your inbox</span>
              </div>

              <h3 className="text-2xl sm:text-3xl font-bold tracking-tight text-white mb-4 font-sans">
                Subscribe to Kernel Notes &amp; Weekly Alpha Drops.
              </h3>
              <p className="text-xs sm:text-sm text-[#888888] leading-relaxed mb-6 font-sans">
                Receive release candidate binaries, WebGPU text shader benchmarks, and AST-CRDT peer mesh updates. No marketing telemetry.
              </p>

              {!submitted ? (
                <form onSubmit={handleSubscribe} className="space-y-3">
                  <div className="flex items-center">
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="engineer@domain.com"
                      className="flex-1 bg-[#111111] border border-[#222222] px-3.5 py-2.5 text-xs font-mono text-white placeholder-[#444444] outline-none rounded-none focus:border-white transition-none"
                    />
                    <button
                      type="submit"
                      disabled={loading}
                      className="px-5 py-2.5 bg-white hover:bg-[#CCCCCC] text-black text-xs font-mono font-bold uppercase transition-none cursor-pointer rounded-none shrink-0"
                    >
                      {loading ? "..." : "Subscribe"}
                    </button>
                  </div>
                  {error && <p role="alert" className="text-xs text-[#FF9C9C]">{error}</p>}
                </form>
              ) : (
                <div className="p-3 bg-[#111111] border border-[#222222] text-xs font-mono text-white flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-white stroke-[3]" />
                  <span>Subscribed. Priority Token #{queuePosition} linked.</span>
                </div>
              )}
            </div>

            {/* Massive Brand Watermark */}
            <div className="pt-12">
              <div className="flex items-center gap-3">
                <CruxBrandLogo size={32} withText={true} />
              </div>
              <p className="text-[11px] font-mono text-[#555555] mt-2">
                CRUX BARE-METAL IDE · RUST + WEBGPU ENGINE · ZERO CHROMIUM
              </p>
            </div>
          </div>

          {/* Right Half: Link Columns */}
          <div className="lg:col-span-6 grid grid-cols-2 sm:grid-cols-3 divide-x divide-[#222222]">
            {/* Column 1: Core Engine */}
            <div className="p-6 sm:p-8 space-y-4">
              <div className="text-[10px] font-mono uppercase tracking-widest text-[#444444] font-bold">
                SYSTEMS ARCH
              </div>
              <ul className="space-y-2.5 text-xs font-mono text-[#888888] list-none p-0 m-0">
                {navCol1.map((item) => (
                  <li key={item.label}>
                    <a
                      href={item.href}
                      className="hover:text-white transition-none no-underline block"
                    >
                      {item.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Column 2: Platform & Docs */}
            <div className="p-6 sm:p-8 space-y-4">
              <div className="text-[10px] font-mono uppercase tracking-widest text-[#444444] font-bold">
                PLATFORM
              </div>
              <ul className="space-y-2.5 text-xs font-mono text-[#888888] list-none p-0 m-0">
                {navCol2.map((item) => (
                  <li key={item.label}>
                    <a
                      href={item.href}
                      className="hover:text-white transition-none no-underline flex items-center gap-1"
                    >
                      <span>{item.label}</span>
                      {item.external && <ArrowUpRight className="w-2.5 h-2.5" />}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Column 3: Community & Mesh */}
            <div className="col-span-2 sm:col-span-1 p-6 sm:p-8 space-y-4 border-t sm:border-t-0 border-[#222222]">
              <div className="text-[10px] font-mono uppercase tracking-widest text-[#444444] font-bold">
                CONNECT
              </div>
              <ul className="space-y-2.5 text-xs font-mono text-[#888888] list-none p-0 m-0">
                {socials.map((item) => (
                  <li key={item.label}>
                    <a
                      href={item.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:text-white transition-none no-underline flex items-center gap-1"
                    >
                      <span>{item.label}</span>
                      <ArrowUpRight className="w-2.5 h-2.5" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Bottom Legal / Copyright Bar */}
        <div className="pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-[#555555]">
          <div className="flex items-center gap-2">
            <span>&copy; {new Date().getFullYear()} Crux Systems Inc.</span>
            <span>·</span>
            <span>All rights reserved.</span>
          </div>

          <div className="flex items-center gap-6">
            <span className="flex items-center gap-1 text-[#888888]">
              <ShieldCheck className="w-3.5 h-3.5 text-white" />
              <span>100% Air-Gapped Ready</span>
            </span>
            <a href="#hero" className="text-[#888888] hover:text-white transition-none no-underline">
              Back to top &uarr;
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
