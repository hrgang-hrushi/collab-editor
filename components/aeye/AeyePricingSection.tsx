"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Check, ArrowRight, ShieldCheck, Terminal, Cpu, Zap, Mail, Phone, Building } from "lucide-react";

export default function AeyePricingSection() {
  const [email, setEmail] = useState("");
  const [contact, setContact] = useState("");
  const [teamSize, setTeamSize] = useState("Individual");
  const [company, setCompany] = useState("");
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [ticketId, setTicketId] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes("@")) {
      setError("Please provide a valid work email address.");
      return;
    }
    if (!contact || contact.trim().length < 7) {
      setError("Please provide a valid phone or direct contact number.");
      return;
    }

    setError("");
    // Generate deterministic brutalist ticket ID
    const randomHex = Math.random().toString(16).substring(2, 8).toUpperCase();
    const generatedId = `CRUX-ALPHA-${randomHex}`;
    setTicketId(generatedId);
    setIsSubmitted(true);

    try {
      localStorage.setItem(
        "crux_waitlist_ticket",
        JSON.stringify({ ticketId: generatedId, email, contact, teamSize, date: new Date().toISOString() })
      );
    } catch (_) {}
  };

  const perks = [
    {
      icon: Cpu,
      title: "Bare-Metal Silicon Runtime",
      desc: "Native Rust kernel executing directly with WebGPU acceleration and 0 Chromium memory overhead.",
    },
    {
      icon: Zap,
      title: "Decentralized AST-CRDT Sync",
      desc: "Sub-15ms peer-to-peer live collaboration mesh over encrypted WebRTC data channels.",
    },
    {
      icon: Terminal,
      title: "Autonomous @CruxAI Kernel",
      desc: "HyperTerminal agent executing background refactors, AST diffs, and sandboxed test suites.",
    },
    {
      icon: ShieldCheck,
      title: "Zero Cloud Telemetry Lock-In",
      desc: "Complete local filesystem residency with air-gapped buffer editing and self-hostable relays.",
    },
  ];

  return (
    <section
      id="waitlist"
      className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden"
    >
      {/* Anchor compatibility for existing #pricing links */}
      <div id="pricing" className="absolute -top-20" />

      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[N.08/11]</span>
            <span className="text-[#888888]">— &gt;</span>
            <span className="text-[#888888] uppercase">EARLY ACCESS // WAITLIST</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            BATCH ONBOARDING · Q3/Q4 2026
          </div>
        </div>

        {/* Section Title & Subtitle */}
        <div className="pt-10 pb-14">
          <h2 className="text-3xl sm:text-5xl lg:text-[54px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
            Join the private alpha.
            <span className="block text-[#888888]">
              Bare-metal collaborative speed.
            </span>
          </h2>
          <p className="mt-4 text-xs sm:text-sm text-[#888888] font-sans max-w-2xl leading-relaxed">
            We are onboarding developer teams in weekly batches. Register your work email and direct contact number to receive your cryptographic access token and macOS/Linux installer.
          </p>
        </div>

        {/* Main Waitlist Console Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 border border-[#222222] divide-y lg:divide-y-0 lg:divide-x divide-[#222222] bg-[#000000]">
          {/* Left Form Panel */}
          <div className="lg:col-span-7 p-8 sm:p-12 bg-[#050507]">
            <AnimatePresence mode="wait">
              {!isSubmitted ? (
                <motion.form
                  key="form"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  onSubmit={handleSubmit}
                  className="space-y-6"
                >
                  <div className="flex items-center justify-between pb-4 border-b border-[#222222] text-xs font-mono text-[#888888]">
                    <span className="text-white font-semibold flex items-center gap-2">
                      <span className="w-2 h-2 bg-[#0055FF]" />
                      ALPHA APPLICATION CONSOLE
                    </span>
                    <span>SLOTS REMAINING: 42</span>
                  </div>

                  {error && (
                    <div className="p-3 border border-red-500/50 bg-red-950/20 text-red-400 font-mono text-xs">
                      {error}
                    </div>
                  )}

                  {/* Input 1: Work Email */}
                  <div>
                    <label className="block text-xs font-mono text-[#888888] mb-2 uppercase">
                      [01] Work Email <span className="text-[#0055FF]">*</span>
                    </label>
                    <div className="relative">
                      <input
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="engineer@company.com"
                        className="w-full h-12 bg-[#0c0c0e] border border-[#222222] px-4 font-mono text-sm text-white placeholder-[#444444] focus:border-white focus:outline-none transition-none rounded-none"
                      />
                    </div>
                  </div>

                  {/* Input 2: Contact / Phone Number */}
                  <div>
                    <label className="block text-xs font-mono text-[#888888] mb-2 uppercase">
                      [02] Contact / Phone Number <span className="text-[#0055FF]">*</span>
                    </label>
                    <div className="relative">
                      <input
                        type="tel"
                        required
                        value={contact}
                        onChange={(e) => setContact(e.target.value)}
                        placeholder="+1 (555) 019-2834"
                        className="w-full h-12 bg-[#0c0c0e] border border-[#222222] px-4 font-mono text-sm text-white placeholder-[#444444] focus:border-white focus:outline-none transition-none rounded-none"
                      />
                    </div>
                  </div>

                  {/* Optional: Team Role & Company */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-mono text-[#888888] mb-2 uppercase">
                        [03] Company / Org
                      </label>
                      <input
                        type="text"
                        value={company}
                        onChange={(e) => setCompany(e.target.value)}
                        placeholder="Acme Systems / Solo"
                        className="w-full h-12 bg-[#0c0c0e] border border-[#222222] px-4 font-mono text-sm text-white placeholder-[#444444] focus:border-white focus:outline-none transition-none rounded-none"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-mono text-[#888888] mb-2 uppercase">
                        [04] Team Configuration
                      </label>
                      <select
                        value={teamSize}
                        onChange={(e) => setTeamSize(e.target.value)}
                        className="w-full h-12 bg-[#0c0c0e] border border-[#222222] px-4 font-mono text-xs text-white focus:border-white focus:outline-none transition-none rounded-none appearance-none"
                      >
                        <option value="Individual">Solo Engineer (1 seat)</option>
                        <option value="Small Team">Engineering Team (2-10 seats)</option>
                        <option value="Enterprise">Enterprise / Scale (10+ seats)</option>
                      </select>
                    </div>
                  </div>

                  {/* Submit Button */}
                  <div className="pt-4">
                    <button
                      type="submit"
                      className="w-full h-14 bg-white text-black hover:bg-[#0055FF] hover:text-white transition-none font-sans font-medium text-sm tracking-wider uppercase flex items-center justify-center gap-3 cursor-pointer rounded-none"
                    >
                      <span className="w-2 h-2 bg-current" />
                      REQUEST ALPHA ACCESS TOKEN
                    </button>
                    <p className="mt-3 text-[11px] font-mono text-[#555555] text-center">
                      ZERO SPAM GUARANTEE · PURE CODE &amp; BINARY RELEASES ONLY
                    </p>
                  </div>
                </motion.form>
              ) : (
                /* Ticket Confirmation Receipt matching hardware brutalist aesthetic */
                <motion.div
                  key="confirmation"
                  initial={{ opacity: 0, scale: 0.98 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="space-y-6"
                >
                  <div className="border border-[#0055FF] bg-[#0055FF]/10 p-6 space-y-4">
                    <div className="flex items-center justify-between pb-3 border-b border-[#0055FF]/30">
                      <div className="flex items-center gap-2">
                        <Check className="w-5 h-5 text-[#0055FF]" />
                        <span className="font-mono text-sm font-bold text-white tracking-wider">
                          ACCESS TICKET ISSUED
                        </span>
                      </div>
                      <span className="font-mono text-xs text-[#0055FF] font-bold">
                        #{ticketId}
                      </span>
                    </div>

                    <div className="space-y-2 font-mono text-xs text-[#aaaaaa] leading-relaxed">
                      <div className="flex justify-between py-1 border-b border-[#222222]">
                        <span className="text-[#666666]">REGISTERED EMAIL:</span>
                        <span className="text-white font-semibold">{email}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-[#222222]">
                        <span className="text-[#666666]">CONTACT NUMBER:</span>
                        <span className="text-white font-semibold">{contact}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-[#222222]">
                        <span className="text-[#666666]">TEAM CONFIGURATION:</span>
                        <span className="text-white">{teamSize}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-[#222222]">
                        <span className="text-[#666666]">INVITATION QUEUE:</span>
                        <span className="text-[#0055FF] font-bold">BATCH #14 (NEXT IN LINE)</span>
                      </div>
                      <div className="flex justify-between py-1">
                        <span className="text-[#666666]">ESTIMATED DISPATCH:</span>
                        <span className="text-white">24 - 48 HOURS</span>
                      </div>
                    </div>
                  </div>

                  <p className="text-xs font-mono text-[#888888] leading-relaxed">
                    A verification ping and download credential have been queued for your contact. You can test the web playground in the meantime.
                  </p>

                  <div className="flex gap-4 pt-2">
                    <a
                      href="/?app=true"
                      className="px-6 py-3 bg-white text-black hover:bg-[#0055FF] hover:text-white transition-none font-sans text-xs tracking-wider uppercase font-medium flex items-center gap-2"
                    >
                      <span className="w-1.5 h-1.5 bg-current" />
                      TEST WEB DEMO NOW
                    </a>
                    <button
                      onClick={() => setIsSubmitted(false)}
                      className="px-4 py-3 border border-[#333333] text-[#888888] hover:text-white hover:border-white transition-none font-mono text-xs uppercase"
                    >
                      RESET FORM
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Right Perks & Specifications Panel */}
          <div className="lg:col-span-5 p-8 sm:p-12 bg-[#000000] flex flex-col justify-between">
            <div>
              <div className="text-xs font-mono text-[#0055FF] font-semibold uppercase tracking-wider mb-2">
                WHAT EARLY ACCESS INCLUDES
              </div>
              <h3 className="text-xl font-medium text-white font-sans">
                Full developer workstation capabilities from Day 1.
              </h3>

              <div className="mt-8 space-y-6">
                {perks.map((p, idx) => {
                  const Icon = p.icon;
                  return (
                    <div key={idx} className="flex items-start gap-4">
                      <div className="w-8 h-8 border border-[#222222] bg-[#0c0c0e] flex items-center justify-center shrink-0 text-[#0055FF]">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <h4 className="text-sm font-medium text-white font-sans">
                          {p.title}
                        </h4>
                        <p className="mt-1 text-xs text-[#71717a] font-sans leading-relaxed">
                          {p.desc}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="mt-12 pt-6 border-t border-[#1a1a1e] font-mono text-[11px] text-[#555555] flex items-center justify-between">
              <span>SECURITY: ED25519 VERIFIED</span>
              <span>HOST ARCH: APPLE SILICON / X86_64</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
