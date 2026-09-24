"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import { Check, ArrowRight } from "lucide-react";

export default function AeyePricingSection() {
  const [billingCycle, setBillingCycle] = useState<"monthly" | "annually">("monthly");
  const [teamSeats, setTeamSeats] = useState<number>(5);

  const plans = [
    {
      name: "Community",
      description: "For individual builders and hackers",
      monthlyPrice: 0,
      annualPrice: 0,
      popular: false,
      featuresTitle: "Includes:",
      features: [
        "Native Rust + WebGPU core",
        "Local buffer editing & Git support",
        "2-seat peer-to-peer live sync",
        "Community Discord support",
      ],
      cta: "DOWNLOAD FREE",
      href: "/?app=true",
    },
    {
      name: "Pro Engineer",
      description: "For high-velocity professional engineers",
      monthlyPrice: 16,
      annualPrice: 12.8,
      popular: true,
      featuresTitle: "Includes everything in Community, plus:",
      features: [
        "Unlimited collaborative P2P seats",
        "Full @CruxAI agent in HyperTerminal",
        "Sub-15ms WebGPU latency pipeline",
        "Instant VS Code extension migration",
        "Direct priority developer support",
      ],
      cta: "START FREE TRIAL",
      href: "/?app=true",
    },
    {
      name: "Enterprise Team",
      description: "For engineering teams requiring compliance & self-hosting",
      monthlyPrice: 39,
      annualPrice: 31.2,
      popular: false,
      featuresTitle: "Includes everything in Community & Pro, plus:",
      features: [
        "Dedicated on-prem sync relays",
        "Air-gapped local model inference",
        "SOC2 Type II + SSO / SAML",
        "Custom AST static analysis plugins",
        "24/7 dedicated engineering SLA",
      ],
      cta: "DEPLOY CRUX",
      href: "#contact",
    },
  ];

  return (
    <section id="pricing" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono"
        >
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[n. 08 / 11 ]</span>
            <span className="text-[#0055FF] font-bold">&gt;</span>
            <span className="text-[#888888]">Pricing</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0">
            TRANSPARENT DEVELOPER &amp; TEAM SEATS
          </div>
        </motion.div>

        {/* Section Title & Subtitle + Billing Toggle */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
          className="pt-8 pb-14 flex flex-col md:flex-row md:items-end justify-between gap-6"
        >
          <div>
            <h2 className="text-3xl sm:text-5xl lg:text-[54px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
              Predictable pricing.{" "}
              <span className="text-[#444444] block sm:inline">
                Bare-metal performance.
              </span>
            </h2>
          </div>

          {/* Brutalist Sharp Billing Toggle */}
          <div className="inline-flex items-center border border-[#222222] bg-[#111111] p-1 rounded-none self-start md:self-auto">
            <button
              onClick={() => setBillingCycle("monthly")}
              className={`px-4 py-1.5 text-xs font-mono uppercase tracking-wider transition-none cursor-pointer rounded-none ${
                billingCycle === "monthly"
                  ? "bg-white text-black font-bold"
                  : "bg-transparent text-[#888888] hover:text-white"
              }`}
            >
              Monthly
            </button>
            <button
              onClick={() => setBillingCycle("annually")}
              className={`px-4 py-1.5 text-xs font-mono uppercase tracking-wider transition-none cursor-pointer rounded-none flex items-center gap-2 ${
                billingCycle === "annually"
                  ? "bg-white text-black font-bold"
                  : "bg-transparent text-[#888888] hover:text-white"
              }`}
            >
              <span>Annually</span>
              <span className="px-1.5 py-0.5 bg-[#222222] text-[9px] text-white font-mono font-bold">
                -20%
              </span>
            </button>
          </div>
        </motion.div>

        {/* 3 Pricing Cards Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 border border-[#222222] divide-y lg:divide-y-0 lg:divide-x divide-[#222222] bg-[#000000]">
          {plans.map((p, idx) => {
            const price =
              billingCycle === "monthly"
                ? p.monthlyPrice.toFixed(2)
                : p.annualPrice.toFixed(2);

            return (
              <div
                key={idx}
                className={`p-8 sm:p-10 flex flex-col justify-between min-h-[520px] relative transition-none bg-[#000000] rounded-none ${
                  p.popular
                    ? "border-t-2 lg:border-t-0 lg:border-l-2 border-[#0055FF] bg-[#0055FF]/5"
                    : "hover:bg-[#111111]"
                }`}
              >
                {/* Popular Badge */}
                {p.popular && (
                  <div className="absolute top-5 right-5 px-2.5 py-0.5 border border-[#0055FF] bg-[#0055FF] text-white text-[10px] font-mono uppercase tracking-wider font-bold rounded-none">
                    MOST POPULAR
                  </div>
                )}

                <div>
                  <div className={`text-2xl font-bold tracking-tight font-sans ${p.popular ? "text-[#0055FF]" : "text-white"}`}>
                    {p.name}
                  </div>
                  <p className="mt-1 text-xs text-[#888888] font-sans">
                    {p.description}
                  </p>

                  {/* Price */}
                  <div className="mt-8 pb-6 border-b border-[#222222] flex items-baseline gap-1">
                    <span className="text-4xl sm:text-5xl font-normal text-white font-sans tracking-tight">
                      ${price}
                    </span>
                    <span className="text-xs font-mono text-[#888888]">
                      / seat / month
                    </span>
                  </div>

                  {/* Features List */}
                  <div className="mt-6">
                    <div className="text-xs font-mono uppercase tracking-wider text-white font-semibold mb-4">
                      {p.featuresTitle}
                    </div>
                    <ul className="space-y-3 p-0 m-0 list-none">
                      {p.features.map((feat, fidx) => (
                        <li
                          key={fidx}
                          className="flex items-center gap-2.5 text-xs text-[#d4d4d8] font-sans"
                        >
                          <span className={`w-4 h-4 border flex items-center justify-center flex-shrink-0 rounded-none ${p.popular ? "border-[#0055FF] bg-[#0055FF]/20 text-[#0055FF]" : "border-[#222222] bg-[#111111] text-white"}`}>
                            <Check className="w-2.5 h-2.5 stroke-[3]" />
                          </span>
                          <span>{feat}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Card CTA */}
                <div className="mt-10 pt-6 border-t border-[#222222]">
                  <a
                    href={p.href}
                    className={`w-full py-3.5 text-xs font-mono uppercase tracking-wider flex items-center justify-center gap-2 transition-none no-underline cursor-pointer rounded-none ${
                      p.popular
                        ? "bg-[#0055FF] text-white hover:bg-[#0044CC] border border-[#0055FF] font-bold"
                        : "bg-[#111111] border border-[#222222] text-white hover:bg-white hover:text-black hover:border-white font-bold"
                    }`}
                  >
                    <span>{p.cta}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </a>
                </div>
              </div>
            );
          })}
        </div>

        {/* Interactive Team Estimator Slider */}
        <div className="mt-8 p-6 sm:p-8 border border-[#222222] bg-[#000000] flex flex-col md:flex-row md:items-center justify-between gap-6 font-mono">
          <div className="max-w-md">
            <div className="text-xs text-white font-bold uppercase tracking-wider">
              INFRASTRUCTURE ESTIMATOR // PRO &amp; ENTERPRISE
            </div>
            <div className="text-sm font-medium text-white mt-1">
              Scale collaborative concurrency for your team
            </div>
            <p className="text-xs text-[#888888] mt-1">
              Select team size to inspect total monthly bandwidth, P2P mesh connections, and dedicated relays.
            </p>
          </div>

          <div className="flex-1 max-w-sm flex flex-col gap-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#888888]">TEAM SIZE:</span>
              <span className="text-white font-bold">{teamSeats} ENGINEERS</span>
            </div>
            <input
              type="range"
              min={1}
              max={50}
              value={teamSeats}
              onChange={(e) => setTeamSeats(Number(e.target.value))}
              className="w-full accent-white bg-[#222222] h-1.5 cursor-pointer"
            />
            <div className="flex items-center justify-between text-[11px] text-[#888888]">
              <span>EST. ESTIMATED COST: ${(teamSeats * (billingCycle === "monthly" ? 16 : 12.8)).toFixed(0)}/mo</span>
              <span className="text-white font-bold font-mono">SAVINGS: 42% VS ELECTRON</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
