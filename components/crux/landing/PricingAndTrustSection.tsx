"use client";

import React from "react";
import { Check, ArrowRight, ShieldCheck, Zap, Terminal } from "lucide-react";

interface PricingAndTrustSectionProps {
  onOpenWaitlist: () => void;
}

export default function PricingAndTrustSection({ onOpenWaitlist }: PricingAndTrustSectionProps) {
  return (
    <section id="pricing" className="py-24 px-6 max-w-6xl mx-auto border-t border-[#222222]">
      {/* Trust & Engineering Pedigree Sub-Bar */}
      <div className="mb-20 text-center">
        <div className="text-[11px] font-mono uppercase tracking-widest text-[#888888] mb-8">
          ENGINEERED WITH STANDARDS FROM WORLD-CLASS SYSTEMS ARCHITECTURES
        </div>
        <div className="flex flex-wrap items-center justify-center gap-8 sm:gap-14">
          <div className="flex items-center gap-2 text-xs font-mono text-[#888888]">
            <span className="w-1.5 h-1.5 rounded-none bg-white" />
            <span className="font-bold text-white">Y Combinator</span>
            <span className="text-[#444444]">· Backed Lineage</span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-[#888888]">
            <span className="w-1.5 h-1.5 rounded-none bg-white" />
            <span className="font-bold text-white">Rust Foundation</span>
            <span className="text-[#444444]">· Memory Safe</span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-[#888888]">
            <span className="w-1.5 h-1.5 rounded-none bg-white" />
            <span className="font-bold text-white">Apple Silicon</span>
            <span className="text-[#444444]">· M1/M2/M3/M4 Metal</span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-[#888888]">
            <span className="w-1.5 h-1.5 rounded-none bg-white" />
            <span className="font-bold text-white">W3C WebGPU</span>
            <span className="text-[#444444]">· Sub-15ms Latency</span>
          </div>
        </div>
      </div>

      {/* Pricing Header */}
      <div className="text-center max-w-2xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-none bg-[#111111] border border-[#222222] text-white text-xs font-mono mb-4">
          <Zap className="w-3.5 h-3.5 text-white fill-current" />
          <span>[TRANSPARENT, PERFORMANCE-FIRST PRICING]</span>
        </div>
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-white mb-4 font-sans">
          Built for Solo Engineers &amp; High-Velocity Teams.
        </h2>
        <p className="text-sm sm:text-base text-[#888888] leading-relaxed font-sans">
          The core native editor is free forever. Upgrade for real-time team AST-CRDT clusters and managed cloud relays.
        </p>
      </div>

      {/* 3 Pricing Cards */}
      <div
        className="grid grid-cols-1 md:grid-cols-3 gap-6"
        style={{
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
        }}
      >
        {/* Tier 1: Community / Open Core */}
        <div className="p-8 rounded-none bg-[#000000] border border-[#222222] flex flex-col justify-between hover:border-white transition-none">
          <div>
            <div className="flex items-center justify-between text-xs font-mono text-[#888888] mb-4">
              <span className="font-bold uppercase tracking-wider text-white">COMMUNITY</span>
              <span className="px-2 py-0.5 rounded-none border border-[#222222] bg-[#111111] text-white">Free Forever</span>
            </div>
            <div className="flex items-baseline gap-1 mb-2">
              <span className="text-4xl font-bold text-white font-mono">$0</span>
              <span className="text-xs text-[#888888] font-mono">/ month</span>
            </div>
            <p className="text-xs text-[#888888] leading-relaxed mb-6 font-sans">
              Complete native macOS runtime for individual developers demanding extreme editor performance.
            </p>

            <div className="space-y-3 text-xs text-[#888888] pt-6 border-t border-[#222222] font-mono">
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span className="text-white">Native Universal Mach-O macOS Binary</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span className="text-white">WebGPU Sub-15ms Rendering Engine</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span>1-Click Universal Migration (VS Code/Cursor)</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span>Local AI Models (DeepSeek, Llama via GGUF)</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span>Infinite Local Time-Travel Rewind</span>
              </div>
            </div>
          </div>

          <div className="pt-8">
            <button
              onClick={onOpenWaitlist}
              className="w-full py-3 rounded-none bg-[#000000] hover:bg-white text-white hover:text-black border border-[#222222] hover:border-white font-bold text-xs uppercase tracking-wider transition-none cursor-pointer"
            >
              Get Community Build
            </button>
          </div>
        </div>

        {/* Tier 2: Crux Pro (Featured) */}
        <div className="p-8 rounded-none bg-[#111111] border-2 border-white flex flex-col justify-between transition-none relative group">
          {/* Accent banner */}
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-none bg-white text-black text-[10px] font-bold uppercase tracking-wider font-mono">
            MOST POPULAR
          </div>

          <div>
            <div className="flex items-center justify-between text-xs font-mono text-white mb-4 pt-1">
              <span className="font-bold uppercase tracking-wider">CRUX PRO</span>
              <span className="px-2 py-0.5 rounded-none bg-[#000000] border border-[#222222] text-white font-bold">
                HIGH VELOCITY
              </span>
            </div>
            <div className="flex items-baseline gap-1 mb-2">
              <span className="text-4xl font-bold text-white font-mono">$20</span>
              <span className="text-xs text-[#888888] font-mono">/ seat / month</span>
            </div>
            <p className="text-xs text-[#888888] leading-relaxed mb-6 font-sans">
              For engineers and fast teams building collaboratively with decentralized AST-CRDT pipelines.
            </p>

            <div className="space-y-3 text-xs text-[#888888] pt-6 border-t border-[#222222] font-mono">
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span className="font-semibold text-white">Everything in Community, plus:</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span className="text-white">Real-time AST-CRDT Multiplayer P2P Sync</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span className="text-white">Unlimited Spatial Canvas Multiplayer Sharing</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span>Global Low-Latency WebRTC Relay Network</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span>Cloud Model Fallback (Claude 3.5 &amp; GPT-4o)</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span>Priority Issue Hotline with Founding Team</span>
              </div>
            </div>
          </div>

          <div className="pt-8">
            <button
              onClick={onOpenWaitlist}
              className="w-full py-3.5 rounded-none bg-white hover:bg-[#000000] text-black hover:text-white border border-white font-bold text-xs uppercase tracking-wider transition-none cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Join Pro Early Access</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Tier 3: Enterprise */}
        <div className="p-8 rounded-none bg-[#000000] border border-[#222222] flex flex-col justify-between hover:border-white transition-none">
          <div>
            <div className="flex items-center justify-between text-xs font-mono text-[#888888] mb-4">
              <span className="font-bold uppercase tracking-wider text-white">ENTERPRISE</span>
              <span className="px-2 py-0.5 rounded-none border border-[#222222] bg-[#111111] text-white">Dedicated</span>
            </div>
            <div className="flex items-baseline gap-1 mb-2">
              <span className="text-4xl font-bold text-white font-mono">Custom</span>
            </div>
            <p className="text-xs text-[#888888] leading-relaxed mb-6 font-sans">
              Air-gapped on-premise deployment, cryptographic workspace presence, and SOC2 compliance.
            </p>

            <div className="space-y-3 text-xs text-[#888888] pt-6 border-t border-[#222222] font-mono">
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span className="text-white">Self-Hosted AST-CRDT Relay Clusters</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span className="text-white">Strict Air-Gapped Zero-Telemetry Enforcement</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span>Custom GPU Shader &amp; LSP Extension Pipelines</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span>SSO, SAML &amp; Audit Logs (Okta, Azure AD)</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />
                <span>Dedicated Solutions Architect &amp; 99.99% SLA</span>
              </div>
            </div>
          </div>

          <div className="pt-8">
            <button
              onClick={onOpenWaitlist}
              className="w-full py-3 rounded-none bg-[#000000] hover:bg-white text-white hover:text-black border border-[#222222] hover:border-white font-bold text-xs uppercase tracking-wider transition-none cursor-pointer"
            >
              Contact Infrastructure Team
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
