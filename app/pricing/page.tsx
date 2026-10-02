import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

export const metadata: Metadata = {
  robots: { index: false, follow: true },
  title: "Code Crux Pricing — Transparent Per-Seat & Self-Hosted Air-Gapped Tiers",
  description:
    "Crux pricing: Community Edition is $0 forever. Team Alpha is $20/seat/month ($200/mo for a 10-person team). Enterprise Air-Gapped is $45/seat/month with 100% on-premise self-hosted relay and zero cloud telemetry.",
  alternates: {
    canonical: "https://codecrux.us/pricing",
  },
};

export default function PricingPage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "Crux IDE",
    "description": "Ultra-performance native collaborative IDE built with Rust and WebGPU.",
    "brand": {
      "@type": "Brand",
      "name": "Crux",
    },
    "offers": [
      {
        "@type": "Offer",
        "name": "Community Bare-Metal",
        "price": "0",
        "priceCurrency": "USD",
        "description": "Free forever for individuals and open-source developers.",
      },
      {
        "@type": "Offer",
        "name": "Team Alpha",
        "price": "20.00",
        "priceCurrency": "USD",
        "description": "Per seat per month. Includes managed WebRTC signaling relays and spatial presence.",
      },
      {
        "@type": "Offer",
        "name": "Enterprise Air-Gapped",
        "price": "45.00",
        "priceCurrency": "USD",
        "description": "Per seat per month. 100% self-hosted, air-gapped zero cloud telemetry.",
      },
    ],
  };

  return (
    <div className="min-h-screen bg-[#000000] text-white font-sans antialiased selection:bg-[#0055FF]/30 selection:text-white">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />

      {/* Header */}
      <header className="border-b border-[#222222] bg-[#000000] sticky top-0 z-50">
        <div className="max-w-[1280px] mx-auto px-6 h-14 flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 no-underline">
              <CruxBrandLogo size={20} />
            </Link>
            <span className="text-[#444444]">/</span>
            <span className="text-[#0055FF] font-bold">COMMERCIAL // SEAT PRICING</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/benchmarks" className="text-[#888888] hover:text-white no-underline uppercase">
              Benchmarks
            </Link>
            <Link href="/ast-crdt" className="text-[#888888] hover:text-white no-underline uppercase">
              AST-CRDT
            </Link>
            <Link href="/vs-zed" className="text-[#888888] hover:text-white no-underline uppercase">
              vs Zed
            </Link>
            <Link
              href="/ide"
              className="px-3 py-1.5 bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono font-bold uppercase no-underline rounded-none"
            >
              LAUNCH IDE ↵
            </Link>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="border-b border-[#222222] pb-10">
          <div className="text-xs font-mono text-[#0055FF] uppercase tracking-wider mb-2 font-bold">
            [TRANSPARENT LICENSING // NO HIDDEN CLOUD LOCK-IN]
          </div>
          <h1 className="text-4xl sm:text-6xl font-normal font-sans tracking-tight text-white leading-tight">
            Predictable Developer Pricing.
          </h1>
          <p className="mt-4 text-base text-[#888888] max-w-3xl leading-relaxed">
            Direct pricing tailored for high-velocity teams. Whether you are an individual systems hacker, a fast-shipping startup, or an enterprise requiring 100% on-prem air-gapped security.
          </p>
        </div>

        {/* 3 Pricing Cards */}
        <section className="my-14 grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Tier 1: Community */}
          <div className="p-8 border border-[#222222] bg-[#050507] flex flex-col justify-between">
            <div>
              <div className="text-xs font-mono text-[#888888] uppercase mb-1">INDIVIDUALS &amp; OSS</div>
              <h3 className="text-2xl font-normal text-white mb-2">Community Bare-Metal</h3>
              <div className="my-6">
                <span className="text-5xl font-mono font-bold text-white">$0</span>
                <span className="text-xs font-mono text-[#71717a] ml-2">/ FOREVER</span>
              </div>
              <p className="text-xs text-[#888888] font-sans leading-relaxed mb-6">
                Full standalone developer workstation with direct Metal/WebGPU acceleration and local terminal PTY.
              </p>
              <ul className="space-y-3 font-mono text-xs text-[#cccccc] border-t border-[#222222] pt-6">
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> Direct WebGPU/Metal compute engine
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> 4.2ms input-to-photon latency
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> Local PTY terminal with host CLI auto-discovery
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> Local-first filesystem residency
                </li>
              </ul>
            </div>
            <div className="mt-8 pt-6 border-t border-[#222222]">
              <Link
                href="/ide"
                className="w-full block py-3 text-center bg-[#111114] hover:bg-[#1a1a24] border border-[#333333] hover:border-white text-white font-mono text-xs uppercase tracking-wider no-underline"
              >
                LAUNCH FREE WORKSTATION ↵
              </Link>
            </div>
          </div>

          {/* Tier 2: Team Alpha */}
          <div className="p-8 border-2 border-[#0055FF] bg-[#001133]/20 flex flex-col justify-between relative">
            <div className="absolute top-0 right-0 bg-[#0055FF] text-white text-[10px] font-mono font-bold px-2 py-0.5 uppercase tracking-wider">
              POPULAR // ACTIVE ALPHA
            </div>
            <div>
              <div className="text-xs font-mono text-[#0055FF] uppercase font-bold mb-1">ENGINEERING TEAMS</div>
              <h3 className="text-2xl font-normal text-white mb-2">Team Alpha</h3>
              <div className="my-6">
                <span className="text-5xl font-mono font-bold text-white">$20</span>
                <span className="text-xs font-mono text-[#71717a] ml-2">/ SEAT / MONTH</span>
              </div>
              <p className="text-xs text-[#888888] font-sans leading-relaxed mb-6">
                Real-time peer-to-peer collaborative mesh with managed WebRTC signaling relays. A 10-person team is exactly $200/month.
              </p>
              <ul className="space-y-3 font-mono text-xs text-[#cccccc] border-t border-[#222222] pt-6">
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> Everything in Community
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> Managed low-latency WebRTC signaling relays
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> Real-time spatial cursor vectors &amp; live presence
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> Lock-free AST-CRDT peer mesh synchronization
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> Shared workspace state &amp; multi-agent execution
                </li>
              </ul>
            </div>
            <div className="mt-8 pt-6 border-t border-[#222222]">
              <a
                href="/#waitlist"
                className="w-full block py-3 text-center bg-[#0055FF] hover:bg-[#0044CC] text-white font-mono text-xs uppercase font-bold tracking-wider no-underline"
              >
                REQUEST TEAM ACCESS ↵
              </a>
            </div>
          </div>

          {/* Tier 3: Enterprise Air-Gapped */}
          <div className="p-8 border border-[#222222] bg-[#050507] flex flex-col justify-between">
            <div>
              <div className="text-xs font-mono text-[#888888] uppercase mb-1">REGULATED &amp; SECURITY-CRITICAL</div>
              <h3 className="text-2xl font-normal text-white mb-2">Enterprise Air-Gapped</h3>
              <div className="my-6">
                <span className="text-5xl font-mono font-bold text-white">$45</span>
                <span className="text-xs font-mono text-[#71717a] ml-2">/ SEAT / MONTH</span>
              </div>
              <p className="text-xs text-[#888888] font-sans leading-relaxed mb-6">
                100% on-premise, self-hostable with zero cloud telemetry. Deployable in air-gapped environments with custom local LLM endpoints.
              </p>
              <ul className="space-y-3 font-mono text-xs text-[#cccccc] border-t border-[#222222] pt-6">
                <li className="flex items-center gap-2">
                  <span className="text-[#0055FF]">✓</span> Everything in Team Alpha
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#22c55e]">✓</span> 100% Self-Hosted WebRTC signaling relay binary
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#22c55e]">✓</span> Zero cloud telemetry guarantee (Air-gapped verified)
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#22c55e]">✓</span> SSO / SAML / Okta &amp; Active Directory integration
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-[#22c55e]">✓</span> Custom local LLM daemon endpoints (Ollama, vLLM, custom IPC)
                </li>
              </ul>
            </div>
            <div className="mt-8 pt-6 border-t border-[#222222]">
              <a
                href="/#waitlist"
                className="w-full block py-3 text-center bg-[#111114] hover:bg-[#1a1a24] border border-[#333333] hover:border-white text-white font-mono text-xs uppercase tracking-wider no-underline"
              >
                CONTACT ENTERPRISE SALES ↵
              </a>
            </div>
          </div>
        </section>

        {/* Pricing FAQ Section */}
        <section className="my-14 border-t border-[#222222] pt-10">
          <h2 className="text-2xl font-normal font-sans text-white mb-6">
            Pricing Frequently Asked Questions
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 font-sans text-xs">
            <div className="p-5 border border-[#222222] bg-[#0c0c10]">
              <h4 className="text-white font-semibold text-sm mb-2">How much does Crux cost for a 10-person engineering team?</h4>
              <p className="text-[#888888] leading-relaxed">
                For a 10-person team on the Team Alpha plan, Crux costs exactly $200 per month ($20/seat/month). This includes unlimited collaboration hours, managed signaling relays, and real-time spatial presence vectors.
              </p>
            </div>
            <div className="p-5 border border-[#222222] bg-[#0c0c10]">
              <h4 className="text-white font-semibold text-sm mb-2">Can we run Crux completely air-gapped without internet access?</h4>
              <p className="text-[#888888] leading-relaxed">
                Yes. With the Enterprise Air-Gapped plan, we provide a standalone compiled signaling relay binary that runs entirely inside your internal VPC or physical network. Crux transmits 0 bytes of telemetry to any external servers.
              </p>
            </div>
            <div className="p-5 border border-[#222222] bg-[#0c0c10]">
              <h4 className="text-white font-semibold text-sm mb-2">Is the individual Community Edition genuinely free?</h4>
              <p className="text-[#888888] leading-relaxed">
                Yes, $0 forever. It includes the complete bare-metal Metal/WebGPU rasterization engine, the full terminal PTY, local CRDT buffers, and CLI tool auto-discovery.
              </p>
            </div>
            <div className="p-5 border border-[#222222] bg-[#0c0c10]">
              <h4 className="text-white font-semibold text-sm mb-2">How are billing and license keys handled?</h4>
              <p className="text-[#888888] leading-relaxed">
                Billing is handled through Stripe per active seat. License keys are cryptographically signed via Ed25519 and verified offline on host silicon without requiring phone-home telemetry.
              </p>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-[#222222] bg-[#000000] py-8 text-center font-mono text-xs text-[#555555]">
        <div>Crux IDE · Engineered for High-Velocity Engineering · <Link href="/" className="text-[#0055FF] no-underline">Return to Overview</Link></div>
      </footer>
    </div>
  );
}
