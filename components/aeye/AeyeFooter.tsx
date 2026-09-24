"use client";

import React from "react";
import CruxBrandLogo from "../crux/CruxBrandLogo";
import { ArrowUpRight } from "lucide-react";

export default function AeyeFooter() {
  const pages = [
    { label: "Home", href: "#hero" },
    { label: "About", href: "#benefit" },
    { label: "Docs", href: "#document" },
    { label: "Pricing", href: "#pricing" },
    { label: "Blog", href: "#blog" },
    { label: "Careers (4)", href: "#careers" },
    { label: "Waitlist", href: "#pricing" },
    { label: "Contact", href: "#contact" },
    { label: "Changelog", href: "#changelog" },
    { label: "Terms", href: "#terms" },
    { label: "Privacy", href: "#privacy" },
  ];

  const social = [
    { label: "X Twitter", href: "https://twitter.com" },
    { label: "GitHub", href: "https://github.com" },
    { label: "Discord", href: "https://discord.com" },
    { label: "Facebook", href: "https://facebook.com" },
    { label: "LinkedIn", href: "https://linkedin.com" },
  ];

  return (
    <footer id="contact" className="w-full bg-[#000000] border-t border-[#222222] font-sans">
      <div className="max-w-[1280px] mx-auto px-6 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-10 pb-16 border-b border-[#222222]">
          {/* Column 1: Brand & Contact Info */}
          <div className="lg:col-span-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-3">
                <CruxBrandLogo size={20} withText={true} />
                <div className="px-2 py-0.5 bg-[#111111] border border-[#222222] rounded-none">
                  <span className="font-mono text-[10px] text-[#888888]">
                    v0.1.0 // RUST + WEBGPU
                  </span>
                </div>
              </div>

              <p className="mt-4 text-xs text-[#888888] font-sans max-w-sm leading-relaxed">
                Crux is the native collaborative IDE engineered for high-velocity engineering. Sub-15ms rendering latency, decentralized AST-CRDT real-time sync, and zero Chromium overhead.
              </p>
            </div>

            <div className="mt-8 space-y-1.5 text-xs font-mono text-[#888888]">
              <div>
                <span className="text-[#444444]">LOC // </span>
                <span>San Francisco, CA &amp; Distributed Global Mesh</span>
              </div>
              <div>
                <span className="text-[#444444]">MAIL // </span>
                <a href="mailto:core@codecrux.us" className="hover:text-[#0055FF] transition-none text-[#888888]">
                  core@codecrux.us
                </a>
              </div>
              <div>
                <span className="text-[#444444]">STATUS // </span>
                <span className="text-[#0055FF] font-semibold">● KERNEL RUNTIME ONLINE</span>
              </div>
            </div>
          </div>

          {/* Column 2: Pages Navigation */}
          <div className="lg:col-span-4">
            <div className="text-xs font-mono uppercase tracking-wider text-white font-bold mb-4">
              PAGES
            </div>
            <div className="grid grid-cols-2 gap-y-2 gap-x-4">
              {pages.map((p, idx) => (
                <a
                  key={idx}
                  href={p.href}
                  className="text-xs font-sans text-[#888888] hover:text-[#0055FF] transition-none no-underline"
                >
                  {p.label}
                </a>
              ))}
            </div>
          </div>

          {/* Column 3: Social & Community */}
          <div className="lg:col-span-3">
            <div className="text-xs font-mono uppercase tracking-wider text-white font-bold mb-4">
              FOLLOW US
            </div>
            <div className="flex flex-col gap-2">
              {social.map((s, idx) => (
                <a
                  key={idx}
                  href={s.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs font-mono text-[#888888] hover:text-[#0055FF] transition-none flex items-center justify-between no-underline group"
                >
                  <span className="group-hover:text-[#0055FF] transition-none">{s.label}</span>
                  <ArrowUpRight className="w-3.5 h-3.5 text-[#444444] group-hover:text-[#0055FF] transition-none" />
                </a>
              ))}
            </div>
          </div>
        </div>

        {/* Bottom Bar: Copyright & Attribution */}
        <div className="pt-8 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-[11px] font-mono text-[#444444]">
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
