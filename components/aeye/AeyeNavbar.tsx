"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ArrowRight, Play } from "lucide-react";
import CruxBrandLogo from "@/components/crux/CruxBrandLogo";

interface AeyeNavbarProps {
  onNavigate?: (sectionId: string) => void;
}

export default function AeyeNavbar({ onNavigate }: AeyeNavbarProps) {
  const [activeTab, setActiveTab] = useState("CRUX");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navLinks = [
    { label: "CRUX", href: "#hero", sectionId: "hero" },
    { label: "ARCHITECTURE", href: "#benefit", sectionId: "benefit" },
    { label: "TELEMETRY", href: "#performance", sectionId: "performance" },
    { label: "FEATURES", href: "#features", sectionId: "features" },
    { label: "WHY CRUX", href: "#why-crux", sectionId: "why-crux" },
    { label: "WAITLIST", href: "#waitlist", sectionId: "waitlist" },
    { label: "DISPATCH", href: "#dispatch", sectionId: "dispatch" },
  ];

  // ScrollSpy with IntersectionObserver
  React.useEffect(() => {
    const sectionIds = ["hero", "benefit", "performance", "features", "why-crux", "installation", "waitlist", "pricing", "dispatch"];
    const labelMap: Record<string, string> = {
      hero: "CRUX",
      benefit: "ARCHITECTURE",
      performance: "TELEMETRY",
      features: "FEATURES",
      "why-crux": "WHY CRUX",
      installation: "WHY CRUX",
      waitlist: "WAITLIST",
      pricing: "WAITLIST",
      dispatch: "DISPATCH",
    };

    const observers: IntersectionObserver[] = [];

    sectionIds.forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;

      const observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              setActiveTab(labelMap[id]);
            }
          });
        },
        { rootMargin: "-20% 0px -55% 0px" }
      );

      observer.observe(el);
      observers.push(observer);
    });

    return () => {
      observers.forEach((obs) => obs.disconnect());
    };
  }, []);

  const handleLinkClick = (link: typeof navLinks[0]) => {
    setActiveTab(link.label);
    setMobileMenuOpen(false);
    if (onNavigate) {
      onNavigate(link.href.replace("#", ""));
    }
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 pointer-events-none w-full">
      <div className="max-w-[1280px] mx-auto px-6 sm:px-12 md:px-20 lg:px-[120px] pt-5 sm:pt-6 flex items-center justify-between">
        {/* Left: Official Crux Brand Logo & Connected Nav Tabs */}
        <div className="hidden lg:flex items-center gap-6 pointer-events-auto">
          {/* Official Crux Logo */}
          <a
            href="#hero"
            onClick={(e) => {
              e.preventDefault();
              if (onNavigate) onNavigate("hero");
            }}
            className="flex items-center hover:opacity-85 transition-none no-underline"
          >
            <CruxBrandLogo size={22} />
          </a>

          {/* Desktop Segmented Control: Connected Nav Tabs */}
          <nav className="flex items-center">
            {navLinks.map((link, idx) => {
              const isActive = activeTab === link.label;
              const isFirst = idx === 0;

              return (
                <a
                  key={link.label}
                  href={link.href}
                  onClick={(e) => {
                    e.preventDefault();
                    handleLinkClick(link);
                  }}
                  className={`h-[40px] px-3.5 flex items-center gap-1.5 text-[13px] font-mono font-medium tracking-tight uppercase transition-none cursor-pointer no-underline select-none border border-[#222222] rounded-none ${
                    !isFirst ? "border-l-0" : ""
                  } ${
                    isActive
                      ? "bg-[#000000] text-[#0055FF] border-[#0055FF] font-bold"
                      : "bg-[#000000] text-[#888888] hover:text-white hover:border-[#444444]"
                  }`}
                >
                  <span>
                    {isActive ? (
                      <>
                        <span className="text-[#0055FF]">&lt;</span>
                        <span className="text-[#0055FF]">{link.label}</span>
                        <span className="text-[#0055FF]">&gt;</span>
                      </>
                    ) : (
                      link.label
                    )}
                  </span>
                </a>
              );
            })}
          </nav>
        </div>

        {/* Right Action: Launch Crux Button */}
        <div className="hidden lg:flex items-center pointer-events-auto">
          <a
            href="/?app=true"
            className="h-[40px] px-4 bg-[#0055FF] hover:bg-[#0044CC] border border-[#0055FF] text-white transition-none flex items-center gap-2 text-[13px] font-mono font-bold tracking-tight uppercase no-underline cursor-pointer rounded-none group"
          >
            <Play className="w-3 h-3 fill-current" />
            <span>LAUNCH CRUX</span>
          </a>
        </div>

        {/* Mobile View: Official Logo + Hamburger Button */}
        <div className="lg:hidden flex items-center justify-between w-full pointer-events-auto">
          <a
            href="#hero"
            onClick={(e) => {
              e.preventDefault();
              if (onNavigate) onNavigate("hero");
            }}
            className="flex items-center no-underline"
          >
            <CruxBrandLogo size={20} />
          </a>

          <motion.button
            whileTap={{ scale: 0.94 }}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="h-[36px] px-3 bg-[#111111] border border-[#222222] text-white text-xs font-mono flex items-center gap-2 cursor-pointer rounded-none"
            aria-label="Toggle Navigation"
          >
            <span className="w-3 h-0.5 bg-white block" />
            <span>MENU</span>
          </motion.button>
        </div>
      </div>

      {/* Mobile Drawer Menu */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.15 }}
            className="lg:hidden mx-6 mt-2 bg-[#000000] border border-[#222222] p-3 flex flex-col gap-1 pointer-events-auto rounded-none"
          >
            {navLinks.map((link) => {
              const isActive = activeTab === link.label;
              return (
                <a
                  key={link.label}
                  href={link.href}
                  onClick={(e) => {
                    e.preventDefault();
                    handleLinkClick(link);
                  }}
                  className={`py-2 px-3 text-xs font-mono flex items-center justify-between no-underline border-b border-[#222222] rounded-none ${
                    isActive ? "bg-[#111111] text-[#0055FF] border-[#0055FF] font-bold" : "text-[#888888] hover:text-white"
                  }`}
                >
                  <span>{isActive ? `<${link.label}>` : link.label}</span>
                </a>
              );
            })}
            <a
              href="/?app=true"
              onClick={() => setMobileMenuOpen(false)}
              className="mt-2 py-2.5 px-3 bg-[#0055FF] text-white font-bold text-xs font-mono text-center uppercase flex items-center justify-center gap-1.5 no-underline rounded-none hover:bg-[#0044CC]"
            >
              <span>Launch Crux</span>
              <ArrowRight className="w-3.5 h-3.5 inline" />
            </a>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
