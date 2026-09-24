"use client";

import React, { useState, useRef } from "react";
import { motion, AnimatePresence, useScroll, useSpring, useTransform, useMotionValueEvent } from "framer-motion";
import { Copy, Check, Terminal } from "lucide-react";
import Link from "next/link";

export default function AeyeInstallationSection() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState<"js" | "cli" | "python">("js");
  const [copied, setCopied] = useState(false);
  const isManualClickRef = useRef(false);
  const manualTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Smooth scroll interpolation using spring physics for butter-smooth response
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end end"],
  });

  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 140,
    damping: 26,
    mass: 0.2,
  });

  // Vertical timeline rail fill height (from 0% to 100%)
  const verticalRailHeight = useTransform(smoothProgress, [0.08, 0.92], ["0%", "100%"]);

  // Individual progress fills for header indicator pills
  const p0 = useTransform(smoothProgress, [0.02, 0.33], ["0%", "100%"]);
  const p1 = useTransform(smoothProgress, [0.33, 0.66], ["0%", "100%"]);
  const p2 = useTransform(smoothProgress, [0.66, 0.98], ["0%", "100%"]);
  const headerFills = [p0, p1, p2];

  // Update activeTab ONLY when thresholding across sections (prevents re-render lag)
  useMotionValueEvent(smoothProgress, "change", (latest) => {
    if (isManualClickRef.current) return;
    if (latest < 0.35) {
      setActiveTab((prev) => (prev !== "js" ? "js" : prev));
    } else if (latest < 0.70) {
      setActiveTab((prev) => (prev !== "cli" ? "cli" : prev));
    } else {
      setActiveTab((prev) => (prev !== "python" ? "python" : prev));
    }
  });

  const tabs = [
    {
      id: "js" as const,
      serial: "// 001",
      label: "JavaScript",
      desc: "Lightweight TypeScript/Node client for direct programmatic integration into application runtimes.",
      lang: "typescript",
      code: `import { CruxClient } from "@crux/product";

const client = new CruxClient({
  apiKey: process.env.CRUX_API_KEY,
});

// Initialize AST pipeline
const pipeline = await client.pipeline.create({
  model: "crux-agent-v1",
  strategy: "ast-crdt",
});

// Stream workspace intelligence
const result = await pipeline.execute({
  workspacePath: "./src",
});
console.log(result.telemetry);`,
    },
    {
      id: "cli" as const,
      serial: "// 002",
      label: "CLI",
      desc: "Execute commands directly from your local terminal with instant hardware execution.",
      lang: "bash",
      code: `# 1. Install Crux native developer toolchain
curl -fsSL https://codecrux.us/install.sh | bash

# 2. Initialize AST pipeline in repository
crux init --model="crux-agent-v1" --strategy="ast-crdt"

# 3. Stream workspace intelligence
crux pipeline execute --path="./src" --telemetry=live`,
    },
    {
      id: "python" as const,
      serial: "// 003",
      label: "Python",
      desc: "Native SDK for high-performance data processing pipelines and agent execution.",
      lang: "python",
      code: `import crux

client = crux.Client(api_key=os.environ["CRUX_API_KEY"])

# Initialize AST pipeline
pipeline = client.pipeline.create(
    model="crux-agent-v1",
    strategy="ast-crdt"
)

# Stream workspace intelligence
result = pipeline.execute(workspace_path="./src")
print(result.telemetry)`,
    },
  ];

  const activeIndex = tabs.findIndex((t) => t.id === activeTab);
  const currentTab = tabs[activeIndex] || tabs[0];

  const handleStepClick = (idx: number) => {
    const selected = tabs[idx];
    if (!selected) return;
    setActiveTab(selected.id);

    if (containerRef.current && typeof window !== "undefined") {
      if (window.innerWidth >= 1024) {
        isManualClickRef.current = true;
        if (manualTimeoutRef.current) clearTimeout(manualTimeoutRef.current);
        manualTimeoutRef.current = setTimeout(() => {
          isManualClickRef.current = false;
        }, 750);

        const rect = containerRef.current.getBoundingClientRect();
        const scrollTop = window.scrollY || document.documentElement.scrollTop;
        const containerTop = rect.top + scrollTop;
        const scrollableDistance = containerRef.current.offsetHeight - window.innerHeight;

        if (scrollableDistance > 0) {
          const targets = [0.08, 0.50, 0.92];
          window.scrollTo({
            top: containerTop + targets[idx] * scrollableDistance,
            behavior: "smooth",
          });
        }
      }
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(currentTab.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="installation" className="relative w-full border-b border-[#222222] bg-[#000000]">
      {/* Scroll-driven Sticky Container matching Feature & How-It-Works sections */}
      <div ref={containerRef} className="relative lg:h-[220vh]">
        <div className="relative lg:sticky lg:top-0 lg:h-screen lg:flex lg:flex-col lg:justify-center overflow-visible lg:overflow-hidden py-12 lg:py-0">
          <div className="max-w-[1280px] w-full mx-auto px-6">
            {/* Section Header Meta with Live Step Tracking */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#222222] text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="text-[#0055FF] font-bold">[N.05/11]</span>
                <span className="text-[#888888]">— &gt;</span>
                <span className="text-[#888888] uppercase">INSTALLATION</span>
              </div>
              <div className="flex items-center gap-3 pt-2 sm:pt-0">
                <span className="text-[10px] text-[#71717a] uppercase tracking-wider hidden sm:inline font-mono">
                  SDK &amp; DEVELOPER TOOLCHAIN
                </span>
                <div className="flex items-center gap-1.5">
                  {tabs.map((tab, idx) => (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => handleStepClick(idx)}
                      className={`h-1.5 transition-none rounded-none ${
                        activeTab === tab.id ? "w-7 bg-[#0055FF]" : "w-2.5 bg-[#222222] hover:bg-[#444444]"
                      }`}
                      aria-label={`Jump to ${tab.label}`}
                    />
                  ))}
                </div>
                <span className="text-xs font-mono text-[#0055FF] font-bold">
                  [ 0{activeIndex + 1} / 03 ]
                </span>
              </div>
            </div>

            {/* 2-Column Section Layout */}
            <div className="pt-8 grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
              {/* Left Column: Code Window in Dotted Bracket Frame */}
              <div className="lg:col-span-7">
                <div className="relative p-5 sm:p-7 border border-[#222222] bg-[#050507]">
                  {/* Corner Double-Dot Accents */}
                  <div className="absolute top-2 left-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>
                  <div className="absolute top-2 right-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>
                  <div className="absolute bottom-2 left-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>
                  <div className="absolute bottom-2 right-2 flex gap-1 font-mono text-[9px] text-[#444444] select-none">
                    ■ ■
                  </div>

                  {/* Code Box */}
                  <div className="border border-[#222222] bg-[#0a0a0c] rounded-none overflow-hidden">
                    {/* Header bar with Crux brand and Copy button */}
                    <div className="h-10 px-4 bg-[#111114] border-b border-[#222222] flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <span className="w-2 h-2 bg-[#0055FF] inline-block" />
                        <span className="font-mono text-xs font-semibold text-white uppercase tracking-wider">
                          CRUX // {currentTab.label.toUpperCase()}
                        </span>
                      </div>
                      <button
                        onClick={handleCopy}
                        className="flex items-center gap-1.5 font-mono text-xs text-[#888888] hover:text-white transition-none px-2 py-1 border border-transparent hover:border-[#333333]"
                        aria-label="Copy code"
                      >
                        <span>{copied ? "Copied" : "Copy"}</span>
                        {copied ? (
                          <Check className="w-3.5 h-3.5 text-[#0055FF]" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>

                    {/* Syntax-highlighted code viewport with smooth crossfade */}
                    <div className="p-5 font-mono text-xs sm:text-[13px] leading-relaxed overflow-x-auto min-h-[300px] text-[#d4d4d8]">
                      <AnimatePresence mode="wait">
                        <motion.div
                          key={currentTab.id}
                          initial={{ opacity: 0, y: 4 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -4 }}
                          transition={{ duration: 0.15 }}
                        >
                          <pre className="text-left font-mono">
                            <code>
                              {currentTab.code.split("\n").map((line, i) => {
                                let styledLine = <span className="text-[#a1a1aa]">{line}</span>;

                                if (line.startsWith("//") || line.startsWith("#")) {
                                  styledLine = <span className="text-[#555555]">{line}</span>;
                                } else if (
                                  line.includes("import ") ||
                                  line.includes("from ") ||
                                  line.includes("const ") ||
                                  line.includes("await ") ||
                                  line.includes("print") ||
                                  line.includes("client =") ||
                                  line.includes("pipeline =") ||
                                  line.includes("curl ") ||
                                  line.includes("crux ")
                                ) {
                                  styledLine = (
                                    <span>
                                      {line.split(" ").map((word, wIdx) => {
                                        if (
                                          [
                                            "import",
                                            "from",
                                            "const",
                                            "await",
                                            "new",
                                            "def",
                                            "print",
                                            "curl",
                                            "crux",
                                          ].includes(word)
                                        ) {
                                          return (
                                            <span key={wIdx} className="text-[#0055FF] font-medium">
                                              {word}{" "}
                                            </span>
                                          );
                                        }
                                        if (word.startsWith('"') || word.endsWith('"')) {
                                          return (
                                            <span key={wIdx} className="text-white font-medium">
                                              {word}{" "}
                                            </span>
                                          );
                                        }
                                        return <span key={wIdx} className="text-[#a1a1aa]">{word} </span>;
                                      })}
                                    </span>
                                  );
                                }

                                return (
                                  <div key={i} className="table-row">
                                    <span className="table-cell select-none pr-4 text-[#444444] text-right font-mono text-[11px] w-6">
                                      {i + 1}
                                    </span>
                                    <span className="table-cell">{styledLine}</span>
                                  </div>
                                );
                              })}
                            </code>
                          </pre>
                        </motion.div>
                      </AnimatePresence>
                    </div>

                    {/* Bottom Console Footer */}
                    <div className="px-4 py-2 border-t border-[#222222] bg-[#0e0e12] flex items-center justify-between text-[11px] font-mono">
                      <div className="flex items-center gap-2 text-[#71717a]">
                        <Terminal className="w-3 h-3 text-[#0055FF]" />
                        <span>RUNTIME: BARE-METAL POSIX</span>
                      </div>
                      <span className="text-[#0055FF] font-bold">
                        LATENCY: &lt; 0.2ms
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Right Column: Title, Action Button, and Butter-Smooth Vertical Timeline Selector */}
              <div className="lg:col-span-5 flex flex-col justify-between h-full pt-2">
                <div>
                  <h2 className="text-2xl sm:text-4xl lg:text-[42px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
                    Simple to integrate.
                    <span className="block text-[#888888]">Unlock new workflow.</span>
                  </h2>

                  <div className="mt-5 flex items-center gap-4">
                    <Link
                      href="#pricing"
                      className="inline-flex items-center gap-2.5 px-4 py-2.5 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none"
                    >
                      <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                      GET STARTED
                    </Link>
                    <div className="text-[11px] font-mono text-[#71717a] hidden sm:flex items-center gap-2">
                      <span className="w-1.5 h-1.5 bg-[#0055FF] animate-pulse" />
                      <span>SCROLL TO ADVANCE // 0{activeIndex + 1} OF 03</span>
                    </div>
                  </div>
                </div>

                {/* Vertical Progress Rail with Dynamic Butter-Smooth Fill */}
                <div className="mt-10 sm:mt-12 relative pl-8 select-none">
                  {/* Background Track Rail */}
                  <div className="absolute left-[9px] top-3 bottom-6 w-[2px] bg-[#1a1a1e]" />

                  {/* GPU-composited Smooth Electric Blue Fill */}
                  <div className="absolute left-[9px] top-3 bottom-6 w-[2px] overflow-hidden">
                    <motion.div
                      className="w-full bg-[#0055FF]"
                      style={{ height: verticalRailHeight }}
                    />
                  </div>

                  <div className="space-y-6 sm:space-y-7">
                    {tabs.map((tab, idx) => {
                      const isActive = activeTab === tab.id;

                      return (
                        <div
                          key={tab.id}
                          onClick={() => handleStepClick(idx)}
                          className="relative cursor-pointer group transition-none"
                        >
                          {/* Active Indicator Square Node on Rail */}
                          <div
                            className={`absolute -left-[27px] top-1.5 w-2 h-2 transition-none ${
                              isActive
                                ? "bg-[#0055FF] border border-white"
                                : "bg-[#222222] border border-[#333333] group-hover:bg-[#444444]"
                            }`}
                          />

                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] font-mono font-semibold transition-none ${
                                isActive ? "text-[#0055FF]" : "text-[#555555]"
                              }`}
                            >
                              {tab.serial}
                            </span>
                            <h3
                              className={`text-xl font-medium font-sans transition-none ${
                                isActive ? "text-[#0055FF] font-semibold" : "text-[#71717a] group-hover:text-white"
                              }`}
                            >
                              {tab.label}
                            </h3>
                          </div>

                          {/* Dynamic Description & Badge */}
                          {isActive && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.2 }}
                              className="overflow-hidden"
                            >
                              <p className="mt-2 text-xs sm:text-sm text-white font-sans leading-relaxed pl-3 border-l border-[#0055FF]">
                                {tab.desc}
                              </p>
                              <div className="mt-2 text-[10px] font-mono text-[#0055FF] pl-3 uppercase">
                                // STATUS: READY FOR ZERO-OVERHEAD COMPILATION
                              </div>
                            </motion.div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
