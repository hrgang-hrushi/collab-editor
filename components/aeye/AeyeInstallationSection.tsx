"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Play, RotateCcw, Check, Copy, ArrowRight } from "lucide-react";

export default function AeyeInstallationSection() {
  const [activeTab, setActiveTab] = useState<"curl" | "cargo" | "brew">("curl");
  const [copied, setCopied] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simStep, setSimStep] = useState(0);

  const codeSnippets = {
    curl: `# 1. Install Crux native binary for macOS / Linux
curl -fsSL https://codecrux.us/install.sh | bash

# 2. Launch Crux in your workspace
crux .

# 3. Connect to live collaborative team session
crux --join="session://team-alpha-09"`,
    cargo: `# 1. Compile from source with WebGPU acceleration
cargo install crux-ide --features="webgpu,metal"

# 2. Verify hardware brutalist kernel & GPU drivers
crux doctor

# 3. Launch with local workspace
crux . --telemetry=stdout`,
    brew: `# 1. Install native macOS binary (Apple Silicon / Intel)
brew tap crux-ide/tap
brew install --cask crux

# 2. One-click migrate settings from VS Code / Cursor
crux migrate --from="vscode"

# 3. Launch Crux IDE
crux .`,
  };

  const simLines = [
    "$ crux install --channel=stable --target=native",
    "  [1/4] Probing host CPU architecture... Apple M4 Pro (arm64-apple-darwin)",
    "  [2/4] Downloading crux-v0.1.0-darwin-arm64.tar.gz [18.4 MB / 18.4 MB] 100%",
    "  [3/4] Verifying SHA-256 cryptographic checksum signature... OK",
    "  [4/4] Linking binary /usr/local/bin/crux -> /opt/crux/bin/crux",
    "[SUCCESS] Crux Kernel v0.1.0 installed successfully in 1.28s.",
    "Ready to launch. Run `crux .` in any repository to begin.",
  ];

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isSimulating && simStep < simLines.length) {
      timer = setTimeout(() => {
        setSimStep((prev) => prev + 1);
      }, 400);
    }
    return () => clearTimeout(timer);
  }, [isSimulating, simStep]);

  const handleStartSim = () => {
    setIsSimulating(true);
    setSimStep(1);
  };

  const handleResetSim = () => {
    setIsSimulating(false);
    setSimStep(0);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(codeSnippets[activeTab]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="installation" className="relative w-full border-b border-[#222222] bg-[#000000] overflow-hidden">
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
            <span className="text-[#0055FF] font-bold">[n. 05 / 11 ]</span>
            <span className="text-[#0055FF] font-bold">&gt;</span>
            <span className="text-[#888888]">Installation</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0">
            NATIVE SDK &amp; CLI INTEGRATIONS
          </div>
        </motion.div>

        {/* Section Title & Subtitle */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
          className="pt-8 pb-14"
        >
          <h2 className="text-3xl sm:text-5xl lg:text-[54px] font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
            Simple to integrate.{" "}
            <span className="text-[#71717a] block sm:inline">
              Unlock new workflow.
            </span>
          </h2>
        </motion.div>

        {/* Installation Main Layout: Terminal Card + Tabs */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Left: Terminal Console */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-30px" }}
            transition={{ duration: 0.6 }}
            className="lg:col-span-8 border border-[#222222] bg-[#000000] text-white rounded-none overflow-hidden"
          >
            {/* Terminal Header */}
            <div className="px-5 py-3.5 bg-[#111111] border-b border-[#222222] flex items-center justify-between">
              {/* Brutalist Square LEDs */}
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 bg-[#333333]" />
                <span className="w-2.5 h-2.5 bg-[#0055FF]" />
                <span className="w-2.5 h-2.5 bg-white" />
                <span className="ml-3 font-mono text-[11px] text-[#888888]">
                  terminal // crux-{isSimulating ? "simulated-exec" : activeTab}
                </span>
              </div>

              {/* Terminal Actions */}
              <div className="flex items-center gap-2">
                {!isSimulating ? (
                  <button
                    onClick={handleStartSim}
                    className="px-2.5 py-1 bg-[#0055FF] hover:bg-[#0044CC] text-white border border-[#0055FF] text-[10px] font-mono uppercase tracking-wider flex items-center gap-1.5 transition-none cursor-pointer rounded-none font-bold"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>RUN SIMULATION</span>
                  </button>
                ) : (
                  <button
                    onClick={handleResetSim}
                    className="px-2.5 py-1 bg-[#111111] hover:bg-white hover:text-black text-white border border-[#222222] text-[10px] font-mono uppercase tracking-wider flex items-center gap-1.5 transition-none cursor-pointer rounded-none"
                  >
                    <RotateCcw className="w-3 h-3" />
                    <span>RESET</span>
                  </button>
                )}

                <button
                  onClick={handleCopy}
                  className="px-3 py-1 bg-[#111111] hover:bg-white hover:text-black text-white border border-[#222222] text-[10px] font-mono uppercase tracking-wider flex items-center gap-1.5 transition-none cursor-pointer rounded-none"
                >
                  {copied ? (
                    <>
                      <Check className="w-3 h-3 text-[#0055FF]" />
                      <span className="text-[#0055FF] font-bold">COPIED</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3 text-[#888888]" />
                      <span>COPY</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Code / Simulation Body */}
            <div className="p-6 sm:p-8 font-mono text-xs sm:text-[13px] leading-relaxed overflow-x-auto min-h-[300px] selection:bg-white selection:text-black bg-[#000000]">
              {!isSimulating ? (
                <AnimatePresence mode="wait">
                  <motion.pre
                    key={activeTab}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    transition={{ duration: 0.15 }}
                    className="text-[#f4f4f5] whitespace-pre"
                  >
                    {codeSnippets[activeTab]}
                  </motion.pre>
                </AnimatePresence>
              ) : (
                <div className="space-y-2">
                  {simLines.slice(0, simStep).map((line, idx) => {
                    const isSuccess = line.includes("[SUCCESS]");
                    const textWithoutEmoji = isSuccess ? line.replace("[SUCCESS]", "").trim() : line;

                    return (
                      <div
                        key={idx}
                        className={
                          isSuccess
                            ? "text-white font-bold flex items-center gap-2"
                            : line.startsWith("$")
                            ? "text-white font-semibold"
                            : "text-[#d4d4d8]"
                        }
                      >
                        {isSuccess && <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[3]" />}
                        <span>{textWithoutEmoji}</span>
                      </div>
                    );
                  })}
                  {simStep < simLines.length && (
                    <div className="flex items-center gap-2 text-[#71717a] animate-pulse">
                      <span className="w-1.5 h-3 bg-white inline-block" />
                      <span>executing pipeline...</span>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Bottom Terminal Banner */}
            <div className="px-5 py-3 bg-[#111111] border-t border-[#222222] flex items-center justify-between text-[10px] font-mono text-[#71717a]">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-white" />
                <span>RUST KERNEL · WEBGPU DISPATCH · POSIX / WIN32</span>
              </div>
              <span className="text-[#71717a]">UTF-8 · READY</span>
            </div>
          </motion.div>

          {/* Right: Interactive Package Manager Selector Cards */}
          <div className="lg:col-span-4 flex flex-col gap-4">
            {[
              {
                id: "curl",
                title: "One-Line Shell Script",
                desc: "Instant single-line install script for Apple Silicon, Intel macOS, and Linux x86_64.",
                tag: "curl -fsSL codecrux.us",
              },
              {
                id: "cargo",
                title: "Rust Cargo Crates",
                desc: "Compile directly from source code with bare-metal hardware acceleration flags.",
                tag: "cargo install crux-ide",
              },
              {
                id: "brew",
                title: "Homebrew Cask",
                desc: "Standard native macOS installation with automated binary update checks.",
                tag: "brew install --cask crux",
              },
            ].map((item) => {
              const isSelected = activeTab === item.id;
              return (
                <div
                  key={item.id}
                  onClick={() => {
                    setActiveTab(item.id as any);
                    setIsSimulating(false);
                  }}
                  className={`p-6 border transition-none cursor-pointer relative rounded-none ${
                    isSelected
                      ? "border-[#0055FF] bg-[#0055FF]/5"
                      : "border-[#222222] bg-[#000000] hover:bg-[#111111]"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <h3 className="text-base font-semibold text-white font-sans">
                      {item.title}
                    </h3>
                    <span
                      className={`text-xs font-mono ${
                        isSelected ? "text-[#0055FF] font-bold" : "text-[#71717a]"
                      }`}
                    >
                      {isSelected ? "● ACTIVE" : "○ SELECT"}
                    </span>
                  </div>
                  <p className="mt-2 text-xs text-[#888888] font-sans leading-relaxed">
                    {item.desc}
                  </p>
                  <div className="mt-4 pt-3 border-t border-[#222222] flex items-center justify-between text-[11px] font-mono text-[#71717a]">
                    <span className={isSelected ? "text-[#0055FF] font-medium" : "text-white font-medium"}>{item.tag}</span>
                    <ArrowRight className={`w-3.5 h-3.5 ${isSelected ? "text-[#0055FF]" : "text-white"}`} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
