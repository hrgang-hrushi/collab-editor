"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Copy, Check } from "lucide-react";
import Link from "next/link";

export default function AeyeInstallationSection() {
  const [activeTab, setActiveTab] = useState<"js" | "cli" | "python">("js");
  const [copied, setCopied] = useState(false);

  const tabs = [
    {
      id: "js" as const,
      label: "JavaScript",
      desc: "Integrate the utility directly into your application logic with a lightweight client.",
      code: `import { CruxClient } from "@crux/product";

const client = new CruxClient({
  apiKey: process.env.CRUX_API_KEY,
});

// Send input & context
const response = await client.generate({
  task: "summarize",
  input: "summarize the following document into key insights",
});

// Trigger next action
if (metadata.score > 0.8) {
  await notifyUser(output);
}`,
    },
    {
      id: "cli" as const,
      label: "CLI",
      desc: "Execute commands directly from your local terminal with instant hardware execution.",
      code: `# 1. Install Crux native binary
curl -fsSL https://codecrux.us/install.sh | bash

# 2. Launch bare-metal IDE in current directory
crux .

# 3. Join live encrypted peer session
crux --join="session://team-alpha-09" --webrtc`,
    },
    {
      id: "python" as const,
      label: "Python",
      desc: "Native SDK for high-performance data processing pipelines and agent execution.",
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

  const currentTab = tabs.find((t) => t.id === activeTab) || tabs[0];

  const handleCopy = () => {
    navigator.clipboard.writeText(currentTab.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="installation" className="relative w-full border-b border-[#222222] bg-[#000000]">
      <div className="max-w-[1280px] mx-auto px-6 py-20">
        {/* Section Header Meta */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#222222] text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-[#0055FF] font-bold">[N.05/11]</span>
            <span className="text-[#888888]">— &gt;</span>
            <span className="text-[#888888] uppercase">INSTALLATION</span>
          </div>
          <div className="text-[11px] text-[#71717a] pt-1 sm:pt-0 font-mono">
            SDK &amp; DEVELOPER TOOLCHAIN
          </div>
        </div>

        {/* 2-Column Section Layout matching Frame 022 */}
        <div className="pt-12 grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-start">
          {/* Left Column: Code Window in Dotted Bracket Frame */}
          <div className="lg:col-span-7">
            <div className="relative p-6 sm:p-8 border border-[#1a1a1e] bg-[#050507]">
              {/* 4 Corner Double-Dot Accents matching video */}
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
              <div className="border border-[#222222] bg-[#0c0c0e] rounded-none overflow-hidden">
                {/* Header bar with Crux brand and Copy button */}
                <div className="h-10 px-4 bg-[#111114] border-b border-[#222222] flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold text-white uppercase tracking-wider">
                    CRUX
                  </span>
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 font-mono text-xs text-[#888888] hover:text-white transition-none"
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

                {/* Syntax-highlighted code viewport */}
                <div className="p-5 font-mono text-xs sm:text-[13px] leading-relaxed overflow-x-auto min-h-[300px] text-[#d4d4d8]">
                  <pre className="text-left font-mono">
                    <code>
                      {currentTab.code.split("\n").map((line, i) => {
                        let styledLine = <span className="text-[#a1a1aa]">{line}</span>;

                        if (line.startsWith("//") || line.startsWith("#")) {
                          styledLine = <span className="text-[#52525b]">{line}</span>;
                        } else if (line.includes("import ") || line.includes("from ") || line.includes("const ") || line.includes("await ") || line.includes("if ") || line.includes("new ")) {
                          styledLine = (
                            <span>
                              {line.split(" ").map((word, wIdx) => {
                                if (["import", "from", "const", "await", "if", "new"].includes(word)) {
                                  return <span key={wIdx} className="text-[#0055FF] font-medium">{word} </span>;
                                }
                                if (word.startsWith('"') || word.endsWith('"')) {
                                  return <span key={wIdx} className="text-[#22c55e]">{word} </span>;
                                }
                                return <span key={wIdx} className="text-white">{word} </span>;
                              })}
                            </span>
                          );
                        }

                        return (
                          <div key={i} className="table-row">
                            <span className="table-cell select-none pr-4 text-[#3f3f46] text-right">
                              {i + 1}
                            </span>
                            <span className="table-cell">{styledLine}</span>
                          </div>
                        );
                      })}
                    </code>
                  </pre>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Title, Get Started Button, and Vertical Selector */}
          <div className="lg:col-span-5 flex flex-col justify-between h-full pt-2">
            <div>
              <h2 className="text-3xl sm:text-5xl font-normal tracking-[-0.04em] text-white font-sans leading-[1.12]">
                Simple to integrate.
                <span className="block text-[#888888]">Unlock new workflow.</span>
              </h2>

              <div className="mt-6">
                <Link
                  href="#pricing"
                  className="inline-flex items-center gap-2.5 px-4 py-2.5 bg-[#000000] border border-white text-white font-sans text-xs tracking-wider uppercase hover:bg-white hover:text-black transition-none"
                >
                  <span className="w-1.5 h-1.5 bg-white group-hover:bg-black inline-block" />
                  GET STARTED
                </Link>
              </div>
            </div>

            {/* Vertical Progress Rail with Tabs matching video */}
            <div className="mt-14 relative pl-8">
              {/* Vertical Dashed Line */}
              <div className="absolute left-2.5 top-2 bottom-6 w-[1px] border-l border-dashed border-[#333333]" />

              <div className="space-y-8">
                {tabs.map((tab) => {
                  const isActive = activeTab === tab.id;
                  return (
                    <div
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className="relative cursor-pointer group"
                    >
                      {/* Active Indicator Square Node on line */}
                      <div
                        className={`absolute -left-[27px] top-1.5 w-2 h-2 transition-none ${
                          isActive
                            ? "bg-[#0055FF] shadow-[0_0_8px_#0055FF]"
                            : "bg-[#222222] group-hover:bg-[#444444]"
                        }`}
                      />

                      <h3
                        className={`text-xl font-medium font-sans transition-none ${
                          isActive ? "text-[#0055FF]" : "text-[#71717a] group-hover:text-white"
                        }`}
                      >
                        {tab.label}
                      </h3>

                      {isActive && (
                        <motion.p
                          initial={{ opacity: 0, y: 4 }}
                          animate={{ opacity: 1, y: 0 }}
                          className="mt-2 text-xs sm:text-sm text-[#888888] font-sans leading-relaxed"
                        >
                          {tab.desc}
                        </motion.p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
