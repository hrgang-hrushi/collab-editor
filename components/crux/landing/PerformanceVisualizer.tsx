"use client";

import React, { useState } from "react";
import { Zap, Cpu, Activity, Gauge, Check, AlertTriangle, Layers } from "lucide-react";

interface BenchmarkMetric {
  title: string;
  cruxValue: string;
  electronValue: string;
  unit: string;
  factor: string;
  description: string;
  cruxPercent: number;
}

const METRICS: BenchmarkMetric[] = [
  {
    title: "Input to Photon Latency",
    cruxValue: "4.2",
    electronValue: "48.6",
    unit: "ms",
    factor: "11.5x FASTER",
    description: "Time from physical key switch contact to pixel phosphor emission on display.",
    cruxPercent: 9,
  },
  {
    title: "Idle Memory Footprint",
    cruxValue: "38",
    electronValue: "680",
    unit: "MB",
    factor: "17.8x LEANER",
    description: "RAM consumption with workspace open. Zero Chromium V8 engine baggage.",
    cruxPercent: 6,
  },
  {
    title: "Cold Boot / Launch Time",
    cruxValue: "140",
    electronValue: "2,400",
    unit: "ms",
    factor: "17.1x FASTER",
    description: "Launch to interactive cursor state. Instantaneous Mach-O binary execution.",
    cruxPercent: 6,
  },
  {
    title: "250,000-Line Scroll Rate",
    cruxValue: "120",
    electronValue: "18",
    unit: "FPS",
    factor: "6.6x SMOOTHER",
    description: "Stress-test throughput scrolling huge monorepos without layout thrashing.",
    cruxPercent: 100,
  },
];

export default function PerformanceVisualizer() {
  const [testInput, setTestInput] = useState("");
  const [renderCount, setRenderCount] = useState(0);

  const handleTestKey = (e: React.ChangeEvent<HTMLInputElement>) => {
    setTestInput(e.target.value);
    setRenderCount((prev) => prev + 1);
  };

  return (
    <section id="benchmarks" className="py-24 px-6 max-w-6xl mx-auto border-t border-[#222222]">
      {/* Section Header */}
      <div className="text-center max-w-2xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-none bg-[#111111] border border-[#222222] text-white text-xs font-mono mb-4">
          <Zap className="w-3.5 h-3.5 text-white fill-current" />
          <span>[HARDWARE ACCELERATION BENCHMARKS]</span>
        </div>
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-white mb-4 font-sans">
          Sub-15ms Latency. Measured, Not Marketed.
        </h2>
        <p className="text-sm sm:text-base text-[#888888] leading-relaxed font-sans">
          Modern web-based editors pack 200MB Chromium runtimes per window. Crux compiles directly
          to native Apple Silicon and x86_64 machine code, rasterizing every character via WebGPU and Metal.
        </p>
      </div>

      {/* 4-Column Benchmark Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-12">
        {METRICS.map((metric, idx) => (
          <div
            key={idx}
            className="p-6 rounded-none bg-[#000000] border border-[#222222] hover:border-white transition-none flex flex-col justify-between group"
            style={{
              fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
            }}
          >
            <div>
              <div className="flex items-center justify-between text-[11px] font-mono text-[#888888] mb-3">
                <span className="uppercase tracking-wider">{metric.title}</span>
                <span className="text-black font-bold px-1.5 py-0.5 rounded-none bg-white">
                  {metric.factor}
                </span>
              </div>

              {/* Crux Value Display */}
              <div className="flex items-baseline gap-2 mb-1">
                <span className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
                  {metric.cruxValue}
                </span>
                <span className="text-sm text-[#888888] font-mono">{metric.unit}</span>
                <span className="ml-auto text-xs font-bold text-white font-mono uppercase">[Crux]</span>
              </div>

              {/* Electron Value Contrast */}
              <div className="flex items-baseline justify-between text-xs text-[#444444] font-mono pb-4 border-b border-[#222222]">
                <span>Legacy Editors:</span>
                <span className="line-through text-[#888888]">
                  {metric.electronValue} {metric.unit}
                </span>
              </div>
            </div>

            <div className="pt-4">
              {/* Dual Visual Bar */}
              <div className="space-y-1.5 mb-3">
                <div className="flex justify-between text-[10px] text-[#888888] font-mono">
                  <span>Crux Pipeline</span>
                  <span className="text-white font-bold">100% Native</span>
                </div>
                <div className="h-1.5 w-full bg-[#111111] rounded-none overflow-hidden border border-[#222222]">
                  <div
                    className="h-full bg-white rounded-none"
                    style={{ width: `${Math.max(metric.cruxPercent, 12)}%` }}
                  />
                </div>
              </div>

              <p className="text-[11px] text-[#888888] leading-relaxed font-sans">
                {metric.description}
              </p>
            </div>
          </div>
        ))}
      </div>

      {/* Interactive Pipeline Comparison Container */}
      <div
        className="rounded-none border border-[#222222] bg-[#000000] p-6 sm:p-8 relative overflow-hidden"
        style={{
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
        }}
      >
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 pb-6 border-b border-[#222222]">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-white mb-1">
              <Activity className="w-4 h-4 text-white" />
              <span>[LIVE FRAME TIME TELEMETRY]</span>
            </div>
            <h3 className="text-xl font-bold text-white font-sans">
              Direct GPU Pipeline vs. HTML DOM Layering
            </h3>
          </div>

          {/* Interactive Keystroke Test Input */}
          <div className="w-full md:w-auto flex items-center gap-3 bg-[#111111] px-4 py-2 rounded-none border border-[#222222]">
            <span className="text-xs text-[#888888] font-mono shrink-0">Test Keystroke:</span>
            <input
              type="text"
              value={testInput}
              onChange={handleTestKey}
              placeholder="Type anything here..."
              className="bg-transparent text-white text-xs font-mono focus:outline-none placeholder-[#444444] w-44"
            />
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-none bg-[#000000] text-white border border-[#222222]">
              {renderCount > 0 ? "3.8ms" : "Idle"}
            </span>
          </div>
        </div>

        {/* Side-by-Side Pipeline Diagram */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-6">
          {/* Left: Crux Native WebGPU */}
          <div className="p-5 rounded-none bg-[#111111] border border-white space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white flex items-center gap-1.5 font-mono">
                <Check className="w-4 h-4 text-white stroke-[3]" />
                <span>Crux Hardware Execution Core</span>
              </span>
              <span className="text-xs font-mono text-white font-bold bg-[#000000] border border-[#222222] px-2 py-0.5">
                Sub-15ms Bound
              </span>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="p-2.5 rounded-none bg-[#000000] border border-[#222222] flex items-center justify-between text-white">
                <span>1. Keystroke Event Dispatch</span>
                <span className="text-[#888888]">0.2 ms</span>
              </div>
              <div className="p-2.5 rounded-none bg-[#000000] border border-[#222222] flex items-center justify-between text-white">
                <span>2. Rust AST CRDT Node Mutation</span>
                <span className="text-[#888888]">0.6 ms</span>
              </div>
              <div className="p-2.5 rounded-none bg-[#000000] border border-[#222222] flex items-center justify-between text-white">
                <span>3. Direct Metal Texture Instanced Blit</span>
                <span className="text-[#888888]">3.4 ms</span>
              </div>
            </div>

            <div className="pt-2 text-[11px] text-[#888888] flex items-center justify-between border-t border-[#222222]">
              <span>Total Latency to Display</span>
              <span className="font-bold font-mono text-white text-xs">4.2 ms (120 FPS Cap)</span>
            </div>
          </div>

          {/* Right: Legacy Electron / Browser IDEs */}
          <div className="p-5 rounded-none bg-[#000000] border border-[#222222] space-y-4 opacity-75">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-[#888888] flex items-center gap-1.5 font-mono">
                <AlertTriangle className="w-4 h-4 text-[#888888]" />
                <span>Legacy Electron Architecture</span>
              </span>
              <span className="text-xs font-mono text-[#444444]">Unbounded Latency</span>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="p-2.5 rounded-none bg-[#111111] border border-[#222222] flex items-center justify-between text-[#888888]">
                <span>1. Node.js IPC Thread Bounce</span>
                <span className="text-[#444444]">12.4 ms</span>
              </div>
              <div className="p-2.5 rounded-none bg-[#111111] border border-[#222222] flex items-center justify-between text-[#888888]">
                <span>2. DOM Reflow &amp; Style Recalculation</span>
                <span className="text-[#444444]">22.8 ms</span>
              </div>
              <div className="p-2.5 rounded-none bg-[#111111] border border-[#222222] flex items-center justify-between text-[#888888]">
                <span>3. Chromium Compositor &amp; GC Check</span>
                <span className="text-[#444444]">13.4 ms</span>
              </div>
            </div>

            <div className="pt-2 text-[11px] text-[#444444] flex items-center justify-between border-t border-[#222222]">
              <span>Total Latency to Display</span>
              <span className="font-bold font-mono text-[#888888] text-xs">48.6 ms (~20 FPS)</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
