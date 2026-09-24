"use client";

import React, { useState } from "react";
import { Layers, RotateCcw, GitBranch, Move, Users, History, FileCode2 } from "lucide-react";

export default function SpatialRewindSection() {
  // Time-travel scrubber state
  const [rewindIndex, setRewindIndex] = useState(2); // 0, 1, 2, 3
  const [activeSpatialNode, setActiveSpatialNode] = useState("auth");

  const TIMELINE_STEPS = [
    {
      time: "42m ago",
      author: "Alex Rivera",
      hash: "a9f82c1",
      commitMsg: "chore: init crdt vector buffer",
      diffCode: [
        "// Step 1: Decentralized Lamport clock",
        "+ pub struct VectorBuffer {",
        "+   nodes: HashMap<PeerId, u64>,",
        "+ }",
      ],
    },
    {
      time: "18m ago",
      author: "Sarah Lin",
      hash: "3b2e71d",
      commitMsg: "feat: direct metal texture blit",
      diffCode: [
        "// Step 2: Instanced WebGPU glyph cache",
        "  pub struct VectorBuffer {",
        "+   pipeline: MetalTexturePipeline,",
        "+   glyph_buffer: GpuRingBuffer,",
        "  }",
      ],
    },
    {
      time: "4m ago",
      author: "@CruxAI Agent",
      hash: "82de90c",
      commitMsg: "refactor: lock-free atomic broadcast",
      diffCode: [
        "// Step 3: Zero-alloc sub-15ms broadcast",
        "  pub struct VectorBuffer {",
        "+   broadcast: Arc<LockFreeRingBuffer>,",
        "-   mutex: Mutex<Vec<PeerDelta>>,",
        "  }",
      ],
    },
    {
      time: "Just now (Live)",
      author: "You",
      hash: "HEAD",
      commitMsg: "feat: live AST synchronization",
      diffCode: [
        "// Step 4: Sub-15ms Live synchronization",
        "  pub struct VectorBuffer {",
        "    broadcast: Arc<LockFreeRingBuffer>,",
        "    sync_state: AtomicU64::new(0),",
        "  }",
      ],
    },
  ];

  const currentStep = TIMELINE_STEPS[rewindIndex];

  return (
    <section className="py-24 px-6 max-w-6xl mx-auto border-t border-[#222222]">
      {/* Header */}
      <div className="text-center max-w-2xl mx-auto mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-none bg-[#111111] border border-[#222222] text-white text-xs font-mono mb-4">
          <Layers className="w-3.5 h-3.5 text-white" />
          <span>[SPATIAL COMPUTING &amp; AST DETERMINISM]</span>
        </div>
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-white mb-4 font-sans">
          Spatial Canvas &amp; Time-Travel Rewind.
        </h2>
        <p className="text-sm sm:text-base text-[#888888] leading-relaxed font-sans">
          Break free from cramped single-file tabs. View your entire architecture across an infinite
          GPU canvas, or scrub code history backwards in time with deterministic AST precision.
        </p>
      </div>

      {/* 2 Interactive Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Card 1: Infinite Spatial Canvas */}
        <div
          className="rounded-none border border-[#222222] bg-[#000000] p-6 sm:p-8 flex flex-col justify-between relative overflow-hidden group hover:border-white transition-none"
          style={{
            fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
          }}
        >
          <div>
            <div className="flex items-center justify-between text-xs font-mono mb-4">
              <span className="flex items-center gap-2 text-white font-bold uppercase tracking-wider">
                <Move className="w-3.5 h-3.5 text-white" />
                <span>Infinite Spatial Zoning</span>
              </span>
              <span className="text-[#888888]">GPU Zoom: 100%</span>
            </div>

            <h3 className="text-xl font-bold text-white mb-2 font-sans">
              Pan, Zoom, and Arrange Multi-File Context
            </h3>
            <p className="text-xs text-[#888888] leading-relaxed mb-6 font-sans">
              Instead of switching tabs, see your frontend, database schema, and backend endpoints
              laid out spatially with real-time peer cursor trails and AST dependency links.
            </p>

            {/* Interactive Spatial Canvas Miniature */}
            <div className="relative h-64 rounded-none bg-[#0a0a0a] border border-[#222222] overflow-hidden p-4">
              {/* Node 1: Auth Module */}
              <div
                onClick={() => setActiveSpatialNode("auth")}
                className={`absolute top-4 left-4 w-44 p-3 rounded-none border transition-none cursor-pointer ${
                  activeSpatialNode === "auth"
                    ? "bg-[#111111] border-white text-white"
                    : "bg-[#000000] border-[#222222] text-[#888888] hover:text-white"
                }`}
              >
                <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                  <span className="font-bold flex items-center gap-1 text-white">
                    <FileCode2 className="w-3 h-3 text-white" />
                    <span>auth/session.rs</span>
                  </span>
                  <span className="w-1.5 h-1.5 rounded-none bg-white" />
                </div>
                <div className="text-[9px] font-mono text-[#888888] truncate">
                  JWT validation + Ed25519
                </div>
              </div>

              {/* Node 2: Database Schema */}
              <div
                onClick={() => setActiveSpatialNode("db")}
                className={`absolute top-28 left-40 w-48 p-3 rounded-none border transition-none cursor-pointer ${
                  activeSpatialNode === "db"
                    ? "bg-[#111111] border-white text-white"
                    : "bg-[#000000] border-[#222222] text-[#888888] hover:text-white"
                }`}
              >
                <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                  <span className="font-bold flex items-center gap-1 text-white">
                    <FileCode2 className="w-3 h-3 text-white" />
                    <span>schema.prisma</span>
                  </span>
                  <span className="text-[9px] text-[#888888]">PostgreSQL</span>
                </div>
                <div className="text-[9px] font-mono text-[#888888] truncate">
                  model User &amp; WorkspaceSession
                </div>
              </div>

              {/* Node 3: Realtime CRDT Engine */}
              <div
                onClick={() => setActiveSpatialNode("crdt")}
                className={`absolute bottom-4 right-4 w-52 p-3 rounded-none border transition-none cursor-pointer ${
                  activeSpatialNode === "crdt"
                    ? "bg-[#111111] border-white text-white"
                    : "bg-[#000000] border-[#222222] text-[#888888] hover:text-white"
                }`}
              >
                <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                  <span className="font-bold flex items-center gap-1 text-white">
                    <FileCode2 className="w-3 h-3 text-white" />
                    <span>crdt/broadcast.rs</span>
                  </span>
                  <span className="text-white font-bold text-[9px]">[120 FPS]</span>
                </div>
                <div className="text-[9px] font-mono text-[#888888] truncate">
                  WebRTC P2P Yjs Protocol
                </div>
              </div>

              {/* Connecting SVG Vector Link lines */}
              <svg className="absolute inset-0 pointer-events-none w-full h-full opacity-40">
                <line x1="120" y1="50" x2="220" y2="130" stroke="#444444" strokeWidth="1.5" strokeDasharray="3 3" />
                <line x1="280" y1="160" x2="350" y2="200" stroke="#444444" strokeWidth="1.5" strokeDasharray="3 3" />
              </svg>
            </div>
          </div>

          <div className="pt-6 border-t border-[#222222] mt-6 flex items-center justify-between text-xs font-mono text-[#888888]">
            <span className="flex items-center gap-1.5 text-white">
              <Users className="w-3.5 h-3.5 text-white" />
              <span>Multiplayer Spatial Cursors Enabled</span>
            </span>
            <span className="text-[#444444]">Click any card to focus</span>
          </div>
        </div>

        {/* Card 2: Time-Travel History Rewind */}
        <div
          className="rounded-none border border-[#222222] bg-[#000000] p-6 sm:p-8 flex flex-col justify-between relative overflow-hidden group hover:border-white transition-none"
          style={{
            fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
          }}
        >
          <div>
            <div className="flex items-center justify-between text-xs font-mono mb-4">
              <span className="flex items-center gap-2 text-white font-bold uppercase tracking-wider">
                <RotateCcw className="w-3.5 h-3.5 text-white" />
                <span>Time-Travel AST Rewind</span>
              </span>
              <span className="text-[#888888] font-mono">{currentStep.time}</span>
            </div>

            <h3 className="text-xl font-bold text-white mb-2 font-sans">
              Scrub Code History Deterministically
            </h3>
            <p className="text-xs text-[#888888] leading-relaxed mb-6 font-sans">
              Every keystroke is recorded as an immutable CRDT delta. Drag the timeline slider to
              rewind your codebase backwards or forwards in time without Git branch switching.
            </p>

            {/* Interactive Timeline Scrubber Slider */}
            <div className="p-4 rounded-none bg-[#0a0a0a] border border-[#222222] space-y-4">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-[#888888]">Scrubber Timeline:</span>
                <span className="text-white font-bold">
                  {currentStep.author} · commit {currentStep.hash}
                </span>
              </div>

              <input
                type="range"
                min="0"
                max={TIMELINE_STEPS.length - 1}
                step="1"
                value={rewindIndex}
                onChange={(e) => setRewindIndex(parseInt(e.target.value))}
                className="w-full h-1.5 bg-[#222222] rounded-none appearance-none cursor-pointer accent-white"
              />

              <div className="flex justify-between text-[10px] font-mono text-[#888888]">
                {TIMELINE_STEPS.map((s, idx) => (
                  <button
                    key={idx}
                    onClick={() => setRewindIndex(idx)}
                    className={`transition-none cursor-pointer ${
                      rewindIndex === idx ? "text-white font-bold" : "hover:text-white"
                    }`}
                  >
                    {s.time}
                  </button>
                ))}
              </div>

              {/* Dynamic Code Diff Window */}
              <div className="p-3.5 rounded-none bg-[#000000] border border-[#222222] font-mono text-xs space-y-1 overflow-x-auto">
                <div className="text-[10px] text-[#888888] pb-1 border-b border-[#222222] flex justify-between">
                  <span>Message: {currentStep.commitMsg}</span>
                  <span className="text-white font-bold">{currentStep.hash}</span>
                </div>
                {currentStep.diffCode.map((line, idx) => (
                  <div
                    key={idx}
                    className={
                      line.startsWith("+")
                        ? "text-black bg-white px-1 py-0.5 rounded-none font-bold"
                        : line.startsWith("-")
                        ? "text-[#666666] line-through px-1 py-0.5"
                        : "text-white px-1"
                    }
                  >
                    {line}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="pt-6 border-t border-[#222222] mt-6 flex items-center justify-between text-xs font-mono text-[#888888]">
            <span className="flex items-center gap-1.5 text-white">
              <History className="w-3.5 h-3.5 text-white" />
              <span>Full Monorepo History in &lt;18MB index</span>
            </span>
            <span className="text-[#444444]">Zero data loss guaranteed</span>
          </div>
        </div>
      </div>
    </section>
  );
}
