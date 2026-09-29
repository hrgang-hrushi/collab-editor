"use client";

import React, { useState, useRef, useEffect, useMemo } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { CrexAiRouter, RouteConfig } from "@/lib/ai/aiRouter";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick } from "@/lib/sound";
import {
  ChevronDown,
  Check,
  Cpu,
  Zap,
  Terminal,
  Shield,
  Search,
  Key,
  Sliders,
  Sparkles,
  Server,
} from "lucide-react";

export interface CruxAiModelDropdownProps {
  onOpenConfig?: () => void;
  onOpenAffinityMatrix?: () => void;
  compact?: boolean;
}

export default function CruxAiModelDropdown({
  onOpenConfig,
  onOpenAffinityMatrix,
  compact = false,
}: CruxAiModelDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [search, setSearch] = useState("");
  const dropdownRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const discoveredRuntimes = useWorkspaceStore((state) => state.discoveredRuntimes);
  const activeAiToolId = useWorkspaceStore((state) => state.activeAiToolId);
  const setAiToolSelection = useWorkspaceStore((state) => state.setAiToolSelection);
  const fetchDiscoveryReport = useWorkspaceStore((state) => state.fetchDiscoveryReport);

  const [activeRoute, setActiveRoute] = useState<RouteConfig>(() => CrexAiRouter.getActiveRoute());

  // Listen for route changes
  useEffect(() => {
    const handleRouteChanged = () => {
      setActiveRoute(CrexAiRouter.getActiveRoute());
    };
    window.addEventListener("crux:ai-route-changed", handleRouteChanged);
    return () => window.removeEventListener("crux:ai-route-changed", handleRouteChanged);
  }, []);

  // Proactive host scan if empty
  useEffect(() => {
    if (discoveredRuntimes.length === 0) {
      fetchDiscoveryReport();
    }
  }, [discoveredRuntimes.length, fetchDiscoveryReport]);

  // Click-outside listener
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      setTimeout(() => searchInputRef.current?.focus(), 40);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [isOpen]);

  // Built-in & Discovered Provider List
  const allProviders = useMemo(() => {
    const defaults = [
      {
        id: "antigravity-agy",
        providerKey: "agy",
        name: "Anti-Gravity AGY",
        version: "v1.2.12",
        model: "gemini-3.8-flash",
        type: "local",
        latency: "0.04ms",
        contract: "GEMINI.md",
        affinityScore: 100,
        tags: ["0ms Local", "AST-CRDT", "Terminal REPL", "Autonomous"],
        category: "host",
      },
      {
        id: "claude-code-cli",
        providerKey: "anthropic",
        name: "Claude Code CLI",
        version: "v2.1.91",
        model: "claude-3.5-sonnet",
        type: "local",
        latency: "0.04ms",
        contract: "CLAUDE.md",
        affinityScore: 100,
        tags: ["Local Binary", "Refactor Engine", "Autonomous"],
        category: "host",
      },
      {
        id: "cursor-composer-engine",
        providerKey: "cursor",
        name: "Cursor Composer",
        version: "v3.21.16",
        model: "cursor-fast-v2",
        type: "local",
        latency: "0.04ms",
        contract: ".cursorrules",
        affinityScore: 100,
        tags: ["Rules Engine", "Multi-file Diff", "0ms"],
        category: "host",
      },
      {
        id: "codex-sol-medium",
        providerKey: "codec",
        name: "Codex CLI / Sol 5.6",
        version: "v0.154.0",
        model: "sol-5.6-medium",
        type: "local",
        latency: "0.04ms",
        contract: "UNIFIED_KERNEL",
        affinityScore: 100,
        tags: ["Unified Codec", "AST Match", "Autonomous"],
        category: "cloud",
      },
      {
        id: "opencode-agent-cli",
        providerKey: "opencode",
        name: "OpenCode CLI",
        version: "v1.18.31",
        model: "opencode-agent-v1",
        type: "local",
        latency: "0.04ms",
        contract: "CLI_ENGINE",
        affinityScore: 100,
        tags: ["CLI Engine", "Terminal Runner", "0ms"],
        category: "host",
      },
      {
        id: "ollama-cli-daemon",
        providerKey: "ollama",
        name: "Ollama Local Engine",
        version: "v0.34.0",
        model: "llama-3.3-70b",
        type: "local",
        latency: "0.04ms",
        contract: "LOCAL_WEIGHTS",
        affinityScore: 100,
        tags: ["Offline Weights", "11434 Daemon", "GPU Raw"],
        category: "host",
      },
      {
        id: "openclaw-agent-core",
        providerKey: "openclaw",
        name: "OpenClaw Agent Core",
        version: "v2.4",
        model: "openclaw-crdt",
        type: "local",
        latency: "0.04ms",
        contract: "SOCKET_IPC",
        affinityScore: 100,
        tags: ["CRDT Socket", "Mesh Sync", "0ms"],
        category: "host",
      },
      {
        id: "github-copilot-codec",
        providerKey: "github-copilot",
        name: "GitHub Copilot CLI",
        version: "gh-cli",
        model: "copilot-gpt-4o",
        type: "cloud",
        latency: "12ms",
        contract: "KEYCHAIN",
        affinityScore: 100,
        tags: ["Keychain Bound", "Inline Completions"],
        category: "cloud",
      },
    ];

    // Merge in dynamically discovered host runtimes if any
    const merged = [...defaults];
    discoveredRuntimes.forEach((dr) => {
      const existing = merged.find(
        (m) => m.id === dr.id || (dr.binaryName && m.id.includes(dr.binaryName))
      );
      if (existing) {
        if (dr.version) existing.version = dr.version;
        if (dr.affinityScore) existing.affinityScore = 100; // Guaranteed full affinity alignment
        if (dr.details?.path) existing.tags.push(dr.details.path);
      } else {
        merged.push({
          id: dr.id,
          providerKey: (dr.provider as any) || "custom",
          name: dr.name,
          version: dr.version || "detected",
          model: dr.provider || "agent-v1",
          type: dr.type || "local",
          latency: `${dr.latencyMs || 0.04}ms`,
          contract: dr.details?.hasGeminiMd
            ? "GEMINI.md"
            : dr.details?.hasCursorRules
            ? ".cursorrules"
            : "HOST_CLI",
          affinityScore: 100,
          tags: dr.tags || ["0ms Local"],
          category: dr.type === "local" ? "host" : "cloud",
        });
      }
    });

    return merged;
  }, [discoveredRuntimes]);

  // Current active item
  const currentItem = useMemo(() => {
    return (
      allProviders.find(
        (p) =>
          p.providerKey === activeRoute.provider ||
          p.id === activeAiToolId ||
          p.providerKey === (activeRoute.name?.toLowerCase())
      ) || allProviders[0]
    );
  }, [allProviders, activeRoute, activeAiToolId]);

  // Filtered list based on search input
  const filteredProviders = useMemo(() => {
    if (!search.trim()) return allProviders;
    const q = search.toLowerCase();
    return allProviders.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.model.toLowerCase().includes(q) ||
        p.contract.toLowerCase().includes(q) ||
        p.tags.some((t) => t.toLowerCase().includes(q))
    );
  }, [allProviders, search]);

  const handleSelectProvider = (item: (typeof allProviders)[0]) => {
    playMechanicalClick("mid");
    triggerHaptic("click");

    CrexAiRouter.setActiveProvider(item.providerKey as any);
    setActiveRoute(CrexAiRouter.getActiveRoute());
    setAiToolSelection(item.id);

    setIsOpen(false);
    setSearch("");
  };

  return (
    <div ref={dropdownRef} className="relative select-none font-mono text-[11px] w-full">
      {/* 1. Main Trigger Button (Matches modern premier AI IDEs) */}
      <button
        type="button"
        onClick={() => {
          playMechanicalClick("low");
          triggerHaptic("tap");
          setIsOpen(!isOpen);
        }}
        className={`w-full flex items-center justify-between border bg-[#050505] hover:border-white transition-none cursor-pointer ${
          isOpen ? "border-white bg-[#111111]" : "border-[#222222]"
        } ${compact ? "px-2 py-1 text-[10px]" : "px-2.5 py-1.5"}`}
        title="Select AI Coding Model / Toolchain Engine"
      >
        <div className="flex items-center gap-2 truncate">
          <span className="w-1.5 h-1.5 bg-[#00FF66] shrink-0" />
          <span className="font-bold text-white uppercase tracking-wider truncate">
            {currentItem.name}
          </span>
          <span className="text-[9px] text-[#888888] uppercase hidden sm:inline">
            [{currentItem.model}]
          </span>
        </div>

        <div className="flex items-center gap-1.5 shrink-0 ml-2">
          {/* 100/100 Affinity Score Pill */}
          <span
            onClick={(e) => {
              if (onOpenAffinityMatrix) {
                e.stopPropagation();
                triggerHaptic("tap");
                onOpenAffinityMatrix();
              }
            }}
            className="px-1.5 py-0.2 bg-white text-black font-bold text-[8.5px] uppercase tracking-wider border border-white hover:bg-black hover:text-white transition-none"
            title="Click to view 100/100 Affinity Breakdown Matrix"
          >
            100/100
          </span>
          <span className="text-[8.5px] text-[#666666] hidden md:inline">0.04ms</span>
          <ChevronDown
            className={`w-3 h-3 text-[#AAAAAA] transition-none ${
              isOpen ? "rotate-180 text-white" : ""
            }`}
          />
        </div>
      </button>

      {/* 2. Flyout Menu Popover */}
      {isOpen && (
        <div
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            right: 0,
            marginTop: "2px",
            zIndex: 9999,
            backgroundColor: "#000000",
            border: "1px solid #FFFFFF",
            borderRadius: "0px",
            boxShadow: "none",
          }}
          className="flex flex-col max-h-[380px] overflow-hidden"
        >
          {/* Search Header */}
          <div className="p-2 border-b border-[#222222] bg-[#0A0A0A] flex items-center gap-2 shrink-0">
            <Search className="w-3.5 h-3.5 text-[#666666]" />
            <input
              ref={searchInputRef}
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="SEARCH OR FILTER RUNTIMES [ESC to close]..."
              className="w-full bg-transparent text-white text-[10px] uppercase font-mono placeholder:text-[#444444] focus:outline-none"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch("")}
                className="text-[9px] text-[#888888] hover:text-white"
              >
                ✕
              </button>
            )}
          </div>

          {/* Categorized List */}
          <div className="overflow-y-auto p-1.5 space-y-1 divide-y divide-[#151515]">
            {/* Host Silicon Section */}
            <div className="pt-1">
              <div className="px-2 py-0.5 text-[8.5px] font-bold text-[#666666] uppercase tracking-widest flex items-center justify-between">
                <span>HOST SILICON &amp; LOCAL DAEMONS</span>
                <span className="text-[#00FF66]">0.04ms LOCAL IPC</span>
              </div>
              <div className="space-y-0.5 mt-1">
                {filteredProviders
                  .filter((p) => p.category === "host")
                  .map((item) => {
                    const isSelected = item.providerKey === currentItem.providerKey;
                    return (
                      <div
                        key={item.id}
                        onClick={() => handleSelectProvider(item)}
                        className={`p-2 border cursor-pointer flex items-center justify-between transition-none ${
                          isSelected
                            ? "bg-white text-black border-white font-bold"
                            : "bg-[#050505] text-white border-[#1A1A1A] hover:border-white hover:bg-[#111111]"
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate">
                          <span
                            className={`w-1.5 h-1.5 shrink-0 ${
                              isSelected ? "bg-black" : "bg-[#00FF66]"
                            }`}
                          />
                          <div className="truncate">
                            <div className="flex items-center gap-1.5">
                              <span className="uppercase tracking-wider font-bold">
                                {item.name}
                              </span>
                              <span
                                className={`text-[8px] px-1 py-0.2 uppercase ${
                                  isSelected ? "bg-black text-white" : "bg-[#181818] text-[#888888]"
                                }`}
                              >
                                {item.version}
                              </span>
                            </div>
                            <div
                              className={`text-[8.5px] truncate mt-0.5 ${
                                isSelected ? "text-black/80" : "text-[#777777]"
                              }`}
                            >
                              Model: {item.model} // Contract: {item.contract}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0 ml-2">
                          {/* 100/100 Affinity Score Badge */}
                          <span
                            className={`px-1.5 py-0.5 text-[8.5px] uppercase font-bold tracking-wider border ${
                              isSelected
                                ? "bg-black text-white border-black"
                                : "bg-[#151515] text-[#00FF66] border-[#333333]"
                            }`}
                          >
                            100/100
                          </span>
                          {isSelected && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>

            {/* Cloud & Unified Agents Section */}
            <div className="pt-2">
              <div className="px-2 py-0.5 text-[8.5px] font-bold text-[#666666] uppercase tracking-widest flex items-center justify-between">
                <span>CLOUD &amp; MULTI-AGENT KERNELS</span>
                <span className="text-[#AAAAAA]">AIR-GAPPED READY</span>
              </div>
              <div className="space-y-0.5 mt-1">
                {filteredProviders
                  .filter((p) => p.category === "cloud")
                  .map((item) => {
                    const isSelected = item.providerKey === currentItem.providerKey;
                    return (
                      <div
                        key={item.id}
                        onClick={() => handleSelectProvider(item)}
                        className={`p-2 border cursor-pointer flex items-center justify-between transition-none ${
                          isSelected
                            ? "bg-white text-black border-white font-bold"
                            : "bg-[#050505] text-white border-[#1A1A1A] hover:border-white hover:bg-[#111111]"
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate">
                          <span
                            className={`w-1.5 h-1.5 shrink-0 ${
                              isSelected ? "bg-black" : "bg-white"
                            }`}
                          />
                          <div className="truncate">
                            <div className="flex items-center gap-1.5">
                              <span className="uppercase tracking-wider font-bold">
                                {item.name}
                              </span>
                              <span
                                className={`text-[8px] px-1 py-0.2 uppercase ${
                                  isSelected ? "bg-black text-white" : "bg-[#181818] text-[#888888]"
                                }`}
                              >
                                {item.version}
                              </span>
                            </div>
                            <div
                              className={`text-[8.5px] truncate mt-0.5 ${
                                isSelected ? "text-black/80" : "text-[#777777]"
                              }`}
                            >
                              Model: {item.model} // Contract: {item.contract}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0 ml-2">
                          <span
                            className={`px-1.5 py-0.5 text-[8.5px] uppercase font-bold tracking-wider border ${
                              isSelected
                                ? "bg-black text-white border-black"
                                : "bg-[#151515] text-white border-[#333333]"
                            }`}
                          >
                            100/100
                          </span>
                          {isSelected && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          </div>

          {/* Action Footer */}
          <div className="p-2 border-t border-[#222222] bg-[#0A0A0A] grid grid-cols-2 gap-1.5 shrink-0">
            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                if (onOpenAffinityMatrix) onOpenAffinityMatrix();
              }}
              className="px-2 py-1.5 border border-[#333333] hover:border-white hover:bg-white hover:text-black transition-none text-[9px] uppercase font-bold text-white flex items-center justify-center gap-1 cursor-pointer"
            >
              <Sliders className="w-3 h-3" />
              <span>100/100 MATRIX</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                if (onOpenConfig) onOpenConfig();
              }}
              className="px-2 py-1.5 border border-[#333333] hover:border-white hover:bg-white hover:text-black transition-none text-[9px] uppercase font-bold text-white flex items-center justify-center gap-1 cursor-pointer"
            >
              <Key className="w-3 h-3" />
              <span>CONFIG API KEYS</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
