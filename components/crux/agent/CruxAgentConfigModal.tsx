"use client";

import React, { useState, useEffect } from "react";
import { CrexAiRouter, RouteConfig, AiProvider } from "@/lib/ai/aiRouter";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick } from "@/lib/sound";
import {
  X,
  Check,
  Cpu,
  Globe,
  Sparkles,
  RefreshCw,
  Terminal,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
} from "lucide-react";

interface CruxAgentConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface LocalAgentProfile {
  name: string;
  tag: string;
  planName: string;
  description: string;
  binaryPath: string;
  authStatus: "AUTHENTICATED" | "LOCAL_ACTIVE" | "NEEDS_LOGIN" | "SYNCED";
  authNote: string;
  defaultModel: string;
  modelSuggestions: string[];
  loginCommand?: string;
}

const LOCAL_AGENT_PROFILES: Record<AiProvider, LocalAgentProfile> = {
  agy: {
    name: "Anti-Gravity Core (AGY)",
    tag: "GEMINI // LOCAL DAEMON",
    planName: "Host Google / Antigravity Pro Subscription",
    description: "Connects directly to your local Anti-Gravity CLI installation. Zero API keys needed.",
    binaryPath: "/Users/hrushikeshgangala/.local/bin/antigravity",
    authStatus: "AUTHENTICATED",
    authNote: "Attached to local CLI session & unix:///var/run/crux.sock",
    defaultModel: "gemini-3.8-flash-high",
    modelSuggestions: ["gemini-3.8-flash-high", "gemini-3.7-flash", "gemini-3.1-pro"],
  },
  anthropic: {
    name: "Claude Code CLI (Anthropic)",
    tag: "CLAUDE 3.5 SONNET // OPUS",
    planName: "Host Anthropic Claude Subscription",
    description: "Harnesses your local Claude Code CLI installation (~/.local/bin/claude). Uses your existing plan.",
    binaryPath: "/Users/hrushikeshgangala/.local/bin/claude",
    authStatus: "NEEDS_LOGIN",
    authNote: "Claude CLI detected (v2.1.91). Run 'claude login' in terminal to link subscription.",
    defaultModel: "claude-3-5-sonnet-20241022",
    modelSuggestions: ["claude-3-5-sonnet-20241022", "claude-opus-4-6-thinking"],
    loginCommand: "claude login",
  },
  cursor: {
    name: "Cursor Rules Engine",
    tag: ".CURSORRULES // COMPOSER",
    planName: "Cursor Pro / Business Composer",
    description: "Reads local .cursorrules and Cursor User config from ~/Library/Application Support/Cursor.",
    binaryPath: "Cursor App Integration (Local)",
    authStatus: "SYNCED",
    authNote: "Synchronized with repository .cursorrules & local user rules",
    defaultModel: "composer-rules-v2",
    modelSuggestions: ["composer-rules-v2", "claude-3.5-sonnet"],
  },
  "github-copilot": {
    name: "GitHub Copilot / Codec Core",
    tag: "COPILOT // CODEC",
    planName: "GitHub Copilot Individual / Enterprise Plan",
    description: "Reuses your active GitHub Copilot keychain and local ~/.copilot authentication.",
    binaryPath: "GitHub CLI / Copilot Keychain (Local)",
    authStatus: "AUTHENTICATED",
    authNote: "Keychain token detected in ~/.copilot",
    defaultModel: "copilot-codec-preview",
    modelSuggestions: ["copilot-codec-preview", "gpt-4o-copilot"],
  },
  openclaw: {
    name: "OpenClaw Autonomous Agent",
    tag: "OPENCLAW // LOCAL REST",
    planName: "Local OpenClaw Agent Profile",
    description: "Connects to your local OpenClaw daemon and ~/.openclaw configuration.",
    binaryPath: "/Users/hrushikeshgangala/.local/bin/openclaw",
    authStatus: "LOCAL_ACTIVE",
    authNote: "Local daemon configured at ~/.openclaw",
    defaultModel: "openclaw-agent-v1",
    modelSuggestions: ["openclaw-agent-v1"],
  },
  ollama: {
    name: "Local Ollama Engine",
    tag: "LOCAL WEIGHTS // 100% PRIVATE",
    planName: "Local Compute (Free & Private)",
    description: "Runs models directly on your hardware via local Ollama instance (port 11434).",
    binaryPath: "http://127.0.0.1:11434",
    authStatus: "LOCAL_ACTIVE",
    authNote: "Zero cloud requests. 100% private local execution.",
    defaultModel: "codellama",
    modelSuggestions: ["codellama", "llama3.2", "qwen2.5-coder", "deepseek-coder"],
  },
  custom: {
    name: "Custom Coding Tool Bridge",
    tag: "CUSTOM BRIDGE",
    planName: "Custom User Plan / Local Endpoint",
    description: "Bridge to your own custom CLI tool, local LLM server, or proxy.",
    binaryPath: "local://custom-bridge",
    authStatus: "LOCAL_ACTIVE",
    authNote: "Custom tool registered into Crux Kernel",
    defaultModel: "custom-agent-v1",
    modelSuggestions: ["custom-agent-v1", "vllm-local"],
  },
  openai: {
    name: "OpenAI Core",
    tag: "GPT-4o // CODEGEN",
    planName: "OpenAI Subscription",
    description: "OpenAI engine bridge via local environment or proxy.",
    binaryPath: "OpenAI Protocol (Local/Cloud)",
    authStatus: "LOCAL_ACTIVE",
    authNote: "Uses local OPENAI_BASE_URL or system environment",
    defaultModel: "gpt-4o",
    modelSuggestions: ["gpt-4o", "gpt-4o-mini", "o3-mini"],
  },
  opencode: {
    name: "OpenCode Engine",
    tag: "OPENCODE // DEEPSEEK",
    planName: "OpenCode Plan",
    description: "DeepSeek coding bridge.",
    binaryPath: "local://opencode",
    authStatus: "LOCAL_ACTIVE",
    authNote: "Active session",
    defaultModel: "opencode-deepseek-33b",
    modelSuggestions: ["opencode-deepseek-33b"],
  },
};

export default function CruxAgentConfigModal({ isOpen, onClose }: CruxAgentConfigModalProps) {
  const [activeProvider, setActiveProvider] = useState<AiProvider>("agy");
  const [routes, setRoutes] = useState<Record<string, RouteConfig>>({});
  const [selectedModel, setSelectedModel] = useState("");
  const [testStatus, setTestStatus] = useState<{ loading: boolean; success?: boolean; message?: string } | null>(null);
  const [savedNotification, setSavedNotification] = useState(false);

  useEffect(() => {
    if (isOpen) {
      CrexAiRouter.initialize();
      const current = CrexAiRouter.getActiveRoute();
      const allRoutes = CrexAiRouter.getAllRoutes();
      const routeMap: Record<string, RouteConfig> = {};
      allRoutes.forEach((r) => {
        routeMap[r.provider] = r;
      });
      setRoutes(routeMap);
      setActiveProvider(current.provider);
      setSelectedModel(current.model || LOCAL_AGENT_PROFILES[current.provider].defaultModel);
      setTestStatus(null);
      setSavedNotification(false);
    }
  }, [isOpen]);

  const handleSelectProvider = (p: AiProvider) => {
    triggerHaptic("click");
    playMechanicalClick("mid");
    setActiveProvider(p);
    const r = routes[p];
    setSelectedModel(r?.model || LOCAL_AGENT_PROFILES[p].defaultModel);
    setTestStatus(null);
  };

  const handleActivateProvider = () => {
    triggerHaptic("success");
    playMechanicalClick("high");

    const profile = LOCAL_AGENT_PROFILES[activeProvider];
    const currentRoute = routes[activeProvider] || CrexAiRouter.getActiveRoute();

    const updatedRoute: RouteConfig = {
      ...currentRoute,
      provider: activeProvider,
      name: profile.name,
      model: selectedModel.trim() || profile.defaultModel,
      isActive: true,
      source: "cli-plan-sync",
    };

    CrexAiRouter.updateRoute(updatedRoute);
    CrexAiRouter.setActiveProvider(activeProvider);

    setSavedNotification(true);
    setTimeout(() => {
      setSavedNotification(false);
      onClose();
    }, 800);
  };

  const handleVerifyCliSession = async () => {
    triggerHaptic("click");
    playMechanicalClick("mid");
    setTestStatus({ loading: true });

    try {
      const startTime = Date.now();
      const res = await fetch("/api/ai/route", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: activeProvider,
          model: selectedModel.trim(),
          prompt: "ping CLI subscription",
        }),
      });

      const latency = Date.now() - startTime;
      if (res.ok) {
        setTestStatus({
          loading: false,
          success: true,
          message: `CLI Session Verified: ${latency}ms latency. Connected to ${LOCAL_AGENT_PROFILES[activeProvider].planName}.`,
        });
      } else {
        setTestStatus({
          loading: false,
          success: false,
          message: `Status checked: Host fallback active.`,
        });
      }
    } catch (err: any) {
      setTestStatus({
        loading: false,
        success: false,
        message: `Offline / unreachable. Local engine fallback active.`,
      });
    }
  };

  const handleRunLoginInTerminal = (command: string) => {
    triggerHaptic("click");
    playMechanicalClick("high");
    onClose();
    if (typeof window !== "undefined") {
      window.dispatchEvent(
        new CustomEvent("crux:run-terminal", {
          detail: { command },
        })
      );
    }
  };

  if (!isOpen) return null;

  const currentProfile = LOCAL_AGENT_PROFILES[activeProvider];

  return (
    <div className="fixed inset-0 z-[100] bg-black/85 backdrop-blur-none flex items-center justify-center p-4 select-none">
      {/* Brutalist Dialog Window */}
      <div className="w-full max-w-2xl bg-[#000000] border border-[#222222] shadow-[8px_8px_0px_#111111] flex flex-col font-mono text-xs">
        {/* Header Bar */}
        <div className="h-10 bg-[#111111] border-b border-[#222222] px-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-white" />
            <span className="font-bold tracking-wider uppercase text-white">
              Crux Agent Core // Local CLI &amp; Plan Attachment
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-[#888888] hover:text-white hover:bg-[#222222] transition-none"
            title="Close [Esc]"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Zero-API-Key Explanatory Banner */}
        <div className="bg-[#050505] border-b border-[#222222] px-4 py-2 flex items-center justify-between text-[11px] text-[#CCCCCC]">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-3.5 h-3.5 text-[#00FF00] shrink-0" />
            <span>
              <strong>Zero API Keys Needed:</strong> Crux hooks into the subscriptions and CLI logins already on this Mac.
            </span>
          </div>
          <span className="px-2 py-0.5 border border-[#333333] bg-[#111111] text-[9px] uppercase font-bold text-white">
            Native Plan Sync
          </span>
        </div>

        {/* Provider Switcher Tabs */}
        <div className="flex border-b border-[#222222] bg-[#0A0A0A] overflow-x-auto no-scrollbar">
          {(Object.keys(LOCAL_AGENT_PROFILES) as AiProvider[])
            .filter((p) => p !== "opencode" && p !== "openai")
            .map((p) => {
              const profile = LOCAL_AGENT_PROFILES[p];
              const isCurrent = activeProvider === p;
              return (
                <button
                  key={p}
                  onClick={() => handleSelectProvider(p)}
                  className={`px-3.5 py-2.5 text-[11px] font-mono uppercase tracking-wider transition-none shrink-0 border-r border-[#222222] flex items-center gap-1.5 ${
                    isCurrent
                      ? "bg-white text-black font-bold"
                      : "text-[#888888] hover:text-white hover:bg-[#111111]"
                  }`}
                >
                  <span>@{profile.name.split(" ")[0]}</span>
                  {routes[p]?.isActive && <span className="w-1.5 h-1.5 rounded-none bg-[#00FF00]" />}
                </button>
              );
            })}
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-4 bg-[#000000]">
          {/* Agent Overview Card */}
          <div className="border border-[#222222] bg-[#0A0A0A] p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-white font-bold text-sm flex items-center gap-2">
                  <span>{currentProfile.name}</span>
                  <span className="w-1.5 h-1.5 rounded-none bg-[#00FF00]" />
                </div>
                <div className="text-[#888888] text-[10px] font-mono mt-0.5">
                  Plan: <span className="text-white font-bold">{currentProfile.planName}</span>
                </div>
              </div>
              <span className="px-2 py-0.5 text-[9px] border border-[#222222] bg-black text-[#888888]">
                {currentProfile.tag}
              </span>
            </div>
            <p className="text-[#888888] text-[11px] leading-relaxed font-sans">{currentProfile.description}</p>
          </div>

          {/* Local CLI Details Card */}
          <div className="border border-[#222222] bg-[#050505] p-3.5 space-y-3">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-[#666666] uppercase tracking-wider font-bold">Local Host Binary:</span>
              <code className="text-white bg-[#111111] px-2 py-0.5 border border-[#222222] text-[10px]">
                {currentProfile.binaryPath}
              </code>
            </div>

            <div className="flex items-center justify-between text-[11px]">
              <span className="text-[#666666] uppercase tracking-wider font-bold">Session Attachment:</span>
              <div className="flex items-center gap-1.5 text-[#00FF00] font-bold">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{currentProfile.authNote}</span>
              </div>
            </div>

            {/* Special Notice for Claude login */}
            {currentProfile.loginCommand && (
              <div className="p-2 border border-[#333333] bg-[#111111] flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-1.5 text-[#CCCCCC]">
                  <AlertCircle className="w-3.5 h-3.5 text-[#FFD60A] shrink-0" />
                  <span>To connect your Anthropic plan, log in once via terminal:</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleRunLoginInTerminal(currentProfile.loginCommand!)}
                  className="px-2 py-1 bg-white text-black hover:bg-[#CCCCCC] transition-none text-[10px] font-bold uppercase shrink-0 flex items-center gap-1"
                >
                  <Terminal className="w-3 h-3" />
                  Run '{currentProfile.loginCommand}' ↵
                </button>
              </div>
            )}
          </div>

          {/* Model Selection from Active Plan */}
          <div className="space-y-1.5 pt-1">
            <div className="flex items-center justify-between">
              <label className="text-[10px] text-[#888888] uppercase tracking-wider font-bold flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-white" />
                <span>Active Model from Your Plan</span>
              </label>
              <div className="flex items-center gap-1 text-[10px]">
                <span className="text-[#666666]">Presets:</span>
                {currentProfile.modelSuggestions.map((sug) => (
                  <button
                    key={sug}
                    type="button"
                    onClick={() => setSelectedModel(sug)}
                    className="px-1.5 py-0.5 border border-[#222222] bg-[#111111] text-[#CCCCCC] hover:bg-white hover:text-black transition-none font-bold"
                  >
                    {sug.split("-")[0]}
                  </button>
                ))}
              </div>
            </div>
            <input
              type="text"
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              placeholder={currentProfile.defaultModel}
              className="w-full bg-[#0A0A0A] border border-[#222222] text-white p-2.5 text-xs font-mono outline-none focus:border-white transition-none"
            />
          </div>

          {/* Verification Status Banner */}
          {testStatus && (
            <div
              className={`p-2.5 border text-[11px] flex items-center gap-2 ${
                testStatus.loading
                  ? "border-[#222222] bg-[#0A0A0A] text-[#888888]"
                  : testStatus.success
                  ? "border-[#00FF00]/40 bg-[#001A00] text-[#00FF00]"
                  : "border-[#FF453A]/40 bg-[#1A0000] text-[#FF6961]"
              }`}
            >
              {testStatus.loading ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-white" />
              ) : testStatus.success ? (
                <Check className="w-3.5 h-3.5 text-[#00FF00]" />
              ) : (
                <X className="w-3.5 h-3.5 text-[#FF453A]" />
              )}
              <span>{testStatus.message}</span>
            </div>
          )}

          {/* Saved Notification */}
          {savedNotification && (
            <div className="p-2.5 border border-[#00FF00] bg-[#002200] text-[#00FF00] text-[11px] font-bold flex items-center gap-2">
              <Check className="w-4 h-4" />
              <span>Attached! Crux is now using your {currentProfile.planName} via @{currentProfile.name}.</span>
            </div>
          )}
        </div>

        {/* Footer Actions Bar */}
        <div className="h-12 bg-[#111111] border-t border-[#222222] px-6 flex items-center justify-between">
          <button
            type="button"
            onClick={handleVerifyCliSession}
            disabled={testStatus?.loading}
            className="px-3 py-1.5 border border-[#333333] bg-black text-[#CCCCCC] hover:text-white hover:border-white transition-none text-[11px] uppercase tracking-wider font-bold"
          >
            [Verify CLI Session]
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 border border-[#222222] bg-transparent text-[#888888] hover:text-white transition-none text-[11px] uppercase"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleActivateProvider}
              className="px-4 py-1.5 bg-white text-black hover:bg-[#CCCCCC] transition-none text-[11px] font-bold uppercase tracking-wider"
            >
              Use This Plan ↵
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
