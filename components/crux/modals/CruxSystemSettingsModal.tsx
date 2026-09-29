"use client";

import React, { useState, useMemo } from "react";
import { useWorkspaceStore } from "@/lib/store";
import {
  X,
  Settings,
  User,
  CreditCard,
  Key,
  Layers,
  Shield,
  Users,
  FileText,
  History,
  Bell,
  Activity,
  HelpCircle,
  Search,
  Check,
  Copy,
  Plus,
  Trash2,
  ExternalLink,
  RefreshCw,
  Download,
  AlertTriangle,
  Lock,
  Cpu,
} from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";

export default function CruxSystemSettingsModal() {
  const isOpen = useWorkspaceStore((state) => state.isSettingsModalOpen);
  const setIsOpen = useWorkspaceStore((state) => state.setSettingsModalOpen);
  const activeTab = useWorkspaceStore((state) => state.activeSettingsTab) || "settings";
  const setActiveTab = useWorkspaceStore((state) => state.setActiveSettingsTab);
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const projectName = useWorkspaceStore((state) => state.projectName);

  const [searchFilter, setSearchFilter] = useState("");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // 1. Settings state
  const [fontSize, setFontSize] = useState("13");
  const [tabSize, setTabSize] = useState("2");
  const [lineNumbers, setLineNumbers] = useState(true);
  const [wordWrap, setWordWrap] = useState(true);
  const [minimap, setMinimap] = useState(false);
  const [vimMode, setVimMode] = useState(false);
  const [editorTheme, setEditorTheme] = useState("monochrome");
  const [envVars, setEnvVars] = useState<Array<{ id: string; key: string; value: string }>>([
    { id: "1", key: "CRUX_DAEMON_SOCKET", value: "/tmp/crux.sock" },
    { id: "2", key: "CRUX_GPU_BACKEND", value: "metal-raw" },
    { id: "3", key: "LLM_INFERENCE_URL", value: "http://127.0.0.1:11434" },
  ]);
  const [newEnvKey, setNewEnvKey] = useState("");
  const [newEnvVal, setNewEnvVal] = useState("");

  // 4. API Keys state
  const [apiKeys, setApiKeys] = useState<
    Array<{
      id: string;
      name: string;
      token: string;
      scope: string;
      created: string;
      lastUsed: string;
      status: "active" | "revoked";
    }>
  >([
    {
      id: "k-1",
      name: "Crux Local Daemon Bus",
      token: "crx_live_sec_892a01ef942d",
      scope: "Full Kernel & Socket Access",
      created: "2026-09-12",
      lastUsed: "Just now",
      status: "active",
    },
    {
      id: "k-2",
      name: "Subagent Runner Pool",
      token: "crx_live_agt_447b99c83a10",
      scope: "AI Agent Execution & CRDT Sync",
      created: "2026-09-20",
      lastUsed: "14m ago",
      status: "active",
    },
    {
      id: "k-3",
      name: "CI/CD Headless Compiler",
      token: "crx_live_ci_110a72fe559c",
      scope: "Read Only // Workspace Diff",
      created: "2026-08-30",
      lastUsed: "3d ago",
      status: "active",
    },
  ]);
  const [newTokenName, setNewTokenName] = useState("");
  const [newTokenScope, setNewTokenScope] = useState("Agent Dispatch + CRDT Write");
  const [justGeneratedToken, setJustGeneratedToken] = useState<string | null>(null);

  // 7. User Management state
  const [teamMembers, setTeamMembers] = useState<
    Array<{ id: string; name: string; email: string; role: string; mfa: boolean; lastActive: string }>
  >([
    {
      id: "u-1",
      name: currentUser.name || "Principal Architect",
      email: currentUser.email || "principal@crux.dev",
      role: "Workspace Owner",
      mfa: true,
      lastActive: "Active Now",
    },
    {
      id: "u-2",
      name: "Alex Vance",
      email: "alex.v@crux.dev",
      role: "Admin",
      mfa: true,
      lastActive: "18m ago",
    },
    {
      id: "u-3",
      name: "Elena Rostova",
      email: "elena@crux.dev",
      role: "Engineer",
      mfa: true,
      lastActive: "2h ago",
    },
    {
      id: "u-4",
      name: "Devon Chen",
      email: "d.chen@crux.dev",
      role: "Engineer",
      mfa: false,
      lastActive: "1d ago",
    },
    {
      id: "u-5",
      name: "Security Auditor Bot",
      email: "audit@internal.corp",
      role: "Read Only",
      mfa: true,
      lastActive: "5m ago",
    },
  ]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("Engineer");

  // 10. Notification channels state
  const [notifMatrix, setNotifMatrix] = useState({
    agentComplete: { desktop: true, toast: true, email: false },
    securityAlert: { desktop: true, toast: true, email: true },
    peerSync: { desktop: false, toast: true, email: false },
    buildFail: { desktop: true, toast: true, email: false },
  });

  const [copiedDiag, setCopiedDiag] = useState(false);

  const tabs = useMemo(
    () => [
      { id: "settings", label: "Settings", category: "Core", icon: Settings, desc: "IDE preferences, theme & env vars" },
      { id: "account", label: "Account", category: "Identity", icon: User, desc: "User profile & license keys" },
      { id: "billing", label: "Billing", category: "Organization", icon: CreditCard, desc: "Tier, invoices & payment info" },
      { id: "apikeys", label: "API Keys", category: "Security", icon: Key, desc: "Token generation & scopes" },
      { id: "integrations", label: "Integrations", category: "Ecosystem", icon: Layers, desc: "Connectors, LLMs & daemons" },
      { id: "admin", label: "Admin Panel", category: "Organization", icon: Shield, desc: "Workspace policies & SSO" },
      { id: "users", label: "User Management", category: "Organization", icon: Users, desc: "Seats, roles & invitations" },
      { id: "audit", label: "Audit Log", category: "Security", icon: FileText, desc: "Immutable security & access stream" },
      { id: "history", label: "Version History", category: "Engine", icon: History, desc: "Time-travel checkpoints & rollbacks" },
      { id: "notifications", label: "Notifications", category: "System", icon: Bell, desc: "Alert feeds & delivery matrix" },
      { id: "analytics", label: "Analytics", category: "Telemetry", icon: Activity, desc: "WebGPU engine & runtime gauges" },
      { id: "help", label: "Help & Maintenance", category: "System", icon: HelpCircle, desc: "Diagnostics, docs & uptime" },
    ],
    []
  );

  const filteredTabs = useMemo(() => {
    if (!searchFilter.trim()) return tabs;
    const q = searchFilter.toLowerCase();
    return tabs.filter(
      (t) => t.label.toLowerCase().includes(q) || t.desc.toLowerCase().includes(q) || t.category.toLowerCase().includes(q)
    );
  }, [tabs, searchFilter]);

  if (!isOpen) return null;

  const handleCopyText = (val: string, id: string) => {
    if (typeof window !== "undefined") {
      navigator.clipboard?.writeText(val);
      setCopiedKey(id);
      triggerHaptic("tap");
      setTimeout(() => setCopiedKey(null), 1500);
    }
  };

  const handleAddEnvVar = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEnvKey.trim()) return;
    setEnvVars((prev) => [...prev, { id: String(Date.now()), key: newEnvKey.toUpperCase().trim(), value: newEnvVal.trim() }]);
    setNewEnvKey("");
    setNewEnvVal("");
    triggerHaptic("tap");
  };

  const handleDeleteEnvVar = (id: string) => {
    setEnvVars((prev) => prev.filter((item) => item.id !== id));
    triggerHaptic("tap");
  };

  const handleGenerateToken = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTokenName.trim()) return;
    const raw = `crx_live_${Math.random().toString(36).substring(2, 10)}${Math.random().toString(36).substring(2, 10)}`;
    const newEntry = {
      id: `k-${Date.now()}`,
      name: newTokenName.trim(),
      token: raw,
      scope: newTokenScope,
      created: "2026-09-28",
      lastUsed: "Never",
      status: "active" as const,
    };
    setApiKeys((prev) => [newEntry, ...prev]);
    setJustGeneratedToken(raw);
    setNewTokenName("");
    triggerHaptic("tap");
  };

  const handleRevokeToken = (id: string) => {
    setApiKeys((prev) =>
      prev.map((k) => (k.id === id ? { ...k, status: "revoked" as const } : k))
    );
    triggerHaptic("toggle");
  };

  const handleInviteUser = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail.trim()) return;
    setTeamMembers((prev) => [
      ...prev,
      {
        id: `u-${Date.now()}`,
        name: inviteEmail.split("@")[0],
        email: inviteEmail.trim(),
        role: inviteRole,
        mfa: false,
        lastActive: "Pending Invite",
      },
    ]);
    setInviteEmail("");
    triggerHaptic("tap");
  };

  const handleCopyDiagnostics = () => {
    const diag = JSON.stringify(
      {
        client: "Crux Desktop Kernel v2.4.0",
        workspace: projectName,
        gpuBackend: "WebGPU / Metal Raw",
        targetArch: "arm64-apple-darwin",
        activeThreads: 8,
        activeSession: "CRX-LOCAL-NODE-01",
        timestamp: new Date().toISOString(),
      },
      null,
      2
    );
    navigator.clipboard?.writeText(diag);
    setCopiedDiag(true);
    triggerHaptic("tap");
    setTimeout(() => setCopiedDiag(false), 1500);
  };

  return (
    <div className="fixed inset-0 z-[120] bg-[#000000]/85 flex items-center justify-center p-2 sm:p-6 select-none font-sans">
      <div className="w-full max-w-6xl h-[90vh] bg-[#000000] border border-[#222222] flex flex-col overflow-hidden">
        {/* Top Control Bar */}
        <div className="h-10 bg-[#111111] border-b border-[#222222] px-4 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs font-bold tracking-tight text-white uppercase">
              Crux // System Configuration & Workspace Hub
            </span>
            <span className="text-[10px] font-mono text-[#444444] hidden md:inline">
              [KERNEL_BUILD: 2026.09.28-RELEASE]
            </span>
          </div>
          <button
            onClick={() => {
              triggerHaptic("click");
              setIsOpen(false);
            }}
            className="text-[#888888] hover:text-white p-1 transition-none"
            title="Close Settings (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Main Workspace Grid (Flush 1px Borders) */}
        <div className="flex-1 flex overflow-hidden">
          {/* Navigation Sidebar */}
          <div className="w-64 border-r border-[#222222] bg-[#000000] flex flex-col shrink-0">
            {/* Search Input */}
            <div className="p-2 border-b border-[#222222]">
              <div className="flex items-center gap-2 px-2 py-1 bg-[#111111] border border-[#222222] focus-within:border-white">
                <Search className="w-3.5 h-3.5 text-[#444444]" />
                <input
                  type="text"
                  placeholder="FILTER MODULES..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="w-full bg-transparent text-[11px] font-mono text-white placeholder-[#444444] outline-none"
                />
              </div>
            </div>

            {/* Tab Links */}
            <div className="flex-1 overflow-y-auto p-1 space-y-0.5">
              {filteredTabs.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => {
                      triggerHaptic("tap");
                      setActiveTab(tab.id);
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 text-left transition-none text-xs font-mono border ${
                      isActive
                        ? "bg-white text-black border-white font-bold"
                        : "bg-transparent text-white border-transparent hover:border-[#222222] hover:bg-[#111111]"
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5 shrink-0" />
                    <div className="truncate flex-1">
                      <div className="truncate uppercase">{tab.label}</div>
                      <div className={`text-[9.5px] truncate font-sans ${isActive ? "text-black/70" : "text-[#444444]"}`}>
                        {tab.category}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Bottom Status Tag */}
            <div className="p-2.5 border-t border-[#222222] bg-[#111111] font-mono text-[10px] text-[#444444] flex items-center justify-between">
              <span>ACTIVE NODE:</span>
              <span className="text-white font-bold">CRX-LOCAL</span>
            </div>
          </div>

          {/* Module Content Pane */}
          <div className="flex-1 bg-[#000000] overflow-y-auto p-6 text-white font-sans">
            {/* 1. SETTINGS TAB */}
            {activeTab === "settings" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Core Settings // IDE Preferences
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Configure typography, editor behaviors, rendering keybindings, and environment runtime variables.
                  </p>
                </div>

                {/* Editor Engine Preferences */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-4">
                  <span className="text-[11px] font-mono text-[#888888] uppercase block tracking-wider">
                    [EDITOR KERNEL PREFERENCES]
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                    <div className="space-y-1">
                      <label className="text-[#888888] block text-[11px]">FONT SIZE (PX)</label>
                      <input
                        type="number"
                        value={fontSize}
                        onChange={(e) => setFontSize(e.target.value)}
                        className="w-full bg-[#000000] border border-[#222222] focus:border-white px-2.5 py-1 text-white text-xs outline-none"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[#888888] block text-[11px]">TAB SIZE (SPACES)</label>
                      <select
                        value={tabSize}
                        onChange={(e) => setTabSize(e.target.value)}
                        className="w-full bg-[#000000] border border-[#222222] focus:border-white px-2.5 py-1 text-white text-xs outline-none"
                      >
                        <option value="2">2 SPACES</option>
                        <option value="4">4 SPACES</option>
                        <option value="8">8 SPACES</option>
                      </select>
                    </div>
                    <div className="space-y-1">
                      <label className="text-[#888888] block text-[11px]">THEME PRESET</label>
                      <select
                        value={editorTheme}
                        onChange={(e) => setEditorTheme(e.target.value)}
                        className="w-full bg-[#000000] border border-[#222222] focus:border-white px-2.5 py-1 text-white text-xs outline-none"
                      >
                        <option value="monochrome">HARDWARE BRUTALIST (STRICT #000)</option>
                        <option value="silicon">SILICON MATRIX (#111)</option>
                        <option value="raw">RAW SILK INVERSION</option>
                      </select>
                    </div>
                    <div className="space-y-1">
                      <label className="text-[#888888] block text-[11px]">KEYMAP EMULATION</label>
                      <button
                        onClick={() => {
                          setVimMode(!vimMode);
                          triggerHaptic("toggle");
                        }}
                        className={`w-full py-1 text-xs border text-left px-2.5 transition-none ${
                          vimMode ? "bg-white text-black border-white font-bold" : "bg-[#000000] border-[#222222] text-[#888888]"
                        }`}
                      >
                        {vimMode ? "MODAL VIM EMULATION: ACTIVE" : "STANDARD CRUX HYPERKEYMAP"}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-4 pt-2 border-t border-[#222222] text-xs font-mono">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={lineNumbers}
                        onChange={(e) => setLineNumbers(e.target.checked)}
                        className="accent-white"
                      />
                      <span>LINE NUMBERS</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={wordWrap}
                        onChange={(e) => setWordWrap(e.target.checked)}
                        className="accent-white"
                      />
                      <span>WORD WRAP</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={minimap}
                        onChange={(e) => setMinimap(e.target.checked)}
                        className="accent-white"
                      />
                      <span>MINIMAP OVERLAY</span>
                    </label>
                  </div>
                </div>

                {/* Environment Variables */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-mono text-[#888888] uppercase tracking-wider">
                      [WORKSPACE ENVIRONMENT VARIABLES]
                    </span>
                    <span className="text-[10px] font-mono text-[#444444]">{envVars.length} CONFIGURED</span>
                  </div>

                  <div className="space-y-1.5 font-mono text-xs">
                    {envVars.map((env) => (
                      <div
                        key={env.id}
                        className="flex items-center justify-between p-2 bg-[#000000] border border-[#222222]"
                      >
                        <span className="text-white font-bold tracking-tight">{env.key}</span>
                        <div className="flex items-center gap-3">
                          <span className="text-[#888888] font-mono text-[11px] truncate max-w-[200px]">{env.value}</span>
                          <button
                            onClick={() => handleDeleteEnvVar(env.id)}
                            className="text-[#666666] hover:text-white transition-none p-1"
                            title="Delete Variable"
                          >
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Add Env Var Input */}
                  <form onSubmit={handleAddEnvVar} className="flex gap-2 pt-2">
                    <input
                      type="text"
                      placeholder="KEY (E.G. API_ENDPOINT)"
                      value={newEnvKey}
                      onChange={(e) => setNewEnvKey(e.target.value)}
                      className="flex-1 bg-[#000000] border border-[#222222] focus:border-white px-2 py-1 text-xs font-mono text-white placeholder-[#444444] outline-none"
                    />
                    <input
                      type="text"
                      placeholder="VALUE"
                      value={newEnvVal}
                      onChange={(e) => setNewEnvVal(e.target.value)}
                      className="flex-1 bg-[#000000] border border-[#222222] focus:border-white px-2 py-1 text-xs font-mono text-white placeholder-[#444444] outline-none"
                    />
                    <button
                      type="submit"
                      className="px-3 py-1 bg-white text-black text-xs font-mono font-bold hover:bg-[#cccccc] transition-none flex items-center gap-1"
                    >
                      <Plus className="w-3 h-3" /> ADD
                    </button>
                  </form>
                </div>

                {/* Danger Zone */}
                <div className="border border-[#222222] p-4 bg-[#000000] space-y-3">
                  <div className="flex items-center gap-2 text-white">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span className="text-xs font-mono font-bold uppercase tracking-wider">Danger Zone</span>
                  </div>
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono border-t border-[#222222] pt-3">
                    <div>
                      <div className="text-white">PURGE LOCAL CRDT CACHE & DISK BUFFER</div>
                      <div className="text-[10px] text-[#666666]">Clears indexedDB documents and forces clean sync.</div>
                    </div>
                    <button
                      onClick={() => {
                        triggerHaptic("toggle");
                        alert("Cache buffer flushed.");
                      }}
                      className="px-3 py-1.5 border border-[#444444] hover:bg-white hover:text-black transition-none text-[11px] font-mono uppercase"
                    >
                      Purge Cache
                    </button>
                  </div>
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono border-t border-[#222222] pt-3">
                    <div>
                      <div className="text-white font-bold uppercase">RESET ONBOARDING &amp; AI CHAT ENCLAVE</div>
                      <div className="text-[10px] text-[#888888]">
                        Purges onboarding state, resets AI chat history, and returns to the hardware calibration wizard.
                      </div>
                    </div>
                    <button
                      onClick={() => {
                        triggerHaptic("toggle");
                        if (typeof window !== "undefined") {
                          localStorage.removeItem("crux_onboarded");
                          localStorage.removeItem("crux_user_profile");
                          window.dispatchEvent(new CustomEvent("crux:reset-ai-chat"));
                        }
                        useWorkspaceStore.getState().setOnboarded(false);
                        setIsOpen(false);
                      }}
                      className="px-3 py-1.5 border border-[#444444] hover:bg-white hover:text-black transition-none text-[11px] font-mono uppercase font-bold text-white cursor-pointer"
                    >
                      Reset Enclave
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* 2. ACCOUNT TAB */}
            {activeTab === "account" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Account // Developer Profile & Node Key
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Manage individual credentials, device activation limits, and cryptographic node signatures.
                  </p>
                </div>

                <div className="border border-[#222222] p-4 bg-[#111111] space-y-4 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [DEVELOPER CREDENTIALS]
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="p-3 bg-[#000000] border border-[#222222]">
                      <div className="text-[10px] text-[#666666] uppercase">IDENTITY</div>
                      <div className="text-sm font-bold text-white mt-1">{currentUser.name || "Principal Architect"}</div>
                    </div>
                    <div className="p-3 bg-[#000000] border border-[#222222]">
                      <div className="text-[10px] text-[#666666] uppercase">EMAIL</div>
                      <div className="text-sm font-bold text-white mt-1">{currentUser.email || "principal@crux.dev"}</div>
                    </div>
                  </div>

                  <div className="p-3 bg-[#000000] border border-[#222222] flex items-center justify-between">
                    <div>
                      <div className="text-[10px] text-[#666666] uppercase">NODE CRYPTO KEY</div>
                      <div className="text-xs font-bold text-white mt-0.5">{currentUser.uid || "CRX-7447-HG"}</div>
                    </div>
                    <button
                      onClick={() => handleCopyText(currentUser.uid || "CRX-7447-HG", "uid")}
                      className="px-2.5 py-1 border border-[#222222] hover:bg-white hover:text-black transition-none text-[10px] flex items-center gap-1.5"
                    >
                      {copiedKey === "uid" ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === "uid" ? "COPIED" : "COPY KEY"}</span>
                    </button>
                  </div>
                </div>

                {/* License Section */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [ENTERPRISE LICENSE ALLOCATION]
                  </span>
                  <div className="p-3 bg-[#000000] border border-[#222222] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-white font-bold">LICENSE: CRX-ENT-2026-9942</span>
                      <span className="px-2 py-0.5 border border-white text-[10px] text-white font-bold">VERIFIED</span>
                    </div>
                    <div className="text-[11px] text-[#888888]">
                      Tier: Crux Sovereign Enterprise · 10 Active Seats · Hardware Accelerated Mesh
                    </div>
                    <div className="text-[10px] text-[#666666]">
                      Valid until: September 30, 2027 (Renews automatically)
                    </div>
                  </div>
                </div>

                {/* Linked Accounts */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [LINKED PROVIDERS]
                  </span>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between p-2.5 bg-[#000000] border border-[#222222]">
                      <span>GitHub Enterprise (@crux-principal)</span>
                      <span className="text-[10px] border border-[#444444] px-2 py-0.5 text-white">CONNECTED</span>
                    </div>
                    <div className="flex items-center justify-between p-2.5 bg-[#000000] border border-[#222222]">
                      <span>GitLab Self-Hosted</span>
                      <button className="text-[10px] border border-[#222222] hover:bg-white hover:text-black transition-none px-2 py-0.5">
                        CONNECT
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* 3. BILLING TAB */}
            {activeTab === "billing" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Billing // Subscription & Invoices
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Payment methods, tier limits, seat consumption, and downloadable VAT tax receipts.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-3 bg-[#111111] border border-[#222222]">
                    <div className="text-[10px] text-[#666666] uppercase">CURRENT PLAN</div>
                    <div className="text-sm font-bold text-white mt-1">SOVEREIGN PRO</div>
                    <div className="text-[10px] text-[#888888] mt-0.5">$49 / seat / mo</div>
                  </div>
                  <div className="p-3 bg-[#111111] border border-[#222222]">
                    <div className="text-[10px] text-[#666666] uppercase">NEXT INVOICE</div>
                    <div className="text-sm font-bold text-white mt-1">$245.00 USD</div>
                    <div className="text-[10px] text-[#888888] mt-0.5">November 1, 2026</div>
                  </div>
                  <div className="p-3 bg-[#111111] border border-[#222222]">
                    <div className="text-[10px] text-[#666666] uppercase">PAYMENT METHOD</div>
                    <div className="text-sm font-bold text-white mt-1">MASTERCARD ···· 8821</div>
                    <div className="text-[10px] text-[#888888] mt-0.5">Expires 12/28</div>
                  </div>
                </div>

                {/* Invoices List */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-[#888888] uppercase tracking-wider">
                      [INVOICE HISTORY // PDF RECEIPTS]
                    </span>
                    <button className="text-[10px] border border-[#222222] hover:bg-white hover:text-black transition-none px-2 py-0.5">
                      UPDATE PAYMENT METHOD
                    </button>
                  </div>
                  <div className="space-y-1.5">
                    {[
                      { id: "CRX-INV-2026-09", date: "Sep 01, 2026", amount: "$245.00", status: "PAID" },
                      { id: "CRX-INV-2026-08", date: "Aug 01, 2026", amount: "$245.00", status: "PAID" },
                      { id: "CRX-INV-2026-07", date: "Jul 01, 2026", amount: "$196.00", status: "PAID" },
                    ].map((inv) => (
                      <div
                        key={inv.id}
                        className="flex items-center justify-between p-2 bg-[#000000] border border-[#222222]"
                      >
                        <div className="flex items-center gap-3">
                          <span className="text-white font-bold">{inv.id}</span>
                          <span className="text-[#666666] text-[11px]">{inv.date}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-white">{inv.amount}</span>
                          <span className="text-[10px] border border-[#333333] px-1.5 py-0.5">{inv.status}</span>
                          <button
                            onClick={() => alert(`Downloading invoice ${inv.id}`)}
                            className="p-1 hover:text-white text-[#888888]"
                            title="Download PDF"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* 4. API KEYS TAB */}
            {activeTab === "apikeys" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    API Keys // Token Generation & Scopes
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Generate scoped developer tokens for local agent runtimes, CI pipelines, and external integrations.
                  </p>
                </div>

                {/* Just generated warning */}
                {justGeneratedToken && (
                  <div className="p-3 bg-[#111111] border border-white space-y-1 font-mono text-xs">
                    <div className="flex items-center justify-between text-white font-bold">
                      <span>[NEW TOKEN GENERATED — SAVE NOW]</span>
                      <button
                        onClick={() => setJustGeneratedToken(null)}
                        className="text-[10px] text-[#888888] hover:text-white"
                      >
                        DISMISS
                      </button>
                    </div>
                    <div className="text-[11px] text-[#aaaaaa]">
                      This secret will not be displayed again. Copy it into your environment or keychain now.
                    </div>
                    <div className="flex items-center justify-between bg-[#000000] border border-[#333333] p-2 mt-2">
                      <code className="text-white text-xs">{justGeneratedToken}</code>
                      <button
                        onClick={() => handleCopyText(justGeneratedToken, "justGenerated")}
                        className="px-2 py-0.5 bg-white text-black text-[10px] font-bold hover:bg-[#cccccc] transition-none"
                      >
                        {copiedKey === "justGenerated" ? "COPIED" : "COPY TOKEN"}
                      </button>
                    </div>
                  </div>
                )}

                {/* Generate New Key Form */}
                <form onSubmit={handleGenerateToken} className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [GENERATE SCOPED ACCESS TOKEN]
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <input
                      type="text"
                      placeholder="TOKEN NAME (E.G. LOCAL_LLM_GATEWAY)"
                      value={newTokenName}
                      onChange={(e) => setNewTokenName(e.target.value)}
                      className="sm:col-span-2 bg-[#000000] border border-[#222222] focus:border-white px-3 py-1.5 text-xs text-white placeholder-[#444444] outline-none"
                    />
                    <select
                      value={newTokenScope}
                      onChange={(e) => setNewTokenScope(e.target.value)}
                      className="bg-[#000000] border border-[#222222] focus:border-white px-2 py-1.5 text-xs text-white outline-none"
                    >
                      <option value="Agent Dispatch + CRDT Write">Agent Dispatch + CRDT Write</option>
                      <option value="Full Kernel & Socket Access">Full Kernel & Socket Access</option>
                      <option value="Read Only // Workspace Diff">Read Only // Workspace Diff</option>
                    </select>
                  </div>
                  <button
                    type="submit"
                    className="px-4 py-1.5 bg-white text-black text-xs font-bold hover:bg-[#cccccc] transition-none uppercase"
                  >
                    + Generate New Scoped Secret
                  </button>
                </form>

                {/* Tokens Table */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [ACTIVE ACCESS TOKENS ({apiKeys.length})]
                  </span>
                  <div className="space-y-2">
                    {apiKeys.map((k) => (
                      <div
                        key={k.id}
                        className={`p-3 bg-[#000000] border ${
                          k.status === "active" ? "border-[#222222]" : "border-[#333333] opacity-50"
                        } space-y-1.5`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white">{k.name}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] text-[#888888] border border-[#222222] px-1.5 py-0.5">
                              {k.scope}
                            </span>
                            {k.status === "active" ? (
                              <button
                                onClick={() => handleRevokeToken(k.id)}
                                className="text-[10px] border border-[#444444] hover:bg-white hover:text-black transition-none px-2 py-0.5 uppercase"
                              >
                                Revoke
                              </button>
                            ) : (
                              <span className="text-[10px] text-[#666666] uppercase">[REVOKED]</span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-[#666666] pt-1">
                          <code>{k.token.slice(0, 16)}••••••••</code>
                          <span>Last active: {k.lastUsed}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* 5. INTEGRATIONS TAB */}
            {activeTab === "integrations" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Integrations // Extensions, Models & Sockets
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Link local daemons, third-party LLM inference hubs, Git hosts, and telemetry hooks.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
                  {[
                    { name: "Ollama / vLLM Local Engine", type: "AI Model Gateway", status: "CONNECTED", desc: "http://localhost:11434" },
                    { name: "WebGPU Raw Pipeline", type: "Hardware Accelerator", status: "ACTIVE", desc: "Apple Metal Shading Language" },
                    { name: "GitHub Enterprise Connector", type: "Git Remote Hub", status: "CONNECTED", desc: "Syncs branches & pull requests" },
                    { name: "Docker Container Daemon", type: "Runtime Container", status: "DISCONNECTED", desc: "/var/run/docker.sock" },
                    { name: "Sentry Performance Sentry", type: "Telemetry Sentry", status: "CONFIGURED", desc: "Crash reporter & memory profiler" },
                    { name: "Slack Deployment Webhook", type: "Team Notification", status: "CONFIGURED", desc: "#crux-builds-prod" },
                  ].map((integ) => (
                    <div key={integ.name} className="p-3 bg-[#111111] border border-[#222222] space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-white font-bold">{integ.name}</span>
                        <span
                          className={`text-[9.5px] px-1.5 py-0.5 border ${
                            integ.status === "ACTIVE" || integ.status === "CONNECTED"
                              ? "border-white text-white font-bold"
                              : "border-[#444444] text-[#888888]"
                          }`}
                        >
                          {integ.status}
                        </span>
                      </div>
                      <div className="text-[11px] text-[#888888]">{integ.desc}</div>
                      <div className="flex items-center justify-between pt-1 border-t border-[#222222]">
                        <span className="text-[10px] text-[#555555]">{integ.type}</span>
                        <button className="text-[10px] border border-[#222222] hover:bg-white hover:text-black transition-none px-2 py-0.5">
                          CONFIG
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 6. ADMIN PANEL TAB */}
            {activeTab === "admin" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Admin Panel // Workspace Governance & Security
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Organization policies, Single Sign-On (SSO), data residency, and enterprise enforcement.
                  </p>
                </div>

                <div className="border border-[#222222] p-4 bg-[#111111] space-y-4 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [WORKSPACE METADATA]
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="text-[#666666] text-[10px]">WORKSPACE NAME</label>
                      <input
                        type="text"
                        defaultValue="Crux Studio Core"
                        className="w-full bg-[#000000] border border-[#222222] px-2.5 py-1 text-white text-xs outline-none"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[#666666] text-[10px]">ORGANIZATION DOMAIN</label>
                      <input
                        type="text"
                        defaultValue="crux.studio/core"
                        className="w-full bg-[#000000] border border-[#222222] px-2.5 py-1 text-white text-xs outline-none"
                      />
                    </div>
                  </div>
                </div>

                {/* SSO & Security Toggles */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [SECURITY & SSO POLICIES]
                  </span>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between p-2.5 bg-[#000000] border border-[#222222]">
                      <div>
                        <div className="text-white font-bold">ENFORCE HARDWARE 2FA FOR ALL MEMBERS</div>
                        <div className="text-[10px] text-[#666666]">Mandates FIDO2 / Authenticator passkeys.</div>
                      </div>
                      <input type="checkbox" defaultChecked className="accent-white" />
                    </div>
                    <div className="flex items-center justify-between p-2.5 bg-[#000000] border border-[#222222]">
                      <div>
                        <div className="text-white font-bold">SAML 2.0 / OKTA SSO GATEWAY</div>
                        <div className="text-[10px] text-[#666666]">Route authentication through corporate IdP.</div>
                      </div>
                      <button className="text-[10px] border border-[#222222] hover:bg-white hover:text-black transition-none px-2 py-0.5">
                        CONFIGURE SSO
                      </button>
                    </div>
                    <div className="flex items-center justify-between p-2.5 bg-[#000000] border border-[#222222]">
                      <div>
                        <div className="text-white font-bold">PEER REVIEW REVERT RESTRICTION</div>
                        <div className="text-[10px] text-[#666666]">Require 2 engineer signatures to execute time-travel rollback.</div>
                      </div>
                      <input type="checkbox" defaultChecked className="accent-white" />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* 7. USER MANAGEMENT TAB */}
            {activeTab === "users" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    User Management // Seats & Team Roster
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Allocate seat licenses, adjust permission matrices, and invite collaborator keys.
                  </p>
                </div>

                {/* Seat Quota */}
                <div className="p-3 bg-[#111111] border border-[#222222] flex items-center justify-between font-mono text-xs">
                  <div>
                    <span className="text-white font-bold">5 OF 10 SEATS ALLOCATED</span>
                    <div className="text-[10px] text-[#888888] mt-0.5">5 seats available on Sovereign Enterprise Plan</div>
                  </div>
                  <div className="w-32 h-2 bg-[#000000] border border-[#222222] overflow-hidden">
                    <div className="w-1/2 h-full bg-white" />
                  </div>
                </div>

                {/* Invite Form */}
                <form onSubmit={handleInviteUser} className="border border-[#222222] p-3 bg-[#111111] flex gap-2 font-mono text-xs">
                  <input
                    type="email"
                    placeholder="COLLEAGUE_EMAIL@CORP.DEV"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    className="flex-1 bg-[#000000] border border-[#222222] focus:border-white px-3 py-1.5 text-xs text-white placeholder-[#444444] outline-none"
                  />
                  <select
                    value={inviteRole}
                    onChange={(e) => setInviteRole(e.target.value)}
                    className="bg-[#000000] border border-[#222222] focus:border-white px-2 py-1.5 text-xs text-white outline-none"
                  >
                    <option value="Engineer">Engineer</option>
                    <option value="Admin">Admin</option>
                    <option value="Read Only">Read Only</option>
                  </select>
                  <button
                    type="submit"
                    className="px-4 py-1.5 bg-white text-black font-bold hover:bg-[#cccccc] transition-none uppercase"
                  >
                    + Invite
                  </button>
                </form>

                {/* Roster Table */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-2 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [ACTIVE TEAM MEMBERS]
                  </span>
                  <div className="space-y-1.5">
                    {teamMembers.map((member) => (
                      <div
                        key={member.id}
                        className="flex items-center justify-between p-2.5 bg-[#000000] border border-[#222222]"
                      >
                        <div>
                          <div className="text-white font-bold">{member.name}</div>
                          <div className="text-[10px] text-[#666666]">{member.email}</div>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-[10px] border border-[#333333] px-2 py-0.5 text-white">
                            {member.role}
                          </span>
                          <span className="text-[10px] text-[#888888]">{member.lastActive}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* 8. AUDIT LOG TAB */}
            {activeTab === "audit" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Audit Log // Security Event Stream
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Cryptographically stamped record of administrative access, key changes, and permission adjustments.
                  </p>
                </div>

                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-[#888888] uppercase tracking-wider">
                      [RECENT AUDIT EVENTS // TAMPER-EVIDENT]
                    </span>
                    <button
                      onClick={() => alert("Audit log exported as JSON format.")}
                      className="text-[10px] border border-[#222222] hover:bg-white hover:text-black transition-none px-2 py-0.5"
                    >
                      EXPORT LOGS (JSON)
                    </button>
                  </div>
                  <div className="space-y-1.5 font-mono text-[11px]">
                    {[
                      { ts: "2026-09-28 11:34:02", actor: "principal@crux.dev", action: "API_KEY_GENERATED (crx_live_sec)", ip: "192.168.1.101", status: "OK" },
                      { ts: "2026-09-28 09:12:44", actor: "alex.v@crux.dev", action: "WORKSPACE_LOCK_ENGAGED", ip: "10.0.4.18", status: "OK" },
                      { ts: "2026-09-27 22:40:11", actor: "system.daemon", action: "CRDT_CHECKPOINT_SAVED", ip: "127.0.0.1", status: "OK" },
                      { ts: "2026-09-27 18:05:30", actor: "d.chen@crux.dev", action: "FAILED_LOGIN_ATTEMPT", ip: "185.220.101.5", status: "WARN" },
                      { ts: "2026-09-26 14:20:00", actor: "principal@crux.dev", action: "SSO_POLICY_ENFORCED", ip: "192.168.1.101", status: "OK" },
                    ].map((row, i) => (
                      <div
                        key={i}
                        className="p-2 bg-[#000000] border border-[#222222] flex items-center justify-between"
                      >
                        <div className="space-x-2 truncate">
                          <span className="text-[#666666]">{row.ts}</span>
                          <span className="text-white font-bold">{row.actor}</span>
                          <span className="text-[#aaaaaa]">{row.action}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="text-[10px] text-[#555555]">{row.ip}</span>
                          <span className={`text-[9.5px] border px-1 ${row.status === "OK" ? "border-[#444444] text-white" : "border-white text-white font-bold"}`}>
                            {row.status}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* 9. VERSION HISTORY TAB */}
            {activeTab === "history" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Version History // Time-Travel Engine
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Inspect AST CRDT revisions, replay editor states, and revert to designated cryptographic checkpoints.
                  </p>
                </div>

                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-[#888888] uppercase tracking-wider">
                      [CRDT REVISION SNAPSHOTS]
                    </span>
                    <button
                      onClick={() => alert("Manual snapshot created.")}
                      className="text-[10px] border border-white bg-white text-black font-bold px-2.5 py-0.5 hover:bg-[#cccccc] transition-none"
                    >
                      + CREATE MANUAL CHECKPOINT
                    </button>
                  </div>
                  <div className="space-y-2">
                    {[
                      { id: "rev-9411", title: "AST CRDT Buffer Synchronization refactor", author: "@Principal", time: "22m ago", hash: "9f82d1c" },
                      { id: "rev-9410", title: "WebGPU Raw shader matrix initialization", author: "@Elena", time: "2h ago", hash: "447a11e" },
                      { id: "rev-9409", title: "Add Scoped API token validation rules", author: "@CruxAI", time: "6h ago", hash: "e038cc9" },
                      { id: "rev-9408", title: "Initial bare-metal kernel workspace commit", author: "@Principal", time: "1d ago", hash: "001a4fb" },
                    ].map((rev) => (
                      <div
                        key={rev.id}
                        className="p-3 bg-[#000000] border border-[#222222] flex items-center justify-between"
                      >
                        <div>
                          <div className="text-white font-bold">{rev.title}</div>
                          <div className="text-[10px] text-[#666666] mt-0.5">
                            {rev.author} · {rev.time} · Commit: {rev.hash}
                          </div>
                        </div>
                        <button
                          onClick={() => {
                            triggerHaptic("toggle");
                            alert(`Reverting to snapshot ${rev.id}...`);
                          }}
                          className="text-[10px] border border-[#444444] hover:bg-white hover:text-black transition-none px-2.5 py-1 uppercase"
                        >
                          Revert to State
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* 10. NOTIFICATIONS TAB */}
            {activeTab === "notifications" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Notifications // Alerts & Channel Matrix
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Configure real-time system alerts, synchronization notifications, and background agent progress updates.
                  </p>
                </div>

                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [NOTIFICATION DELIVERY MATRIX]
                  </span>
                  <div className="border border-[#222222] bg-[#000000]">
                    <div className="grid grid-cols-4 p-2 border-b border-[#222222] text-[10px] text-[#666666] uppercase">
                      <div>EVENT CATEGORY</div>
                      <div className="text-center">DESKTOP</div>
                      <div className="text-center">IN-EDITOR</div>
                      <div className="text-center">EMAIL</div>
                    </div>
                    {[
                      { key: "agentComplete", label: "Autonomous Agent Task Done" },
                      { key: "securityAlert", label: "Security & Key Revocation Alert" },
                      { key: "peerSync", label: "Multiplayer Peer Cursor Connect" },
                      { key: "buildFail", label: "Kernel Build Failure" },
                    ].map((row) => (
                      <div key={row.key} className="grid grid-cols-4 p-2.5 border-b border-[#222222] last:border-b-0 items-center">
                        <div className="text-white">{row.label}</div>
                        <div className="flex justify-center">
                          <input type="checkbox" defaultChecked className="accent-white" />
                        </div>
                        <div className="flex justify-center">
                          <input type="checkbox" defaultChecked className="accent-white" />
                        </div>
                        <div className="flex justify-center">
                          <input type="checkbox" defaultChecked={row.key === "securityAlert"} className="accent-white" />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* 11. ANALYTICS TAB */}
            {activeTab === "analytics" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Analytics // WebGPU Engine Telemetry
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Live hardware resource gauges, shader pipeline latency, and AST CRDT throughput.
                  </p>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                  <div className="p-3 bg-[#111111] border border-[#222222]">
                    <div className="text-[10px] text-[#666666] uppercase">WEBGPU FPS</div>
                    <div className="text-lg font-bold text-white mt-1">120 FPS</div>
                    <div className="text-[10px] text-[#888888] mt-0.5">Frame Time: 0.38ms</div>
                  </div>
                  <div className="p-3 bg-[#111111] border border-[#222222]">
                    <div className="text-[10px] text-[#666666] uppercase">CRDT LATENCY</div>
                    <div className="text-lg font-bold text-white mt-1">8.4 ms</div>
                    <div className="text-[10px] text-[#888888] mt-0.5">P99: 14.1ms</div>
                  </div>
                  <div className="p-3 bg-[#111111] border border-[#222222]">
                    <div className="text-[10px] text-[#666666] uppercase">HEAP BUFFER</div>
                    <div className="text-lg font-bold text-white mt-1">142 MB</div>
                    <div className="text-[10px] text-[#888888] mt-0.5">Pressure: 12%</div>
                  </div>
                  <div className="p-3 bg-[#111111] border border-[#222222]">
                    <div className="text-[10px] text-[#666666] uppercase">AGENT TOKENS</div>
                    <div className="text-lg font-bold text-white mt-1">148 tok/s</div>
                    <div className="text-[10px] text-[#888888] mt-0.5">Local Daemon Bus</div>
                  </div>
                </div>

                {/* ASCII Hardware Brutalist Monitor */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-2 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-[#888888] uppercase tracking-wider">
                      [RAW HARDWARE SHADER METRICS // METAL GPU]
                    </span>
                    <span className="text-[10px] text-[#444444]">DEVICE: APPLE M-SERIES METAL</span>
                  </div>
                  <pre className="p-3 bg-[#000000] border border-[#222222] text-[10.5px] leading-relaxed text-[#aaaaaa] overflow-x-auto whitespace-pre">
{`RENDER PASS:    [========================================] 100% (0.12ms)
COMPUTE PASS:   [====================                    ]  50% (0.26ms)
CRDT INGEST:    [=======                                 ]  18% (0.04ms)
DAEMON BUS:     [===                                     ]   8% (0.02ms)

STATUS: NOMINAL // ALL PIPELINES PASSING ZERO-COPY INTEGRITY`}
                  </pre>
                </div>
              </div>
            )}

            {/* 12. HELP & MAINTENANCE TAB */}
            {activeTab === "help" && (
              <div className="space-y-6">
                <div className="border-b border-[#222222] pb-3">
                  <h2 className="text-base font-bold font-mono uppercase text-white tracking-wider">
                    Help Center & Maintenance // System Status
                  </h2>
                  <p className="text-xs text-[#888888] mt-1 font-sans">
                    Diagnostic bundles, documentation search, support tickets, and system health status.
                  </p>
                </div>

                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-[#888888] uppercase tracking-wider">
                      [OPERATIONAL SYSTEM STATUS]
                    </span>
                    <span className="px-2 py-0.5 border border-white text-white font-bold text-[10px]">
                      ALL SYSTEMS OPERATIONAL
                    </span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    <div className="p-2.5 bg-[#000000] border border-[#222222]">
                      <div className="text-[#666666] text-[10px]">SYNC MESH</div>
                      <div className="text-white font-bold mt-0.5">ONLINE · 99.99%</div>
                    </div>
                    <div className="p-2.5 bg-[#000000] border border-[#222222]">
                      <div className="text-[#666666] text-[10px]">DAEMON SOCKET</div>
                      <div className="text-white font-bold mt-0.5">READY · /tmp/crux.sock</div>
                    </div>
                    <div className="p-2.5 bg-[#000000] border border-[#222222]">
                      <div className="text-[#666666] text-[10px]">AGENT RUNTIME</div>
                      <div className="text-white font-bold mt-0.5">LOCAL + CLOUD</div>
                    </div>
                  </div>
                </div>

                {/* Diagnostics Bundle */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-3 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [DIAGNOSTICS BUNDLE // SUPPORT ESCALATION]
                  </span>
                  <p className="text-[#aaaaaa] text-xs font-sans">
                    Generate an anonymized telemetry and runtime log bundle to attach to GitHub issues or enterprise support tickets.
                  </p>
                  <button
                    onClick={handleCopyDiagnostics}
                    className="px-3.5 py-1.5 border border-[#444444] hover:bg-white hover:text-black transition-none text-xs font-mono uppercase flex items-center gap-2"
                  >
                    {copiedDiag ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedDiag ? "COPIED TO CLIPBOARD" : "COPY DIAGNOSTICS BUNDLE"}</span>
                  </button>
                </div>

                {/* Direct Links */}
                <div className="border border-[#222222] p-4 bg-[#111111] space-y-2 font-mono text-xs">
                  <span className="text-[11px] text-[#888888] uppercase block tracking-wider">
                    [DOCUMENTATION & RESOURCES]
                  </span>
                  <div className="flex flex-col gap-1.5">
                    <a
                      href="https://github.com"
                      target="_blank"
                      rel="noreferrer"
                      className="p-2 bg-[#000000] border border-[#222222] hover:border-white text-white flex items-center justify-between transition-none"
                    >
                      <span>Crux Kernel Architecture Manual</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                    <a
                      href="https://github.com"
                      target="_blank"
                      rel="noreferrer"
                      className="p-2 bg-[#000000] border border-[#222222] hover:border-white text-white flex items-center justify-between transition-none"
                    >
                      <span>WebGPU Rendering & CRDT Protocol Specification</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
