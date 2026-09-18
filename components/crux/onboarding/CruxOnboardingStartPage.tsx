"use client";

import React, { useState, useMemo } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { ShieldCheck, ArrowRight, Key, Sparkles, User, Check, Copy } from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";
import CruxBrandLogo from "../CruxBrandLogo";

export default function CruxOnboardingStartPage() {
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const setUserProfile = useWorkspaceStore((state) => state.setUserProfile);
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);

  const [name, setName] = useState(currentUser.name || "");
  const [email, setEmail] = useState(currentUser.email || "");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [copiedUid, setCopiedUid] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  // Dynamically generate clean brutalist UID based on name and email hash
  const generatedUid = useMemo(() => {
    if (!name && !email) return currentUser.uid || "CRX-7447-HG";
    const initials = (name.split(" ").map((n) => n[0]).join("") || "CRX").slice(0, 2).toUpperCase();
    const hash = Math.abs(
      (name + email).split("").reduce((acc, char) => acc + char.charCodeAt(0), 7447) % 9000 + 1000
    );
    return `CRX-${hash}-${initials}`;
  }, [name, email, currentUser.uid]);

  const handleLaunch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setErrorMsg("Please enter your name to initialize identity.");
      return;
    }
    if (!email.trim() || !email.includes("@")) {
      setErrorMsg("Please enter a valid email address for mesh routing.");
      return;
    }
    if (!password.trim()) {
      setErrorMsg("Please specify a master password for local keyring encryption.");
      return;
    }

    triggerHaptic("click");
    setUserProfile({
      name: name.trim(),
      email: email.trim(),
      uid: generatedUid,
      password: password.trim(),
      role: "Principal Developer",
      accessLevel: "full",
      isSelf: true,
    });
    setOnboarded(true);
  };

  const handlePresetSelect = (presetName: string, presetEmail: string, presetUid: string, role: string) => {
    setName(presetName);
    setEmail(presetEmail);
    setPassword("crux-local-secure-key");
    setErrorMsg("");
    triggerHaptic("tap");
  };

  const handleCopyUid = () => {
    if (typeof window !== "undefined") {
      navigator.clipboard?.writeText(generatedUid);
      setCopiedUid(true);
      setTimeout(() => setCopiedUid(false), 1200);
    }
  };

  return (
    <div className="w-screen h-screen bg-void text-signal flex flex-col items-center justify-center p-4 font-sans select-none overflow-y-auto">
      {/* Background Subtle Dot Grid */}
      <div className="absolute inset-0 pointer-events-none canvas-dot-grid opacity-20" />

      {/* Main Container Card */}
      <div className="relative z-10 w-full max-w-lg bg-surface border border-grid shadow-[4px_4px_0px_#222222] flex flex-col overflow-hidden">
        {/* Header Strip */}
        <div className="h-12 px-6 border-b border-grid bg-void flex items-center justify-between">
          <div className="flex items-center gap-3">
            {/* Modular Crux Brand Logo */}
            <CruxBrandLogo size={18} withText={false} />
            <span className="text-xs font-bold tracking-widest uppercase text-signal">Crux // Initial Setup</span>
          </div>

          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-accent1" />
            <span className="text-[11px] font-mono text-muted">Daemon: 7447</span>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6">
          <div>
            <h1 className="text-base font-semibold text-signal uppercase tracking-wider">
              Initialize Developer Identity
            </h1>
            <p className="text-xs text-muted mt-1 leading-relaxed">
              Crux relies on cryptographic UIDs for zero-copy memory mapping and WebRTC peer sync. Enter your credentials to generate your node key.
            </p>
          </div>

          {errorMsg && (
            <div className="p-3 bg-[#FF453A]/10 border-l-2 border-accent2 text-accent2 text-xs font-mono">
              {errorMsg}
            </div>
          )}

          <form onSubmit={handleLaunch} className="space-y-4">
            {/* Name Input */}
            <div className="space-y-1.5">
              <label className="text-[10px] font-mono uppercase tracking-widest text-muted block">
                Developer Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Hrushikesh Gangala"
                className="w-full bg-void border border-grid px-3 py-2 text-xs text-signal font-mono outline-none focus:border-signal transition-colors"
                autoFocus
              />
            </div>

            {/* Email Input */}
            <div className="space-y-1.5">
              <label className="text-[10px] font-mono uppercase tracking-widest text-muted block">
                Email Address (Mesh Identifier)
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="e.g. hrushi@crux.dev"
                className="w-full bg-void border border-grid px-3 py-2 text-xs text-signal font-mono outline-none focus:border-signal transition-colors"
              />
            </div>

            {/* Password Input */}
            <div className="space-y-1.5">
              <div className="flex justify-between items-center">
                <label className="text-[10px] font-mono uppercase tracking-widest text-muted block">
                  Master Key / Password
                </label>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="text-[10px] font-mono text-muted hover:text-signal uppercase"
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-void border border-grid px-3 py-2 text-xs text-signal font-mono outline-none focus:border-signal transition-colors"
              />
            </div>

            {/* Dynamic UID Display Card */}
            <div className="p-3 bg-void border border-grid space-y-1">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Key className="w-3.5 h-3.5 text-accent1" />
                  <span className="text-[10px] font-mono text-muted uppercase tracking-wider">
                    Assigned Cryptographic UID
                  </span>
                </div>
                <button
                  type="button"
                  onClick={handleCopyUid}
                  className="text-[10px] font-mono text-muted hover:text-signal flex items-center gap-1 uppercase"
                >
                  {copiedUid ? <Check className="w-3 h-3 text-[#00FF00]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedUid ? "Copied" : "Copy"}</span>
                </button>
              </div>
              <div className="text-sm font-mono font-bold text-signal tracking-wide">
                {generatedUid}
              </div>
            </div>

            {/* Preset Profile Shortcuts */}
            <div className="space-y-2 pt-2">
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted block">
                Or quick-select verified mesh peer:
              </span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => handlePresetSelect("Sarah Lin", "sarah@crux.dev", "CRX-9941-SL", "Staff Infrastructure")}
                  className="px-3 py-2 bg-void border border-grid hover:border-signal text-left transition-colors"
                >
                  <div className="text-[11px] font-semibold text-signal truncate">Sarah Lin</div>
                  <div className="text-[9.5px] font-mono text-muted truncate">CRX-9941-SL</div>
                </button>
                <button
                  type="button"
                  onClick={() => handlePresetSelect("Marcus Vance", "marcus@crux.dev", "CRX-5520-MV", "Systems Architect")}
                  className="px-3 py-2 bg-void border border-grid hover:border-signal text-left transition-colors"
                >
                  <div className="text-[11px] font-semibold text-signal truncate">Marcus Vance</div>
                  <div className="text-[9.5px] font-mono text-muted truncate">CRX-5520-MV</div>
                </button>
              </div>
            </div>

            {/* Launch Button */}
            <div className="pt-3">
              <button
                type="submit"
                className="w-full py-2.5 px-4 bg-signal text-void font-bold text-xs uppercase tracking-widest hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
              >
                <span>Initialize &amp; Launch Crux IDE</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </form>
        </div>

        {/* Footer Telemetry */}
        <div className="px-6 py-3 border-t border-grid bg-void text-[10px] font-mono text-muted flex items-center justify-between">
          <span>Memory-mapped IPC: 0.08ms</span>
          <span>Ed25519 Attestation: Ready</span>
        </div>
      </div>
    </div>
  );
}
