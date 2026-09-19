"use client";

import React, { useState, useMemo } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick, playMechanicalEnter, playMagneticPulse } from "@/lib/sound";
import MagneticNeedleField from "../void/MagneticNeedleField";
import { Settings, User, Lock, Key, Shield, Check, Sliders, Cpu, ArrowRight } from "lucide-react";

export default function CruxOnboardingStartPage() {
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const setUserProfile = useWorkspaceStore((state) => state.setUserProfile);
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);
  const setZeroStateOpen = useWorkspaceStore((state) => state.setZeroStateOpen);

  // Flow State: 'welcome' (Monolithic Zero State Landing), 'signup' (Create Developer Node), 'login' (Authenticate Node Key), or 'settings' (Account & Hardware Preferences)
  const [activeView, setActiveView] = useState<"welcome" | "signup" | "login" | "settings">("welcome");

  // Auth & Profile Form States
  const [name, setName] = useState(currentUser.name || "");
  const [email, setEmail] = useState(currentUser.email || "");
  const [password, setPassword] = useState("");
  const [loginIdentifier, setLoginIdentifier] = useState(currentUser.email || currentUser.uid || "");
  const [loginKey, setLoginKey] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [copiedUid, setCopiedUid] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  // Account Settings States
  const [keymapPreference, setKeymapPreference] = useState<"default" | "jetbrains" | "vscode" | "vim">(
    currentUser.keymapPreference || "default"
  );
  const [defaultComputeTarget, setDefaultComputeTarget] = useState<"local" | "bedrock" | "copilot">(
    currentUser.defaultComputeTarget || "local"
  );
  const [telemetryEnabled, setTelemetryEnabled] = useState<boolean>(
    currentUser.telemetryEnabled !== false
  );

  // Dynamically generate cryptographic node UID based on name and email hash
  const generatedUid = useMemo(() => {
    if (!name && !email) return currentUser.uid || "CRX-7447-HG";
    const initials = (name.split(" ").map((n) => n[0]).join("") || "CRX").slice(0, 2).toUpperCase();
    const hash = Math.abs(
      (name + email).split("").reduce((acc, char) => acc + char.charCodeAt(0), 7447) % 9000 + 1000
    );
    return `CRX-${hash}-${initials}`;
  }, [name, email, currentUser.uid]);

  // Handle Signup (Create New Node Enclave)
  const handleSignUp = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      playMechanicalClick("low");
      setErrorMsg("[ERR: DEVELOPER_NAME_REQUIRED // ENCLAVE_REJECTED]");
      return;
    }
    if (!email.trim() || !email.includes("@")) {
      playMechanicalClick("low");
      setErrorMsg("[ERR: INVALID_MESH_ROUTING_EMAIL // TLS_FAILED]");
      return;
    }
    if (!password.trim()) {
      playMechanicalClick("low");
      setErrorMsg("[ERR: MASTER_KEY_REQUIRED // KEYRING_LOCKED]");
      return;
    }

    playMechanicalEnter();
    playMagneticPulse();
    triggerHaptic("click");

    setUserProfile({
      name: name.trim(),
      email: email.trim(),
      uid: generatedUid,
      password: password.trim(),
      role: "Principal Developer",
      accessLevel: "full",
      isSelf: true,
      keymapPreference,
      defaultComputeTarget,
      telemetryEnabled,
    });
    setOnboarded(true);
    setZeroStateOpen(false);
  };

  // Handle Login (Verify Master Enclave Key)
  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginIdentifier.trim()) {
      playMechanicalClick("low");
      setErrorMsg("[ERR: UID_OR_EMAIL_REQUIRED // AUTH_ABORTED]");
      return;
    }
    if (!loginKey.trim()) {
      playMechanicalClick("low");
      setErrorMsg("[ERR: MASTER_ENCRYPTION_KEY_REQUIRED // ENCLAVE_LOCKED]");
      return;
    }

    playMechanicalEnter();
    playMagneticPulse();
    triggerHaptic("click");

    // Authenticate and load existing profile
    const initials = (loginIdentifier.split("@")[0].slice(0, 2) || "CR").toUpperCase();
    const existingUid = loginIdentifier.startsWith("CRX-") ? loginIdentifier : `CRX-7447-${initials}`;

    setUserProfile({
      name: currentUser.name || loginIdentifier.split("@")[0] || "Developer",
      email: loginIdentifier.includes("@") ? loginIdentifier : currentUser.email || "developer@crux.engine",
      uid: existingUid,
      password: loginKey.trim(),
      role: "Principal Developer",
      accessLevel: "full",
      isSelf: true,
      keymapPreference,
      defaultComputeTarget,
      telemetryEnabled,
    });
    setOnboarded(true);
    setZeroStateOpen(false);
  };

  // Save Account Settings on Start Page
  const handleSaveSettings = (e: React.FormEvent) => {
    e.preventDefault();
    playMechanicalClick("mid");
    triggerHaptic("toggle");

    setUserProfile({
      keymapPreference,
      defaultComputeTarget,
      telemetryEnabled,
    });

    setSuccessMsg("[ACCOUNT_SETTINGS_SYNCHRONIZED_TO_ENCLAVE]");
    setTimeout(() => setSuccessMsg(""), 2000);
  };

  const handleCopyUid = () => {
    playMechanicalClick("mid");
    if (typeof window !== "undefined") {
      navigator.clipboard?.writeText(generatedUid);
      setCopiedUid(true);
      setTimeout(() => setCopiedUid(false), 1400);
    }
  };

  const switchTab = (tab: "welcome" | "signup" | "login" | "settings") => {
    playMechanicalClick("mid");
    triggerHaptic("tap");
    setErrorMsg("");
    setSuccessMsg("");
    setActiveView(tab);
  };

  return (
    <div className="relative w-screen h-screen bg-[#000000] text-white overflow-hidden select-none flex flex-col font-sans">
      {/* 1. Interactive Cursor-Magnetic Vector Needle Matrix (Z-0) */}
      <div className="absolute inset-0 z-0 pointer-events-auto">
        <MagneticNeedleField
          gridSpacing={26}
          needleLength={12}
          influenceRadius={360}
          initialMode="ATTRACT"
          showTelemetry={false}
        />
      </div>

      {/* 2. Top Telemetry & Status Calibration Bar (Z-20) */}
      <header className="relative z-20 h-9 border-b border-[#222222] bg-[#000000] flex items-center justify-between px-3 text-[10px] font-mono select-none">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 bg-white animate-hard-blink" />
          <button
            onClick={() => switchTab("welcome")}
            className="font-brand font-black tracking-[0px] text-white text-xs hover:text-white/80 transition-none"
            title="Return to Start Enclave"
          >
            Crux
          </button>
          <span className="text-[#333333]">/</span>
          <span className="text-[#666666] uppercase tracking-widest text-[9px]">
            {activeView === "welcome"
              ? "START_ENCLAVE // ZERO_STATE"
              : activeView === "signup"
              ? "INITIALIZE_NODE // SIGN_UP"
              : activeView === "login"
              ? "AUTHENTICATE // SIGN_IN"
              : "ACCOUNT_SETTINGS // HARDWARE_PREF"}
          </span>
        </div>

        {/* Top-Right Navigation Switches */}
        <div className="flex items-center gap-1.5 text-[9px] font-mono">
          <button
            onClick={() => switchTab("welcome")}
            className={`px-2 py-0.5 border transition-none uppercase ${
              activeView === "welcome"
                ? "bg-white text-black border-white font-bold"
                : "bg-[#000000] text-[#888888] border-[#222222] hover:text-white hover:border-[#444444]"
            }`}
          >
            00 // OVERVIEW
          </button>
          <button
            onClick={() => switchTab("signup")}
            className={`px-2 py-0.5 border transition-none uppercase ${
              activeView === "signup"
                ? "bg-white text-black border-white font-bold"
                : "bg-[#000000] text-[#888888] border-[#222222] hover:text-white hover:border-[#444444]"
            }`}
          >
            01 // SIGN UP
          </button>
          <button
            onClick={() => switchTab("login")}
            className={`px-2 py-0.5 border transition-none uppercase ${
              activeView === "login"
                ? "bg-white text-black border-white font-bold"
                : "bg-[#000000] text-[#888888] border-[#222222] hover:text-white hover:border-[#444444]"
            }`}
          >
            02 // SIGN IN
          </button>
          <button
            onClick={() => switchTab("settings")}
            className={`px-2 py-0.5 border transition-none uppercase flex items-center gap-1 ${
              activeView === "settings"
                ? "bg-white text-black border-white font-bold"
                : "bg-[#000000] text-[#888888] border-[#222222] hover:text-white hover:border-[#444444]"
            }`}
          >
            <Settings className="w-2.5 h-2.5" />
            <span>03 // SETTINGS</span>
          </button>
        </div>
      </header>

      {/* 3. Central Start Board Matrix (Z-30) */}
      <main className="relative z-30 flex-1 flex flex-col items-center justify-center p-3 sm:p-6 overflow-y-auto">
        {/* VIEW 0: WELCOME & START YOUR PROJECT LANDING DECK */}
        {activeView === "welcome" ? (
          <div className="w-full max-w-3xl flex flex-col items-center select-none gap-8 rounded-none">
            {/* 1. Monolithic Crux Title with Anchored Badge Box */}
            <div className="flex flex-col items-center select-none gap-0">
              <div className="inline-flex items-center gap-3">
                <h1 className="font-brand font-black text-white text-9xl sm:text-[116px] md:text-[132px] tracking-[0px] leading-none select-none text-center">
                  Crux
                </h1>
                <div className="self-start mt-3 border border-[#222222] bg-[#111111] px-2 py-0.5 text-xs font-mono text-[#888888] rounded-none select-none">
                  v1.2
                </div>
              </div>

              {/* 2. Precision Headline (Enlarged Scale, Tight Leading, Pure White, -tracking-[0.02em], Light Weight) */}
              <h2 className="font-sans text-4xl sm:text-5xl md:text-6xl lg:text-[68px] text-white font-light -tracking-[0.025em] leading-[1.05] select-none text-center max-w-2xl -mt-2 sm:-mt-3">
                Bringing the dream
                <br />
                IDE to reality.
              </h2>
            </div>

            {/* 3. Utilitarian Button Deck (Enlarged Scale, Exact h-14, text-sm, rounded-none, Hardware Inversion) */}
            <div className="w-full max-w-md flex flex-col gap-3 rounded-none">
              {/* Primary Action Button */}
              <button
                onClick={() => switchTab("signup")}
                className="w-full h-14 px-6 bg-white text-black font-sans font-bold text-sm uppercase tracking-wider hover:bg-white hover:text-black hover:invert transition-none flex items-center justify-center gap-3 cursor-pointer border border-white rounded-none"
              >
                <span>START YOUR PROJECT</span>
                <ArrowRight className="w-4 h-4 text-black" />
              </button>

              {/* Secondary Navigation Row */}
              <div className="grid grid-cols-2 gap-3 rounded-none">
                <button
                  onClick={() => switchTab("login")}
                  className="h-12 px-4 border border-[#222222] bg-transparent text-[#888888] hover:text-white hover:border-white transition-none font-mono text-xs sm:text-[13px] uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer rounded-none"
                >
                  <Lock className="w-4 h-4 text-[#666666] group-hover:text-white" />
                  <span>SIGN IN</span>
                </button>
                <button
                  onClick={() => switchTab("settings")}
                  className="h-12 px-4 border border-[#222222] bg-transparent text-[#888888] hover:text-white hover:border-white transition-none font-mono text-xs sm:text-[13px] uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer rounded-none"
                >
                  <Settings className="w-4 h-4 text-[#666666] group-hover:text-white" />
                  <span>SETTINGS</span>
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="w-full max-w-xl border border-[#222222] bg-[#000000]">
            {/* Card Title Strip with Hardware Mode Tabs */}
            <div className="h-9 px-3 bg-[#111111] border-b border-[#222222] flex items-center justify-between font-mono text-[10px] select-none">
              <div className="flex items-center gap-2 text-[#888888] uppercase tracking-wider">
                <span className="text-white font-bold">SYS.ENCLAVE</span>
                <span className="text-[#333333]">|</span>
                <span className="text-white">
                  {activeView === "signup"
                    ? "CREATE DEVELOPER NODE"
                    : activeView === "login"
                    ? "ATTACH EXISTING NODE KEY"
                    : "CALIBRATE ACCOUNT & PREFERENCES"}
                </span>
              </div>
              <div className="flex items-center gap-2 text-[#444444] text-[9px]">
                <span>ENCLAVE: 0x9B4E</span>
                <span className="w-1.5 h-1.5 bg-white animate-hard-blink" />
              </div>
            </div>

            {/* Upper Ruler Micro-Calibrations */}
            <div className="h-2 border-b border-[#181818] bg-[#050505] flex items-center justify-between px-2 text-[6px] text-[#222222] font-mono select-none">
              <span>000</span>
              <span>||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||</span>
              <span>256</span>
            </div>

            {/* Form Content Deck */}
            <div className="p-4 sm:p-6 space-y-5 bg-[#000000]">
              {/* Header Description */}
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="font-brand font-black text-white text-xl sm:text-2xl -tracking-[0.05em] uppercase">
                    {activeView === "signup"
                      ? "NODE INITIALIZATION"
                      : activeView === "login"
                      ? "AUTHENTICATE NODE"
                      : "ACCOUNT SETTINGS"}
                  </div>
                  <button
                    type="button"
                    onClick={() => switchTab("welcome")}
                    className="font-mono text-[9px] text-[#666666] hover:text-white border border-[#222222] px-2 py-0.5 uppercase transition-none"
                  >
                    ← Back to Start
                  </button>
                </div>
                <p className="font-sans text-[11px] text-[#666666] leading-relaxed">
                  {activeView === "signup"
                    ? "Crux compiles bare-metal collaborative buffers using cryptographic developer attestations. Register your identity to lock local memory rings and pair with mesh peers."
                    : activeView === "login"
                    ? "Enter your cryptographic Node UID or mesh routing email with master encryption key to unlock your local workspace keyring."
                    : "Configure workspace keybindings, default compute dispatch targets, and hardware telemetry diagnostics."}
                </p>
              </div>

              {/* Error Message Display */}
              {errorMsg && (
                <div className="px-3 py-2 bg-[#111111] border-l-2 border-white text-white text-[10px] font-mono uppercase tracking-wider">
                  {errorMsg}
                </div>
              )}

              {/* Success Message Display */}
              {successMsg && (
                <div className="px-3 py-2 bg-[#00FF00]/10 border-l-2 border-[#00FF00] text-[#00FF00] text-[10px] font-mono uppercase tracking-wider flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5" />
                  <span>{successMsg}</span>
                </div>
              )}

              {/* VIEW 1: SIGN UP (NEW DEVELOPER ENCLAVE) */}
              {activeView === "signup" && (
              <form onSubmit={handleSignUp} className="space-y-4">
                {/* Input: Developer Name */}
                <div className="space-y-1">
                  <div className="flex justify-between items-center font-mono text-[9px] uppercase tracking-widest text-[#555555]">
                    <label htmlFor="dev-name">01 // DEVELOPER NAME</label>
                    <span className="text-[#333333]">[ASCII_STR]</span>
                  </div>
                  <input
                    id="dev-name"
                    type="text"
                    value={name}
                    onChange={(e) => {
                      playMechanicalClick("mid");
                      setName(e.target.value);
                    }}
                    placeholder="e.g. Hrushikesh Gangala"
                    className="w-full bg-[#000000] border border-[#222222] focus:border-white px-3 py-2 text-xs text-white font-mono placeholder:text-[#333333] outline-none transition-none"
                    autoFocus
                    spellCheck={false}
                    autoComplete="off"
                  />
                </div>

                {/* Input: Email Address */}
                <div className="space-y-1">
                  <div className="flex justify-between items-center font-mono text-[9px] uppercase tracking-widest text-[#555555]">
                    <label htmlFor="mesh-email">02 // MESH ROUTING IDENTIFIER (EMAIL)</label>
                    <span className="text-[#333333]">[RFC_5322]</span>
                  </div>
                  <input
                    id="mesh-email"
                    type="email"
                    value={email}
                    onChange={(e) => {
                      playMechanicalClick("mid");
                      setEmail(e.target.value);
                    }}
                    placeholder="e.g. hrushi@crux.engine"
                    className="w-full bg-[#000000] border border-[#222222] focus:border-white px-3 py-2 text-xs text-white font-mono placeholder:text-[#333333] outline-none transition-none"
                    spellCheck={false}
                    autoComplete="off"
                  />
                </div>

                {/* Input: Master Key / Password */}
                <div className="space-y-1">
                  <div className="flex justify-between items-center font-mono text-[9px] uppercase tracking-widest text-[#555555]">
                    <label htmlFor="master-key">03 // LOCAL MASTER ENCRYPTION KEY</label>
                    <button
                      type="button"
                      onClick={() => {
                        playMechanicalClick("low");
                        setShowPassword(!showPassword);
                      }}
                      className="text-[#666666] hover:text-white transition-none uppercase text-[8px] border border-[#222222] px-1"
                    >
                      {showPassword ? "[MASK]" : "[REVEAL]"}
                    </button>
                  </div>
                  <input
                    id="master-key"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => {
                      playMechanicalClick("mid");
                      setPassword(e.target.value);
                    }}
                    placeholder="••••••••••••••••"
                    className="w-full bg-[#000000] border border-[#222222] focus:border-white px-3 py-2 text-xs text-white font-mono placeholder:text-[#333333] outline-none transition-none"
                    autoComplete="off"
                  />
                </div>

                {/* Cryptographic UID Display Box */}
                <div className="p-3 bg-[#080808] border border-[#222222] space-y-1.5 font-mono">
                  <div className="flex items-center justify-between text-[9px] text-[#555555] uppercase tracking-wider">
                    <span>[ASSIGNED_CRYPTOGRAPHIC_NODE_UID]</span>
                    <button
                      type="button"
                      onClick={handleCopyUid}
                      className="text-white hover:bg-white hover:text-black px-1.5 py-0.5 border border-[#333333] transition-none uppercase"
                    >
                      {copiedUid ? "[COPIED_TO_CLIPBOARD]" : "[COPY_UID]"}
                    </button>
                  </div>
                  <div className="text-sm font-bold text-white tracking-widest flex items-center justify-between">
                    <span>{generatedUid}</span>
                    <span className="text-[9px] text-[#444444] font-normal">[ED25519_OK]</span>
                  </div>
                </div>

                {/* Submit Button */}
                <div className="pt-2">
                  <button
                    type="submit"
                    className="w-full py-3 px-4 bg-white text-black font-sans font-bold text-xs sm:text-sm tracking-normal hover:bg-white hover:text-black hover:invert transition-none flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <span className="font-bold">INITIALIZE &amp; LAUNCH CRUX KERNEL</span>
                    <span className="font-sans font-bold text-xs">❯</span>
                  </button>
                </div>

                <div className="text-center pt-1 font-mono text-[10px] text-[#666666]">
                  Already have an authenticated node?{" "}
                  <button
                    type="button"
                    onClick={() => switchTab("login")}
                    className="text-white underline hover:no-underline font-bold"
                  >
                    Sign In instead
                  </button>
                </div>
              </form>
            )}

            {/* VIEW 2: SIGN IN (ATTACH EXISTING NODE KEY) */}
            {activeView === "login" && (
              <form onSubmit={handleLogin} className="space-y-4">
                <div className="space-y-1">
                  <div className="flex justify-between items-center font-mono text-[9px] uppercase tracking-widest text-[#555555]">
                    <label htmlFor="login-id">01 // NODE UID OR EMAIL IDENTIFIER</label>
                    <span className="text-[#333333]">[ID_OR_EMAIL]</span>
                  </div>
                  <input
                    id="login-id"
                    type="text"
                    value={loginIdentifier}
                    onChange={(e) => {
                      playMechanicalClick("mid");
                      setLoginIdentifier(e.target.value);
                    }}
                    placeholder="e.g. CRX-7447-HG or hrushi@crux.engine"
                    className="w-full bg-[#000000] border border-[#222222] focus:border-white px-3 py-2 text-xs text-white font-mono placeholder:text-[#333333] outline-none transition-none"
                    autoFocus
                    spellCheck={false}
                    autoComplete="off"
                  />
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between items-center font-mono text-[9px] uppercase tracking-widest text-[#555555]">
                    <label htmlFor="login-key">02 // MASTER ENCRYPTION KEY</label>
                    <button
                      type="button"
                      onClick={() => {
                        playMechanicalClick("low");
                        setShowPassword(!showPassword);
                      }}
                      className="text-[#666666] hover:text-white transition-none uppercase text-[8px] border border-[#222222] px-1"
                    >
                      {showPassword ? "[MASK]" : "[REVEAL]"}
                    </button>
                  </div>
                  <input
                    id="login-key"
                    type={showPassword ? "text" : "password"}
                    value={loginKey}
                    onChange={(e) => {
                      playMechanicalClick("mid");
                      setLoginKey(e.target.value);
                    }}
                    placeholder="••••••••••••••••"
                    className="w-full bg-[#000000] border border-[#222222] focus:border-white px-3 py-2 text-xs text-white font-mono placeholder:text-[#333333] outline-none transition-none"
                    autoComplete="off"
                  />
                </div>

                <div className="p-3 bg-[#080808] border border-[#222222] text-[10px] font-mono text-[#666666] flex items-center gap-2">
                  <Key className="w-3.5 h-3.5 text-white shrink-0" />
                  <span>Your master key remains localized in memory and is never transmitted over external network hops.</span>
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    className="w-full py-3 px-4 bg-white text-black font-sans font-bold text-xs sm:text-sm tracking-normal hover:bg-white hover:text-black hover:invert transition-none flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <span className="font-bold">ATTACH NODE &amp; LAUNCH CRUX</span>
                    <span className="font-sans font-bold text-xs">❯</span>
                  </button>
                </div>

                <div className="text-center pt-1 font-mono text-[10px] text-[#666666]">
                  Need a new developer enclave?{" "}
                  <button
                    type="button"
                    onClick={() => switchTab("signup")}
                    className="text-white underline hover:no-underline font-bold"
                  >
                    Create Node
                  </button>
                </div>
              </form>
            )}

            {/* VIEW 3: ACCOUNT & HARDWARE SETTINGS */}
            {activeView === "settings" && (
              <form onSubmit={handleSaveSettings} className="space-y-4 font-mono text-xs">
                {/* Keymap Preference */}
                <div className="space-y-1.5">
                  <div className="flex justify-between items-center text-[9px] uppercase tracking-widest text-[#555555]">
                    <span>01 // KEYMAP &amp; SHORTCUT PREFERENCE</span>
                    <span className="text-[#333333]">[INGESTED_DEFAULTS]</span>
                  </div>
                  <div className="grid grid-cols-4 gap-1.5">
                    {(["default", "jetbrains", "vscode", "vim"] as const).map((km) => (
                      <button
                        key={km}
                        type="button"
                        onClick={() => setKeymapPreference(km)}
                        className={`p-2 border text-[10px] uppercase font-bold transition-none ${
                          keymapPreference === km
                            ? "bg-white text-black border-white"
                            : "bg-[#000000] text-[#888888] border-[#222222] hover:text-white"
                        }`}
                      >
                        {km}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Default Compute Dispatch Target */}
                <div className="space-y-1.5">
                  <div className="flex justify-between items-center text-[9px] uppercase tracking-widest text-[#555555]">
                    <span>02 // DEFAULT COMPUTE DISPATCH TARGET</span>
                    <span className="text-[#333333]">[0ms_FALLBACK]</span>
                  </div>
                  <div className="grid grid-cols-3 gap-1.5">
                    {[
                      { id: "local", label: "Local (Ollama/AST)" },
                      { id: "bedrock", label: "AWS Bedrock (SDK)" },
                      { id: "copilot", label: "GitHub (gh CLI)" },
                    ].map((target) => (
                      <button
                        key={target.id}
                        type="button"
                        onClick={() => setDefaultComputeTarget(target.id as any)}
                        className={`p-2 border text-[10px] uppercase font-bold transition-none ${
                          defaultComputeTarget === target.id
                            ? "bg-white text-black border-white"
                            : "bg-[#000000] text-[#888888] border-[#222222] hover:text-white"
                        }`}
                      >
                        {target.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Hardware Telemetry Toggle */}
                <div className="p-3 bg-[#080808] border border-[#222222] flex items-center justify-between">
                  <div className="space-y-0.5">
                    <span className="text-[10px] uppercase text-white font-bold block">
                      Hardware Micro-Telemetry Diagnostics
                    </span>
                    <span className="text-[9.5px] text-[#666666] block">
                      Reports 0.08ms memory-mapped ring latencies and AST vector clock throughput.
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setTelemetryEnabled(!telemetryEnabled)}
                    className={`px-2.5 py-1 text-[9px] uppercase font-bold border transition-none ${
                      telemetryEnabled
                        ? "bg-white text-black border-white"
                        : "bg-[#000000] text-[#666666] border-[#222222]"
                    }`}
                  >
                    {telemetryEnabled ? "ENABLED" : "DISABLED"}
                  </button>
                </div>

                {/* Save Settings Button */}
                <div className="pt-2 flex items-center gap-2">
                  <button
                    type="submit"
                    className="flex-1 py-2.5 px-4 bg-white text-black font-sans font-bold text-xs uppercase tracking-wider hover:invert transition-none flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <span>SAVE ENCLAVE PREFERENCES</span>
                    <Check className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => switchTab("signup")}
                    className="py-2.5 px-3 border border-[#222222] text-[#888888] hover:text-white text-xs uppercase transition-none"
                  >
                    Back to Launch
                  </button>
                </div>
              </form>
            )}
          </div>

          {/* Lower Hardware Telemetry Stencil */}
          <div className="px-4 py-2 border-t border-[#222222] bg-[#050505] text-[9px] font-mono text-[#444444] flex items-center justify-between select-none uppercase">
            <span>[IPC: 0.04ms MEM_LOCK]</span>
            <span className="text-[#222222]">/</span>
            <span>[VCLOCK: SYNC_READY]</span>
            <span className="text-[#222222]">/</span>
            <span className="text-white">[ZERO_RADIUS // HARDWARE_BRUTALISM]</span>
          </div>
        </div>
        )}
      </main>

      {/* 4. Bottom Footer Calibration (Z-20) */}
      <footer className="relative z-20 h-7 border-t border-[#222222] bg-[#000000] flex items-center justify-between px-3 text-[9px] font-mono text-[#444444] select-none">
        <div>[crux_dom_kernel // v1.2.0]</div>
        <div className="flex items-center gap-3">
          <span>ETNA SANS SERIF / ARIAL MT PRO</span>
          <span className="text-[#222222]">|</span>
          <span className="text-white">HARDWARE BRUTALISM</span>
        </div>
      </footer>
    </div>
  );
}
