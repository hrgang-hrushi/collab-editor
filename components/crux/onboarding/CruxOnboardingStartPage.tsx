"use client";

import React, { useState, useMemo, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { triggerHaptic } from "@/lib/haptics";
import MagneticNeedleField from "../void/MagneticNeedleField";
import CruxAuthGate from "../auth/CruxAuthGate";
import { WORKSPACE_TEMPLATES } from "@/lib/defaultData";
import {
  Settings,
  User,
  Lock,
  Key,
  Shield,
  Check,
  Cpu,
  ArrowRight,
  ChevronRight,
  Terminal,
  Share2,
  Copy,
  Layers,
  Sparkles,
} from "lucide-react";
import CruxMinimalistMigrationCard from "../migration/CruxMinimalistMigrationCard";

export default function CruxOnboardingStartPage() {
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const setUserProfile = useWorkspaceStore((state) => state.setUserProfile);
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);
  const setZeroStateOpen = useWorkspaceStore((state) => state.setZeroStateOpen);
  const loadWorkspaceTemplate = useWorkspaceStore((state) => state.loadWorkspaceTemplate);

  // Flow views:
  // - "welcome": GA Hero landing with Quick Launch, Calibration, or Connect Node Key
  // - "calibrate": 3-step guided setup (Identity -> Blueprint -> Engine -> Boot sequence)
  // - "auth": CruxAuthGate for GitHub / Google / Cryptographic Master Key
  // - "settings": Account & hardware preferences calibration
  const [activeView, setActiveView] = useState<"welcome" | "calibrate" | "auth" | "settings">("welcome");

  // Calibration wizard steps: 1 (Operator Callsign), 2 (Workspace Blueprint), 3 (Engine & Keymap), 4 (Booting)
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [bootLogs, setBootLogs] = useState<string[]>([]);

  // Profile Form States
  const [name, setName] = useState(currentUser.name || "Operator");
  const [role, setRole] = useState(currentUser.role || "Principal Architect");
  const [selectedColor, setSelectedColor] = useState(currentUser.color || "#FFFFFF");
  const [selectedTemplate, setSelectedTemplate] = useState<string>("mesh");
  const [copiedUid, setCopiedUid] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  // Account Settings States
  const [keymapPreference, setKeymapPreference] = useState<"default" | "jetbrains" | "vscode" | "vim">(
    currentUser.keymapPreference || "vscode"
  );
  const [defaultComputeTarget, setDefaultComputeTarget] = useState<"local" | "bedrock" | "copilot">(
    currentUser.defaultComputeTarget || "local"
  );
  const [telemetryEnabled, setTelemetryEnabled] = useState<boolean>(
    currentUser.telemetryEnabled !== false
  );

  // Dynamically generate cryptographic node UID based on name and timestamp
  const generatedUid = useMemo(() => {
    const clean = (name || "CRX").replace(/[^a-zA-Z0-9]/g, "").slice(0, 4).toUpperCase();
    const hash = Math.abs(
      (name + role).split("").reduce((acc, char) => acc + char.charCodeAt(0), 7447) % 9000 + 1000
    );
    return `CRX-${hash}-${clean || "NODE"}`;
  }, [name, role]);

  const handleCopyUid = () => {
    triggerHaptic("tap");
    if (typeof window !== "undefined") {
      navigator.clipboard?.writeText(generatedUid);
      setCopiedUid(true);
      setTimeout(() => setCopiedUid(false), 1400);
    }
  };

  // Express One-Click Boot
  const handleQuickBoot = () => {
    triggerHaptic("click");
    loadWorkspaceTemplate("mesh");
    setUserProfile({
      name: name.trim() || "Operator",
      role,
      uid: generatedUid,
      color: selectedColor,
      keymapPreference,
      defaultComputeTarget,
      telemetryEnabled,
      isSelf: true,
      accessLevel: "full",
    });
    setOnboarded(true);
    setZeroStateOpen(false);
  };

  // Start Calibration Wizard
  const handleStartCalibration = () => {
    triggerHaptic("tap");
    setErrorMsg("");
    setStep(1);
    setActiveView("calibrate");
  };

  // Advance Step in Calibration Wizard
  const handleNextStep = () => {
    triggerHaptic("tap");
    if (step === 1) {
      if (!name.trim()) {
        setErrorMsg("Please provide an operator call-sign.");
        return;
      }
      setErrorMsg("");
      setStep(2);
    } else if (step === 2) {
      setStep(3);
    } else if (step === 3) {
      // Begin mechanical boot sequence
      setStep(4);
      setBootLogs(["[INIT] ALLOCATING HARDWARE MEMORY ENCLAVE..."]);

      setTimeout(() => {
        setBootLogs((prev) => [...prev, "[OK] INGESTING SELECTED BLUEPRINT MATRIX..."]);
      }, 350);

      setTimeout(() => {
        setBootLogs((prev) => [...prev, "[OK] INITIALIZING VECTOR CLOCK & ED25519 VAULT..."]);
      }, 700);

      setTimeout(() => {
        setBootLogs((prev) => [...prev, `[READY] OPERATOR ${generatedUid} ATTESTED // DISPATCHING GA RUNTIME.`]);
      }, 1050);

      setTimeout(() => {
        loadWorkspaceTemplate(selectedTemplate);
        setUserProfile({
          name: name.trim() || "Operator",
          role,
          uid: generatedUid,
          color: selectedColor,
          keymapPreference,
          defaultComputeTarget,
          telemetryEnabled,
          isSelf: true,
          accessLevel: "full",
        });
        setOnboarded(true);
        setZeroStateOpen(false);
      }, 1450);
    }
  };

  // Save Preferences in Settings View
  const handleSaveSettings = (e: React.FormEvent) => {
    e.preventDefault();
    triggerHaptic("click");
    setUserProfile({
      keymapPreference,
      defaultComputeTarget,
      telemetryEnabled,
    });
    setSuccessMsg("Settings saved.");
    setTimeout(() => setSuccessMsg(""), 1800);
  };

  const switchTab = (tab: "welcome" | "calibrate" | "auth" | "settings") => {
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

      {/* 2. Top System Telemetry Bar (Z-30) */}
      <header className="relative z-30 h-10 px-4 border-b border-[#222222] bg-[#000000]/90 flex items-center justify-between font-mono text-[10px] uppercase text-[#888888] shrink-0 select-none">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-white font-bold">
            <span className="w-1.5 h-1.5 bg-white animate-hard-blink" />
            <span className="font-brand font-black tracking-[0px]">Crux</span>
          </div>
          <span className="text-[#333333]">/</span>
          <span className="text-white">v1.0.0 GA</span>
          <span className="text-[#333333]">/</span>
          <span className="hidden sm:inline">BARE-METAL COLLABORATIVE IDE</span>
        </div>

        <div className="flex items-center gap-4 text-[9px]">
          <div className="hidden md:flex items-center gap-2">
            <span>[CRDT: VECTOR_SYNC]</span>
            <span className="text-[#333333]">|</span>
            <span>[LERP: 120HZ]</span>
            <span className="text-[#333333]">|</span>
            <span>[WEBRTC: MESH READY]</span>
          </div>
          <button
            onClick={() => switchTab(activeView === "settings" ? "welcome" : "settings")}
            className="flex items-center gap-1 text-[#888888] hover:text-white border border-[#222222] px-2 py-0.5 transition-none"
          >
            <Settings className="w-3 h-3" />
            <span>{activeView === "settings" ? "EXIT CONFIG" : "CONFIG"}</span>
          </button>
        </div>
      </header>

      {/* 3. Central Content Arena (Z-30) */}
      <main className="relative z-30 flex-1 flex flex-col items-center justify-center p-4 sm:p-6 overflow-y-auto">
        {/* VIEW 1: WELCOME / GA GATEWAY */}
        {activeView === "welcome" && (
          <div className="w-full max-w-2xl flex flex-col items-center gap-7 select-none">
            {/* Monolithic Crux Title (Strictly Capital C Only, 0 Tracking, No Floating Badges) */}
            <div className="flex flex-col items-center text-center">
              <div className="text-[10px] font-mono uppercase tracking-[0.25em] text-[#888888] mb-1">
                GENERAL AVAILABILITY // v1.0.0
              </div>
              <h1 className="font-brand font-black text-white text-8xl sm:text-[112px] md:text-[128px] tracking-[0px] leading-none select-none">
                Crux
              </h1>
              <p className="font-sans text-xs sm:text-sm text-[#888888] max-w-lg mt-3 leading-relaxed">
                The bare-metal collaborative IDE for high-velocity engineering.
                Built on raw silicon, lock-free vector clocks, and zero-knowledge peer mesh.
              </p>
            </div>

            {/* Utilitarian Hardware Launch Triggers */}
            <div className="w-full max-w-md flex flex-col gap-2.5">
              {/* Primary Kernel Boot Trigger */}
              <button
                onClick={handleQuickBoot}
                className="w-full h-13 px-6 bg-white text-black font-sans font-bold text-xs uppercase tracking-wider hover:bg-black hover:text-white hover:border-white transition-none flex items-center justify-center gap-3 cursor-pointer border border-white rounded-none"
              >
                <span>QUICK BOOT WORKSPACE</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              {/* Guided Setup & Auth Triggers */}
              <div className="grid grid-cols-2 gap-2.5">
                <button
                  onClick={handleStartCalibration}
                  className="h-11 px-4 border border-[#222222] bg-[#0A0A0A] text-[#CCCCCC] hover:text-white hover:border-white transition-none font-mono text-xs uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer rounded-none"
                >
                  <Sparkles className="w-3.5 h-3.5 text-white" />
                  <span>CALIBRATE ENCLAVE</span>
                </button>
                <button
                  onClick={() => switchTab("auth")}
                  className="h-11 px-4 border border-[#222222] bg-[#0A0A0A] text-[#CCCCCC] hover:text-white hover:border-white transition-none font-mono text-xs uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer rounded-none"
                >
                  <Lock className="w-3.5 h-3.5 text-white" />
                  <span>CONNECT NODE KEY</span>
                </button>
              </div>

              {/* Minimalist Migration Entry Point */}
              <CruxMinimalistMigrationCard />
            </div>

            {/* Hardware Telemetry Spec Matrix */}
            <div className="w-full max-w-md border border-[#222222] bg-[#0A0A0A] p-3 grid grid-cols-3 gap-2 font-mono text-[9px] uppercase text-[#888888]">
              <div>
                <span className="block text-[#444444]">SYNC ARCH</span>
                <span className="text-white font-bold">Yjs CRDT 0.04ms</span>
              </div>
              <div>
                <span className="block text-[#444444]">SECURITY</span>
                <span className="text-white font-bold">Ed25519 Vault</span>
              </div>
              <div>
                <span className="block text-[#444444]">PEER TOPOLOGY</span>
                <span className="text-white font-bold">WebRTC Mesh</span>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 2: GUIDED CALIBRATION WIZARD */}
        {activeView === "calibrate" && (
          <div className="w-full max-w-xl border border-[#222222] bg-[#000000] flex flex-col">
            {/* Header Strip with Step Tracker */}
            <div className="h-10 px-4 bg-[#111111] border-b border-[#222222] flex items-center justify-between font-mono text-[10px] select-none">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-white" />
                <span className="text-white font-bold uppercase tracking-wider">
                  ENCLAVE CALIBRATION // STEP {step} OF 3
                </span>
              </div>
              <button
                onClick={() => switchTab("welcome")}
                className="text-[#888888] hover:text-white border border-[#222222] px-2 py-0.5 uppercase transition-none text-[9px]"
              >
                CANCEL
              </button>
            </div>

            {/* Upper Step Segmented Progress */}
            <div className="grid grid-cols-3 border-b border-[#222222] text-[9px] font-mono uppercase select-none">
              <div className={`p-2 text-center border-r border-[#222222] ${step === 1 ? "bg-white text-black font-bold" : step > 1 ? "text-white bg-[#111111]" : "text-[#444444]"}`}>
                01 // IDENTITY
              </div>
              <div className={`p-2 text-center border-r border-[#222222] ${step === 2 ? "bg-white text-black font-bold" : step > 2 ? "text-white bg-[#111111]" : "text-[#444444]"}`}>
                02 // BLUEPRINT
              </div>
              <div className={`p-2 text-center ${step === 3 ? "bg-white text-black font-bold" : "text-[#444444]"}`}>
                03 // ENGINE
              </div>
            </div>

            {/* Error Message */}
            {errorMsg && (
              <div className="px-4 py-2 bg-[#111111] border-b border-white text-white text-[10px] font-mono uppercase tracking-wider">
                {errorMsg}
              </div>
            )}

            {/* Step 1: Operator Identity */}
            {step === 1 && (
              <div className="p-5 space-y-5 bg-[#000000]">
                <div className="space-y-1">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                    OPERATOR CALLSIGN &amp; IDENTITY
                  </h3>
                  <p className="text-[11px] text-[#888888] font-mono leading-relaxed">
                    Set your collaborative handle and generate a local cryptographic node identifier.
                  </p>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <div className="space-y-1">
                    <label className="text-[9px] uppercase tracking-widest text-[#666666] block">
                      OPERATOR CALLSIGN
                    </label>
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. Lead Architect / Operator"
                      className="w-full bg-[#0A0A0A] border border-[#222222] focus:border-white px-3 py-2 text-white font-mono text-xs outline-none transition-none"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[9px] uppercase tracking-widest text-[#666666] block">
                      ROLE SPECIALIZATION
                    </label>
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        "Principal Architect",
                        "Distributed Systems",
                        "Kernel Infrastructure",
                        "Security Auditor",
                      ].map((r) => (
                        <button
                          key={r}
                          type="button"
                          onClick={() => setRole(r)}
                          className={`p-2 border text-[10px] uppercase font-bold text-left transition-none ${
                            role === r
                              ? "bg-white text-black border-white"
                              : "bg-[#0A0A0A] text-[#888888] border-[#222222] hover:text-white"
                          }`}
                        >
                          {r}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[9px] uppercase tracking-widest text-[#666666] block">
                      NODE UID (CRYPTOGRAPHIC ATTESTATION)
                    </label>
                    <div className="flex items-center gap-2 p-2 bg-[#0A0A0A] border border-[#222222]">
                      <span className="text-white font-bold flex-1 text-xs">{generatedUid}</span>
                      <button
                        type="button"
                        onClick={handleCopyUid}
                        className="px-2 py-1 border border-[#222222] hover:border-white text-[9px] text-[#CCCCCC] hover:text-white flex items-center gap-1 transition-none uppercase"
                      >
                        {copiedUid ? <Check className="w-3 h-3 text-white" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedUid ? "COPIED" : "COPY"}</span>
                      </button>
                    </div>
                  </div>
                </div>

                <div className="pt-2 border-t border-[#181818] flex items-center justify-between">
                  <button
                    type="button"
                    onClick={() => switchTab("welcome")}
                    className="px-3 py-2 border border-[#222222] text-[#888888] hover:text-white text-xs uppercase font-mono transition-none"
                  >
                    BACK
                  </button>
                  <button
                    type="button"
                    onClick={handleNextStep}
                    className="px-5 py-2 bg-white text-black font-bold text-xs uppercase hover:bg-black hover:text-white hover:border-white border border-white transition-none flex items-center gap-2 cursor-pointer font-mono"
                  >
                    <span>NEXT: BLUEPRINT</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {/* Step 2: Workspace Blueprint Selection */}
            {step === 2 && (
              <div className="p-5 space-y-5 bg-[#000000]">
                <div className="space-y-1">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                    SELECT WORKSPACE MATRIX BLUEPRINT
                  </h3>
                  <p className="text-[11px] text-[#888888] font-mono leading-relaxed">
                    Choose a starting architecture template for your workspace.
                  </p>
                </div>

                <div className="space-y-2.5 font-mono">
                  {Object.values(WORKSPACE_TEMPLATES).map((tmpl) => (
                    <div
                      key={tmpl.id}
                      onClick={() => setSelectedTemplate(tmpl.id)}
                      className={`p-3 border cursor-pointer transition-none ${
                        selectedTemplate === tmpl.id
                          ? "bg-[#111111] border-white text-white"
                          : "bg-[#0A0A0A] border-[#222222] text-[#888888] hover:border-[#444444] hover:text-white"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 ${selectedTemplate === tmpl.id ? "bg-white" : "bg-[#444444]"}`} />
                          <span className="text-xs font-bold uppercase text-white">{tmpl.name}</span>
                        </div>
                        <span className="text-[9px] border border-[#222222] px-1.5 py-0.5 bg-black text-[#888888]">
                          {tmpl.tag}
                        </span>
                      </div>
                      <p className="text-[10.5px] text-[#888888] mt-1.5 leading-relaxed">
                        {tmpl.description}
                      </p>
                      <div className="flex items-center gap-2 mt-2 text-[9px] text-[#666666]">
                        <span>FILES:</span>
                        {tmpl.files.map((f) => (
                          <span key={f.id} className="text-[#CCCCCC] bg-black px-1 border border-[#222222]">
                            {f.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="pt-2 border-t border-[#181818] flex items-center justify-between font-mono">
                  <button
                    type="button"
                    onClick={() => setStep(1)}
                    className="px-3 py-2 border border-[#222222] text-[#888888] hover:text-white text-xs uppercase transition-none"
                  >
                    BACK
                  </button>
                  <button
                    type="button"
                    onClick={handleNextStep}
                    className="px-5 py-2 bg-white text-black font-bold text-xs uppercase hover:bg-black hover:text-white hover:border-white border border-white transition-none flex items-center gap-2 cursor-pointer"
                  >
                    <span>NEXT: ENGINE</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {/* Step 3: Engine & Keybindings */}
            {step === 3 && (
              <div className="p-5 space-y-5 bg-[#000000]">
                <div className="space-y-1">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                    COMPUTATION &amp; CONTROL SCHEME
                  </h3>
                  <p className="text-[11px] text-[#888888] font-mono leading-relaxed">
                    Configure your execution dispatch engine and shortcut preferences.
                  </p>
                </div>

                <div className="space-y-4 font-mono text-xs">
                  {/* Keymap Preference */}
                  <div className="space-y-1.5">
                    <span className="text-[9px] uppercase tracking-widest text-[#666666] block">
                      KEYBINDINGS STANDARD
                    </span>
                    <div className="grid grid-cols-4 gap-1.5">
                      {(["vscode", "vim", "jetbrains", "default"] as const).map((km) => (
                        <button
                          key={km}
                          type="button"
                          onClick={() => setKeymapPreference(km)}
                          className={`p-2 border text-[10px] uppercase font-bold transition-none ${
                            keymapPreference === km
                              ? "bg-white text-black border-white"
                              : "bg-[#0A0A0A] text-[#888888] border-[#222222] hover:text-white"
                          }`}
                        >
                          {km}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Compute Dispatch Target */}
                  <div className="space-y-1.5">
                    <span className="text-[9px] uppercase tracking-widest text-[#666666] block">
                      DEFAULT AI &amp; CODE EXECUTION TARGET
                    </span>
                    <div className="grid grid-cols-3 gap-1.5">
                      {[
                        { id: "local", label: "Local AST Node" },
                        { id: "bedrock", label: "AWS Bedrock" },
                        { id: "copilot", label: "GitHub Copilot" },
                      ].map((tgt) => (
                        <button
                          key={tgt.id}
                          type="button"
                          onClick={() => setDefaultComputeTarget(tgt.id as any)}
                          className={`p-2 border text-[10px] uppercase font-bold transition-none ${
                            defaultComputeTarget === tgt.id
                              ? "bg-white text-black border-white"
                              : "bg-[#0A0A0A] text-[#888888] border-[#222222] hover:text-white"
                          }`}
                        >
                          {tgt.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Hardware Telemetry */}
                  <div className="p-3 bg-[#0A0A0A] border border-[#222222] flex items-center justify-between">
                    <div>
                      <span className="text-[10px] uppercase text-white font-bold block">
                        HARDWARE MICRO-TELEMETRY
                      </span>
                      <span className="text-[9px] text-[#666666] block">
                        Displays 0.04ms ring latency and vector clock telemetry in bottom status bar.
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
                </div>

                <div className="pt-2 border-t border-[#181818] flex items-center justify-between font-mono">
                  <button
                    type="button"
                    onClick={() => setStep(2)}
                    className="px-3 py-2 border border-[#222222] text-[#888888] hover:text-white text-xs uppercase transition-none"
                  >
                    BACK
                  </button>
                  <button
                    type="button"
                    onClick={handleNextStep}
                    className="px-5 py-2.5 bg-white text-black font-bold text-xs uppercase hover:bg-black hover:text-white hover:border-white border border-white transition-none flex items-center gap-2 cursor-pointer"
                  >
                    <span>INITIALIZE ENCLAVE</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            {/* Step 4: Live Mechanical Boot Log */}
            {step === 4 && (
              <div className="p-6 space-y-4 bg-[#000000] font-mono text-xs select-none">
                <div className="flex items-center gap-2 text-white font-bold text-sm uppercase">
                  <span className="w-2 h-2 bg-white animate-hard-blink" />
                  <span>BOOTING CRUX GA KERNEL...</span>
                </div>
                <div className="p-4 bg-[#050505] border border-[#222222] space-y-2 min-h-[140px] text-[11px]">
                  {bootLogs.map((log, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-white">
                      <span className="text-[#555555]">&gt;</span>
                      <span>{log}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* VIEW 3: AUTH GATE (CONNECT NODE KEY) */}
        {activeView === "auth" && (
          <CruxAuthGate onCancel={() => switchTab("welcome")} />
        )}

        {/* VIEW 4: SETTINGS / PREFERENCES */}
        {activeView === "settings" && (
          <div className="w-full max-w-xl border border-[#222222] bg-[#000000]">
            <div className="h-9 px-3 bg-[#111111] border-b border-[#222222] flex items-center justify-between font-mono text-[10px] select-none">
              <div className="flex items-center gap-2 text-[#888888] uppercase tracking-wider">
                <span className="text-white font-bold">SYS.ENCLAVE</span>
                <span className="text-[#333333]">|</span>
                <span className="text-white">ACCOUNT &amp; HARDWARE PREFERENCES</span>
              </div>
              <button
                onClick={() => switchTab("welcome")}
                className="font-mono text-[9px] text-[#888888] hover:text-white border border-[#222222] px-2 py-0.5 uppercase transition-none"
              >
                CLOSE
              </button>
            </div>

            <div className="p-5 space-y-5 bg-[#000000]">
              {successMsg && (
                <div className="px-3 py-2 bg-[#111111] border-l-2 border-white text-white text-[10px] font-mono uppercase tracking-wider flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5" />
                  <span>{successMsg}</span>
                </div>
              )}

              <form onSubmit={handleSaveSettings} className="space-y-4 font-mono text-xs">
                {/* Keymap */}
                <div className="space-y-1.5">
                  <span className="text-[9px] uppercase tracking-widest text-[#666666] block">
                    KEYMAP STANDARD
                  </span>
                  <div className="grid grid-cols-4 gap-1.5">
                    {(["vscode", "vim", "jetbrains", "default"] as const).map((km) => (
                      <button
                        key={km}
                        type="button"
                        onClick={() => setKeymapPreference(km)}
                        className={`p-2 border text-[10px] uppercase font-bold transition-none ${
                          keymapPreference === km
                            ? "bg-white text-black border-white"
                            : "bg-[#0A0A0A] text-[#888888] border-[#222222] hover:text-white"
                        }`}
                      >
                        {km}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Compute Dispatch Target */}
                <div className="space-y-1.5">
                  <span className="text-[9px] uppercase tracking-widest text-[#666666] block">
                    DEFAULT COMPUTE TARGET
                  </span>
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
                            : "bg-[#0A0A0A] text-[#888888] border-[#222222] hover:text-white"
                        }`}
                      >
                        {target.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Telemetry Toggle */}
                <div className="p-3 bg-[#0A0A0A] border border-[#222222] flex items-center justify-between">
                  <div>
                    <span className="text-[10px] uppercase text-white font-bold block">
                      HARDWARE TELEMETRY
                    </span>
                    <span className="text-[9px] text-[#666666] block">
                      Sub-millisecond ring latency and vector clock counters.
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

                <div className="pt-2 flex items-center gap-2">
                  <button
                    type="submit"
                    className="flex-1 py-2 px-4 bg-white text-black font-sans font-bold text-xs uppercase tracking-wider hover:bg-black hover:text-white hover:border-white border border-white transition-none flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <span>SAVE PREFERENCES</span>
                    <Check className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => switchTab("welcome")}
                    className="py-2 px-3 border border-[#222222] text-[#888888] hover:text-white text-xs uppercase transition-none font-mono"
                  >
                    BACK
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </main>

      {/* 4. Bottom Hardware Telemetry Bar */}
      <footer className="relative z-30 h-8 px-4 border-t border-[#222222] bg-[#000000] text-[9px] font-mono text-[#666666] flex items-center justify-between select-none uppercase shrink-0">
        <div className="flex items-center gap-3">
          <span>[MEM_LOCK: 0.04ms]</span>
          <span className="text-[#333333]">/</span>
          <span>[VCLOCK: ACTIVE]</span>
          <span className="text-[#333333]">/</span>
          <span className="text-white">[HARDWARE BRUTALISM // 0px RADIUS]</span>
        </div>
        <div className="flex items-center gap-2">
          <span>HOST: CODECRUX.US</span>
          <span className="text-[#333333]">|</span>
          <span className="text-white">PROD GA</span>
        </div>
      </footer>
    </div>
  );
}
