"use client";

import React, { useState, useMemo } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick, playMechanicalEnter, playMagneticPulse } from "@/lib/sound";
import MagneticNeedleField from "../void/MagneticNeedleField";

export default function CruxOnboardingStartPage() {
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const setUserProfile = useWorkspaceStore((state) => state.setUserProfile);
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);
  const setZeroStateOpen = useWorkspaceStore((state) => state.setZeroStateOpen);

  const [name, setName] = useState(currentUser.name || "");
  const [email, setEmail] = useState(currentUser.email || "");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [copiedUid, setCopiedUid] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  // Dynamically generate cryptographic node UID based on name and email hash
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
    });
    setOnboarded(true);
    setZeroStateOpen(false);
  };

  const handleCopyUid = () => {
    playMechanicalClick("mid");
    if (typeof window !== "undefined") {
      navigator.clipboard?.writeText(generatedUid);
      setCopiedUid(true);
      setTimeout(() => setCopiedUid(false), 1400);
    }
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
          <span className="font-brand font-black tracking-tight text-white text-xs">
            Crex
          </span>
          <span className="text-[#333333]">/</span>
          <span className="text-[#666666] uppercase tracking-widest text-[9px]">
            START_BOARD // ENCLAVE_SETUP
          </span>
        </div>

        <div className="flex items-center gap-3 text-[9px] text-[#444444]">
          <span className="hidden sm:inline">[MMU_LOCK: SECURE]</span>
          <span className="text-[#222222] hidden sm:inline">/</span>
          <span>[DAEMON: 7447]</span>
          <span className="text-[#222222]">/</span>
          <span className="text-white font-bold">128-BIT IPC</span>
        </div>
      </header>

      {/* 3. Central Start Board Matrix (Z-30) */}
      <main className="relative z-30 flex-1 flex flex-col items-center justify-center p-3 sm:p-6 overflow-y-auto">
        <div className="w-full max-w-xl border border-[#222222] bg-[#000000]">
          {/* Card Title Strip */}
          <div className="h-9 px-3 bg-[#111111] border-b border-[#222222] flex items-center justify-between font-mono text-[10px] select-none">
            <div className="flex items-center gap-2 text-[#888888] uppercase tracking-wider">
              <span className="text-white font-bold">SYS.INIT</span>
              <span className="text-[#333333]">|</span>
              <span className="text-white">INITIALIZE DEVELOPER IDENTITY</span>
            </div>
            <div className="flex items-center gap-2 text-[#444444] text-[9px]">
              <span>NODE_ID: 0x9B4E</span>
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
              <div className="font-brand font-black text-white text-xl sm:text-2xl -tracking-[0.05em] uppercase">
                IDENTITY CONFIGURATION
              </div>
              <p className="font-sans text-[11px] text-[#666666] leading-relaxed">
                Crux compiles bare-metal collaborative buffers using cryptographic developer attestations. Register your identity to lock local memory rings and pair with mesh peers.
              </p>
            </div>

            {/* Error Message Display */}
            {errorMsg && (
              <div className="px-3 py-2 bg-[#111111] border-l-2 border-white text-white text-[10px] font-mono uppercase tracking-wider">
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleLaunch} className="space-y-4">
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

              {/* Mechanical Switch Submit Button */}
              <div className="pt-2">
                <button
                  type="submit"
                  className="w-full py-3 px-4 bg-white text-black font-brand font-black text-xs sm:text-sm -tracking-[0.02em] hover:bg-white hover:text-black hover:invert transition-none flex items-center justify-center gap-2 cursor-pointer"
                >
                  <span className="font-bold">INITIALIZE &amp; LAUNCH <span className="font-brand">Crex</span> KERNEL</span>
                  <span className="font-mono text-xs">❯</span>
                </button>
              </div>
            </form>
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
      </main>

      {/* 4. Bottom Footer Calibration (Z-20) */}
      <footer className="relative z-20 h-7 border-t border-[#222222] bg-[#000000] flex items-center justify-between px-3 text-[9px] font-mono text-[#444444] select-none">
        <div>[crex_dom_kernel // v1.2.0]</div>
        <div className="flex items-center gap-3">
          <span>ETNA SANS SERIF / ARIAL MT PRO</span>
          <span className="text-[#222222]">|</span>
          <span className="text-white">HARDWARE BRUTALISM</span>
        </div>
      </footer>
    </div>
  );
}
