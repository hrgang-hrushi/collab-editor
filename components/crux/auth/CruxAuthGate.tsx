"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick, playMechanicalEnter } from "@/lib/sound";

interface CruxAuthGateProps {
  onSuccess?: () => void;
  onCancel?: () => void;
}

export default function CruxAuthGate({ onSuccess, onCancel }: CruxAuthGateProps) {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "transmitting" | "success">("idle");
  const [statusMsg, setStatusMsg] = useState("");

  const setUserProfile = useWorkspaceStore((state) => state.setUserProfile);
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);

  const handleOAuth = (provider: "github" | "google") => {
    playMechanicalClick("mid");
    triggerHaptic("tap");
    setStatus("transmitting");
    setStatusMsg(`[CONNECTING_TO_${provider.toUpperCase()}_GATEWAY...]`);

    setTimeout(() => {
      const generatedName = provider === "github" ? "dev_octo" : "sec_node";
      setUserProfile({
        name: generatedName,
        email: `${generatedName}@${provider}.auth`,
        color: "#FFFFFF",
      });
      setOnboarded(true);
      if (onSuccess) {
        onSuccess();
      } else if (typeof window !== "undefined") {
        window.location.href = "/?mode=edit";
      }
    }, 600);
  };

  const handleMagicLinkSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!email.trim() || !email.includes("@")) {
      setStatusMsg("[ERR: INVALID_IDENTITY_FORMAT]");
      triggerHaptic("error");
      playMechanicalClick("low");
      return;
    }

    playMechanicalEnter();
    triggerHaptic("click");
    setStatus("transmitting");
    setStatusMsg("[DISPATCHING_CRYPTOGRAPHIC_MAGIC_LINK...]");

    setTimeout(() => {
      setStatus("success");
      setStatusMsg(`[LINK_TRANSMITTED_TO_${email.toUpperCase()}]`);

      // Authorize session
      const username = email.split("@")[0].toLowerCase().replace(/[^a-z0-9_]/g, "_");
      setUserProfile({
        name: username || "kernel_user",
        email: email.trim(),
        color: "#FFFFFF",
      });

      setTimeout(() => {
        setOnboarded(true);
        if (onSuccess) {
          onSuccess();
        } else if (typeof window !== "undefined") {
          window.location.href = "/?mode=edit";
        }
      }, 1000);
    }, 600);
  };

  return (
    <div className="w-full max-w-sm flex flex-col gap-1 select-none font-sans">
      {/* Top Header Label: sitting right above the border box */}
      <div className="flex items-center justify-between px-0.5">
        <span className="font-sans text-[10px] text-[#888888] uppercase tracking-wider text-left">
          [SYSTEM_AUTH_REQUIRED]
        </span>
        {onCancel && (
          <button
            type="button"
            onClick={() => {
              playMechanicalClick("low");
              onCancel();
            }}
            className="font-mono text-[9px] text-[#666666] hover:text-white uppercase transition-none cursor-pointer"
          >
            [ESC // ABORT]
          </button>
        )}
      </div>

      {/* Main Stark Container */}
      <div className="w-full bg-[#0A0A0A] border border-[#222222] p-4 flex flex-col gap-3 rounded-none">
        {/* 1. GitHub OAuth Button */}
        <button
          type="button"
          onClick={() => handleOAuth("github")}
          className="h-10 w-full border border-[#222222] bg-transparent text-[#888888] flex items-center justify-center gap-3 font-mono text-[11px] uppercase tracking-widest transition-none cursor-pointer rounded-none hover:bg-white hover:text-black hover:border-white"
        >
          {/* Monochrome GitHub SVG Icon: pure #888888, fills black on button hover via currentColor */}
          <svg
            className="w-4 h-4 fill-current transition-none shrink-0"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path
              fillRule="evenodd"
              clipRule="evenodd"
              d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
            />
          </svg>
          <span>INITIATE GITHUB OAUTH</span>
        </button>

        {/* 2. Google OAuth Button */}
        <button
          type="button"
          onClick={() => handleOAuth("google")}
          className="h-10 w-full border border-[#222222] bg-transparent text-[#888888] flex items-center justify-center gap-3 font-mono text-[11px] uppercase tracking-widest transition-none cursor-pointer rounded-none hover:bg-white hover:text-black hover:border-white"
        >
          {/* Flat Monochrome Google SVG Icon: forbidden from colorful brand styling */}
          <svg
            className="w-4 h-4 fill-current transition-none shrink-0"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path d="M12.24 10.285V14.4h6.887C18.2 16.55 16.14 18.8 12.24 18.8c-3.79 0-6.86-3.08-6.86-6.8s3.07-6.8 6.86-6.8c1.78 0 3.12.68 4.09 1.57l3.07-3.07C17.48 2.05 14.99 1.2 12.24 1.2 6.27 1.2 1.44 6.03 1.44 12s4.83 10.8 10.8 10.8c6.24 0 10.36-4.38 10.36-10.55 0-.74-.08-1.3-.23-1.965H12.24z" />
          </svg>
          <span>INITIATE GOOGLE OAUTH</span>
        </button>

        {/* 3. Horizontal Divider with embedded OR */}
        <div className="relative flex items-center justify-center py-2 select-none">
          <div className="w-full border-t border-[#222222]" />
          <span className="absolute bg-[#0A0A0A] px-2 font-mono text-[10px] text-[#444444] uppercase tracking-widest">
            OR
          </span>
        </div>

        {/* 4. CLI Terminal Style Email Input & Form */}
        <form onSubmit={handleMagicLinkSubmit} className="flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="> enter_secure_email@domain.com_"
              className="bg-transparent border-b border-[#222222] focus:border-white outline-none w-full text-white font-mono text-[12px] py-2 rounded-none transition-none placeholder:text-[#444444]"
              autoComplete="email"
              required
            />
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={status === "transmitting"}
            className="h-10 w-full bg-white text-black font-sans font-bold text-[11px] uppercase tracking-wider rounded-none hover:invert transition-none flex items-center justify-center cursor-pointer disabled:opacity-50"
          >
            <span>TRANSMIT MAGIC LINK ↵</span>
          </button>
        </form>

        {/* Telemetry Status Line (When active) */}
        {statusMsg && (
          <div className="pt-1 border-t border-[#181818] font-mono text-[9px] text-[#888888] flex items-center justify-between">
            <span className="truncate">{statusMsg}</span>
            <span className="w-1.5 h-1.5 bg-white animate-hard-blink shrink-0" />
          </div>
        )}
      </div>
    </div>
  );
}
