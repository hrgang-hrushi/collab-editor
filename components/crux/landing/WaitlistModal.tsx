"use client";

import React, { useState } from "react";
import { X, Check, ArrowRight, ShieldCheck, Terminal } from "lucide-react";
import confetti from "canvas-confetti";
import CruxBrandLogo from "../CruxBrandLogo";
import CallChip from "@/components/ui/CallChip";

interface WaitlistModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const ROLES = [
  { id: "systems", label: "Systems & Rust Engineer" },
  { id: "fullstack", label: "Full-Stack Architect" },
  { id: "ai", label: "Autonomous Agent Developer" },
  { id: "founder", label: "Founder / CTO" },
];

export default function WaitlistModal({ isOpen, onClose }: WaitlistModalProps) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("systems");
  const [arch, setArch] = useState<"apple_silicon" | "intel" | "linux">("apple_silicon");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [chipStage, setChipStage] = useState<"idle" | "almost" | "gone" | "done">("idle");

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes("@")) return;

    setLoading(true);
    setChipStage("almost");

    setTimeout(() => {
      setChipStage("gone");
    }, 900);

    setTimeout(() => {
      setLoading(false);
      setChipStage("done");
      setTimeout(() => {
        setSubmitted(true);
      }, 700);

      // Trigger celebratory monochrome confetti burst
      try {
        confetti({
          particleCount: 80,
          spread: 70,
          origin: { y: 0.6 },
          colors: ["#ffffff", "#cccccc", "#888888", "#222222"],
        });
      } catch {
        // Fallback gracefully
      }

      try {
        const stored = JSON.parse(localStorage.getItem("crux_waitlist") || "[]");
        stored.push({ email, role, arch, timestamp: Date.now() });
        localStorage.setItem("crux_waitlist", JSON.stringify(stored));
      } catch {
        // LocalStorage fallback
      }
    }, 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90">
      <div
        className="relative w-full max-w-lg rounded-none bg-[#000000] border border-[#222222] p-7 sm:p-9 text-white overflow-hidden"
        style={{
          fontFamily: '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif',
        }}
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-1.5 rounded-none text-[#888888] hover:text-white hover:bg-[#111111] border border-transparent hover:border-[#222222] transition-none cursor-pointer"
          aria-label="Close modal"
        >
          <X className="w-4 h-4" />
        </button>

        {!submitted ? (
          <form onSubmit={handleSubmit} className="space-y-6 relative z-10">
            {/* Header */}
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <CruxBrandLogo size={18} withText={true} />
                <span className="text-[10px] font-mono text-white px-2 py-0.5 border border-[#222222] bg-[#111111]">
                  [PRIVATE PREVIEW]
                </span>
              </div>
              <h3 className="text-2xl font-bold tracking-tight text-white font-sans">
                Request Early Access to Crux
              </h3>
              <p className="text-xs text-[#888888] leading-relaxed font-sans">
                Join elite systems engineers and architects testing the native Rust/WebGPU desktop IDE before public v1.0.
              </p>
            </div>

            {/* Email Input */}
            <div className="space-y-2">
              <label className="block text-xs font-semibold uppercase tracking-wider text-[#888888] font-mono">
                Work or GitHub Email
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="developer@company.com"
                className="w-full px-4 py-3 rounded-none bg-[#111111] border border-[#222222] text-white placeholder-[#444444] text-xs font-mono focus:outline-none focus:border-white transition-none"
              />
            </div>

            {/* Developer Role Selection */}
            <div className="space-y-2">
              <label className="block text-xs font-semibold uppercase tracking-wider text-[#888888] font-mono">
                Primary Engineering Domain
              </label>
              <div className="grid grid-cols-2 gap-2">
                {ROLES.map((r) => (
                  <button
                    key={r.id}
                    type="button"
                    onClick={() => setRole(r.id)}
                    className={`px-3 py-2 rounded-none text-xs text-left transition-none border font-mono cursor-pointer ${
                      role === r.id
                        ? "bg-white text-black border-white font-bold"
                        : "bg-[#111111] border-[#222222] text-[#888888] hover:text-white"
                    }`}
                  >
                    {r.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Hardware Architecture Selector */}
            <div className="space-y-2">
              <label className="block text-xs font-semibold uppercase tracking-wider text-[#888888] font-mono">
                Target Hardware Architecture
              </label>
              <div className="flex gap-2">
                {[
                  { id: "apple_silicon", label: "Apple Silicon (Metal)" },
                  { id: "intel", label: "Intel x86_64" },
                  { id: "linux", label: "Linux (Vulkan)" },
                ].map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setArch(item.id as any)}
                    className={`flex-1 py-1.5 px-2 rounded-none text-[11px] text-center border transition-none font-mono cursor-pointer ${
                      arch === item.id
                        ? "bg-white text-black font-bold border-white"
                        : "bg-[#111111] border-[#222222] text-[#888888] hover:text-white"
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Submit CTA or CallChip */}
            {chipStage !== "idle" && !submitted ? (
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                className="w-full h-14 bg-[#111111] border border-[#222222] flex items-center justify-between px-3 sm:px-4"
              >
                <CallChip
                  icon="terminal"
                  name="Waitlist"
                  argument={
                    chipStage === "almost"
                      ? "Almost there..."
                      : chipStage === "gone"
                      ? "Going through..."
                      : "Done! See ya at Crux!"
                  }
                  status={chipStage === "done" ? "done" : "running"}
                  expectedMs={2000}
                  size={35}
                  radius={10}
                  color="currentColor"
                  surfaceColor="#27272a"
                  progressColor="currentColor"
                  progressOpacity={0.26}
                  doneColor="#22c55e"
                  errorColor="#ef4444"
                  washOpacity={0.18}
                  shake={9}
                  showTimer
                />
                <div className="flex items-center gap-2 font-mono text-xs text-[#888888] shrink-0 select-none">
                  <span
                    className={`w-1.5 h-1.5 ${
                      chipStage === "done" ? "bg-[#22c55e]" : "bg-[#0055FF] animate-pulse"
                    }`}
                  />
                  <span>{chipStage === "done" ? "TOKEN RESERVED" : "SECURE DISPATCH"}</span>
                </div>
              </motion.div>
            ) : (
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3.5 px-4 rounded-none bg-white hover:bg-[#111111] hover:text-white border border-white text-black font-bold text-xs uppercase tracking-wider transition-none flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                <span>Claim Priority Waitlist Spot</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}

            <div className="flex items-center justify-between text-[11px] text-[#444444] pt-2 border-t border-[#222222] font-mono">
              <span className="flex items-center gap-1.5 text-[#888888]">
                <ShieldCheck className="w-3.5 h-3.5 text-white" />
                <span>Zero telemetry lock-in</span>
              </span>
              <span>Rolling access weekly</span>
            </div>
          </form>
        ) : (
          <div className="py-6 text-center space-y-5 relative z-10 font-mono">
            <div className="flex justify-center pb-1">
              <CallChip
                icon="terminal"
                name="Waitlist"
                argument="Done! See ya at Crux!"
                status="done"
                expectedMs={2000}
                size={35}
                radius={10}
                color="currentColor"
                surfaceColor="#27272a"
                progressColor="currentColor"
                progressOpacity={0.26}
                doneColor="#22c55e"
                errorColor="#ef4444"
                washOpacity={0.18}
                shake={9}
                showTimer={false}
              />
            </div>
            <div className="space-y-2">
              <h4 className="text-xl font-bold text-white font-sans">You're on the Crux Priority Roster</h4>
              <p className="text-xs text-[#888888] max-w-sm mx-auto leading-relaxed font-sans">
                We've reserved your early build access token for <span className="text-white font-mono">{email}</span>. You will receive an invitation when the next macOS build drops.
              </p>
            </div>
            <div className="p-3.5 rounded-none bg-[#111111] border border-[#222222] text-xs font-mono text-white inline-block">
              Priority Ticket: #CRUX-{Math.floor(1000 + Math.random() * 9000)} · Priority Roster
            </div>
            <div>
              <button
                onClick={onClose}
                className="px-6 py-2.5 rounded-none bg-white hover:bg-[#111111] hover:text-white text-black text-xs font-bold uppercase transition-none cursor-pointer"
              >
                Close &amp; Return to Overview
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
