"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { X, User, Key, Mail, Shield, Copy, Check, LogOut, Lock } from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";

export default function CruxIdentityDrawer() {
  const isIdentityDrawerOpen = useWorkspaceStore((state) => state.isIdentityDrawerOpen);
  const setIdentityDrawerOpen = useWorkspaceStore((state) => state.setIdentityDrawerOpen);
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);
  const viewerLock = useWorkspaceStore((state) => state.viewerLock);
  const toggleViewerLock = useWorkspaceStore((state) => state.toggleViewerLock);
  const accessLevel = useWorkspaceStore((state) => state.accessLevel);
  const setAccessLevel = useWorkspaceStore((state) => state.setAccessLevel);

  const [copied, setCopied] = useState(false);

  if (!isIdentityDrawerOpen) return null;

  const handleCopyUid = () => {
    if (typeof window !== "undefined" && currentUser.uid) {
      navigator.clipboard?.writeText(currentUser.uid);
      setCopied(true);
      triggerHaptic("tap");
      setTimeout(() => setCopied(false), 1200);
    }
  };

  const handleReOnboard = () => {
    triggerHaptic("toggle");
    setIdentityDrawerOpen(false);
    setOnboarded(false);
  };

  return (
    <div className="fixed inset-0 z-[100] bg-black/80 flex items-center justify-center p-4 font-sans select-none animate-in fade-in duration-150">
      <div className="w-full max-w-md bg-surface border border-grid shadow-[4px_4px_0px_#222222] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="h-11 px-4 border-b border-grid bg-void flex items-center justify-between">
          <div className="flex items-center gap-2">
            <User className="w-3.5 h-3.5 text-accent1" />
            <span className="text-xs font-bold uppercase tracking-widest text-signal">
              Developer Identity // Node Key
            </span>
          </div>
          <button
            onClick={() => setIdentityDrawerOpen(false)}
            className="text-muted hover:text-signal p-1 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4">
          {/* Identity Card */}
          <div className="p-4 bg-void border border-grid space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase text-muted tracking-wider">DEVELOPER</span>
              <span className="text-signal font-bold">{currentUser.name}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase text-muted tracking-wider">EMAIL</span>
              <span className="text-muted">{currentUser.email || "principal@crux.dev"}</span>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-grid">
              <div className="space-y-0.5">
                <span className="text-[10px] uppercase text-muted tracking-wider block">USER ID</span>
                <span className="text-sm font-bold text-white tracking-wide">{currentUser.uid || "CRX-7447-HG"}</span>
              </div>
              <button
                onClick={handleCopyUid}
                className="px-2.5 py-1 border border-grid hover:border-signal text-[10.5px] font-mono text-muted hover:text-signal flex items-center gap-1 uppercase transition-colors"
              >
                {copied ? <Check className="w-3 h-3 text-[#00FF00]" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? "Copied" : "Copy UID"}</span>
              </button>
            </div>
          </div>

          {/* Access Level and Viewer Lock Controls */}
          <div className="p-3 bg-void border border-grid space-y-2.5 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-[10.5px] uppercase text-muted tracking-wider">SESSION ACCESS:</span>
              <span className="text-[#00FF00] font-bold uppercase">{accessLevel.toUpperCase()} ACCESS</span>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-grid">
              <div className="space-y-0.5">
                <span className="text-[10.5px] uppercase text-muted tracking-wider block">VIEWER LOCK:</span>
                <span className="text-[10px] text-muted">Freeze writes across entire workspace</span>
              </div>
              <button
                onClick={toggleViewerLock}
                className={`px-3 py-1 text-xs font-bold uppercase border transition-colors ${
                  viewerLock
                    ? "bg-accent2 text-signal border-accent2"
                    : "bg-surface text-muted border-grid hover:text-signal"
                }`}
              >
                {viewerLock ? "LOCKED" : "UNLOCKED"}
              </button>
            </div>
          </div>

          {/* Re-onboard / Switch User Button */}
          <div className="pt-2 flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={handleReOnboard}
              className="w-full py-2 px-3 border border-grid hover:border-accent2 text-muted hover:text-accent2 text-xs font-mono uppercase tracking-wider flex items-center justify-center gap-2 transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Switch Identity / Re-Onboard</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
