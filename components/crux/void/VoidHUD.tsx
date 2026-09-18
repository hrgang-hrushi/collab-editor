"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import CruxBrandLogo from "../CruxBrandLogo";
import { Users, Wifi, Shield, Copy, Check } from "lucide-react";

export default function VoidHUD({
  onSelectPeer,
}: {
  onSelectPeer?: (peerName: string, fileId: string) => void;
}) {
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const remoteCursors = useWorkspaceStore((state) => state.remoteCursors);
  const [showRadarDropdown, setShowRadarDropdown] = useState(false);
  const [copiedUid, setCopiedUid] = useState(false);

  const activePeerList = Object.values(remoteCursors);

  const handleCopy = () => {
    if (typeof window !== "undefined" && currentUser.uid) {
      navigator.clipboard?.writeText(currentUser.uid);
      setCopiedUid(true);
      setTimeout(() => setCopiedUid(false), 1200);
    }
  };

  return (
    <header className="absolute top-0 inset-x-0 h-10 px-4 flex items-center justify-between border-b border-[#141414] bg-[#020202]/80 backdrop-blur-sm z-20 select-none text-[11px] font-mono">
      {/* Left: Engine & Daemon Status */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <CruxBrandLogo size={14} withText={false} />
          <span className="font-bold text-white tracking-widest uppercase">CRUX</span>
        </div>
        <span className="text-[#333333]">/</span>
        <div className="flex items-center gap-1.5 text-[#888888]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00FF66] shadow-[0_0_6px_#00FF66]" />
          <span>DAEMON: 0.04ms</span>
        </div>
        <span className="hidden sm:inline text-[#333333]">/</span>
        <span className="hidden sm:inline text-[#555555]">IPC MESH: AES-256</span>
      </div>

      {/* Right: Multiplayer Radar & Identity */}
      <div className="flex items-center gap-3">
        {/* Radar Peer Dropdown Trigger */}
        <div className="relative">
          <button
            onClick={() => setShowRadarDropdown(!showRadarDropdown)}
            className="flex items-center gap-1.5 px-2 py-1 border border-[#222222] bg-[#0a0a0a] hover:bg-[#111111] hover:border-[#333333] transition-colors text-white text-[11px]"
            title="Multiplayer Radar: Active Mesh Sessions"
          >
            <Users className="w-3 h-3 text-[#007AFF]" />
            <span className="text-[10px] tracking-wider uppercase font-medium">
              {activePeerList.length} PEERS LIVE
            </span>
            <span className="w-1.5 h-1.5 rounded-full bg-[#007AFF] animate-pulse" />
          </button>

          {/* Radar Dropdown */}
          {showRadarDropdown && (
            <div className="absolute right-0 mt-1 w-64 border border-[#222222] bg-[#050505] p-2 shadow-2xl z-30 space-y-1">
              <div className="px-2 py-1 text-[10px] text-[#555555] uppercase tracking-wider border-b border-[#161616] flex justify-between">
                <span>Multiplayer Radar</span>
                <span>Drop-in Live</span>
              </div>
              {activePeerList.map((p) => (
                <div
                  key={p.userId}
                  onClick={() => {
                    setShowRadarDropdown(false);
                    onSelectPeer?.(p.userName, p.activeFileId || "file-stream-syncer");
                  }}
                  className="px-2 py-1.5 flex items-center justify-between hover:bg-[#111111] cursor-pointer transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: p.userColor }}
                    />
                    <span className="text-white font-sans text-xs">{p.userName}</span>
                  </div>
                  <span className="text-[10px] text-[#666666] font-mono">
                    {(p.activeFileId || "").replace("file-", "")}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Identity Chip */}
        <div
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2 py-1 border border-[#1a1a1a] hover:border-[#2a2a2a] bg-[#050505] cursor-pointer text-[#888888] hover:text-white transition-colors text-[10px]"
          title="Click to copy encrypted developer UID"
        >
          <span className="text-[#555555]">UID:</span>
          <span>{currentUser.uid || "CRX-7447-HG"}</span>
          {copiedUid ? (
            <Check className="w-2.5 h-2.5 text-[#00FF66]" />
          ) : (
            <Copy className="w-2.5 h-2.5 text-[#444444]" />
          )}
        </div>
      </div>
    </header>
  );
}
