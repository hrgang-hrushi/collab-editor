"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";

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
    <header className="absolute top-0 inset-x-0 h-8 px-2 flex items-center justify-between border-b border-[#222222] bg-[#000000] z-50 select-none text-[11px] font-sans">
      {/* Left: Brand & Silicon Daemon Status */}
      <div className="flex items-center gap-2">
        <span className="font-brand font-black text-white -tracking-[0.05em] text-xs">
          Crux
        </span>
        <span className="text-[#222222]">|</span>
        <span className="font-mono text-[10px] text-[#444444]">
          [DAEMON: 0.04ms]
        </span>
        <span className="text-[#222222]">|</span>
        <span className="font-mono text-[10px] text-[#444444]">
          [BARE-METAL DOM KERNEL]
        </span>
      </div>

      {/* Right: Multiplayer Radar & Identity (Tactile Mechanical Inversion) */}
      <div className="flex items-center gap-2">
        {/* Radar Dropdown Toggle */}
        <div className="relative">
          <button
            onClick={() => setShowRadarDropdown(!showRadarDropdown)}
            className="px-2 py-0.5 border border-[#222222] bg-[#000000] text-white hover:bg-white hover:text-black transition-none text-[10px] font-mono uppercase flex items-center gap-1.5"
          >
            <span>[{activePeerList.length} PEERS]</span>
            <span className="inline-block w-1.5 h-1.5 bg-white animate-hard-blink" />
            <span>[LIVE]</span>
          </button>

          {showRadarDropdown && (
            <div className="absolute right-0 mt-[1px] w-64 border border-[#222222] bg-[#000000] p-1 z-50 space-y-1">
              <div className="px-1 py-0.5 text-[9px] text-[#444444] uppercase font-mono border-b border-[#222222] flex justify-between">
                <span>RADAR SESSIONS</span>
                <span>DIRECT SPECTATE</span>
              </div>
              {activePeerList.map((p) => (
                <div
                  key={p.userId}
                  onClick={() => {
                    setShowRadarDropdown(false);
                    onSelectPeer?.(p.userName, p.activeFileId || "file-stream-syncer");
                  }}
                  className="px-1.5 py-1 flex items-center justify-between border border-transparent hover:border-[#222222] hover:bg-white hover:text-black cursor-pointer transition-none text-[11px]"
                >
                  <div className="flex items-center gap-1.5 font-sans font-medium uppercase">
                    <span>[{p.userName}]</span>
                  </div>
                  <span className="text-[10px] font-mono">
                    {(p.activeFileId || "").replace("file-", "")}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Identity Chip */}
        <button
          onClick={handleCopy}
          className="px-2 py-0.5 border border-[#222222] bg-[#000000] text-white hover:bg-white hover:text-black transition-none text-[10px] font-mono uppercase"
        >
          {copiedUid ? "[ENCLAVE KEY COPIED]" : `[UID: ${currentUser.uid || "CRX-7447-HG"}]`}
        </button>
      </div>
    </header>
  );
}
