"use client";

import React from "react";
import { useWorkspaceStore } from "@/lib/store";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick } from "@/lib/sound";

export interface PresencePeer {
  id: string;
  name: string;
  initials: string;
  isSelf: boolean;
  uid?: string;
  activeFileId?: string;
}

interface CruxMultiplayerPresenceProps {
  className?: string;
  peers?: PresencePeer[];
}

export default function CruxMultiplayerPresence({
  className = "",
  peers: propPeers,
}: CruxMultiplayerPresenceProps) {
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const toggleDrone = useWorkspaceStore((state) => state.toggleDrone);
  const setShareModalOpen = useWorkspaceStore((state) => state.setShareModalOpen);

  // Default presence cells adhering strictly to Hardware Brutalism
  // Local User: "SL" (or active operator), bg-white text-black
  // Remote Peers: "MV", "AI", bg-transparent text-[#888888] hover:text-white
  const defaultPeers: PresencePeer[] = [
    {
      id: "peer-self",
      name: currentUser?.name || "Sarah Lin",
      initials: "SL",
      isSelf: true,
      uid: currentUser?.uid || "CRX-9941-SL",
    },
    {
      id: "peer-mv",
      name: "Marcus Vance",
      initials: "MV",
      isSelf: false,
      uid: "CRX-5520-MV",
      activeFileId: "file-auth",
    },
    {
      id: "peer-ai",
      name: "CruxAI Copilot",
      initials: "AI",
      isSelf: false,
      uid: "CRX-0001-AI",
    },
  ];

  const activePeers = propPeers && propPeers.length > 0 ? propPeers : defaultPeers;

  const handlePeerClick = (peer: PresencePeer) => {
    playMechanicalClick("high");
    triggerHaptic("click");

    if (peer.isSelf) {
      setShareModalOpen(true);
      return;
    }

    if (peer.initials === "AI" || peer.name.toLowerCase().includes("ai")) {
      toggleDrone();
      return;
    }

    if (peer.activeFileId) {
      openTab(peer.activeFileId);
      setActiveFile(peer.activeFileId);
    } else {
      setShareModalOpen(true);
    }
  };

  return (
    <div
      role="group"
      aria-label="Active Collaborators"
      className={`flex items-center border border-[#222222] rounded-none select-none bg-black ${className}`}
    >
      {activePeers.map((peer, idx) => {
        const isLocal = peer.isSelf || idx === 0;
        return (
          <button
            key={peer.id || idx}
            type="button"
            onClick={() => handlePeerClick(peer)}
            title={
              isLocal
                ? `${peer.name} (You) · ${peer.uid || "Local"}`
                : `${peer.name} (${peer.uid || "Remote Peer"}) · Click to jump to cursor`
            }
            className={`px-2 py-1 font-mono text-[10px] uppercase tracking-widest leading-none border-r border-[#222222] last:border-r-0 rounded-none transition-none ${
              isLocal
                ? "bg-white text-black font-bold cursor-pointer"
                : "bg-transparent text-[#888888] hover:text-white cursor-pointer"
            }`}
          >
            {peer.initials}
          </button>
        );
      })}
    </div>
  );
}
