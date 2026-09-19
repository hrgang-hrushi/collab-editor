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
  const activeUsers = useWorkspaceStore((state) => state.activeUsers);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const toggleDrone = useWorkspaceStore((state) => state.toggleDrone);
  const setShareModalOpen = useWorkspaceStore((state) => state.setShareModalOpen);

  const getInitials = (name: string) => {
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  };

  const activePeers: PresencePeer[] = React.useMemo(() => {
    if (propPeers && propPeers.length > 0) return propPeers;

    const selfName = currentUser?.name || "Local Operator";
    const selfPeer: PresencePeer = {
      id: "peer-self",
      name: selfName,
      initials: getInitials(selfName),
      isSelf: true,
      uid: currentUser?.uid || "CRX-LOCAL",
    };

    const peersList: PresencePeer[] = [selfPeer];

    // Dynamically pull live peers from Yjs awareness
    if (activeUsers && activeUsers.length > 0) {
      const seen = new Set<string>([selfPeer.name.toLowerCase()]);
      activeUsers.forEach((u) => {
        if (u.isSelf || u.id === currentUser?.uid || seen.has(u.name.toLowerCase())) return;
        seen.add(u.name.toLowerCase());
        peersList.push({
          id: u.id,
          name: u.name,
          initials: getInitials(u.name),
          isSelf: false,
          uid: u.uid,
          activeFileId: u.activeFileId,
        });
      });
    }

    return peersList;
  }, [propPeers, activeUsers, currentUser]);

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
                ? `${peer.name} (You) · Click to share`
                : `${peer.name} (${peer.uid || "Remote Peer"}) · Click to view active file`
            }
            className={`px-2 py-1 font-mono text-[10px] uppercase tracking-widest leading-none border-r border-[#222222] rounded-none transition-none ${
              isLocal
                ? "bg-white text-black font-bold cursor-pointer"
                : "bg-transparent text-[#888888] hover:text-white cursor-pointer"
            }`}
          >
            {peer.initials}
          </button>
        );
      })}

      {/* Actionable Share Trigger */}
      <button
        type="button"
        onClick={() => {
          playMechanicalClick("high");
          triggerHaptic("click");
          setShareModalOpen(true);
        }}
        title="Share workspace or invite peers"
        className="px-2 py-1 font-mono text-[10px] uppercase tracking-wider leading-none text-[#888888] hover:text-white hover:bg-[#111111] transition-none cursor-pointer"
      >
        {activePeers.length === 1 ? "+ SHARE" : "+"}
      </button>
    </div>
  );
}
