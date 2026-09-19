"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { X, Mail, Check, Trash2, Lock, ArrowRight, ShieldCheck, Sparkles, RefreshCw } from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";

export default function CruxInboxModal() {
  const isInboxOpen = useWorkspaceStore((state) => state.isInboxOpen);
  const setInboxOpen = useWorkspaceStore((state) => state.setInboxOpen);
  const inboxInvites = useWorkspaceStore((state) => state.inboxInvites);
  const acceptInvite = useWorkspaceStore((state) => state.acceptInvite);
  const declineInvite = useWorkspaceStore((state) => state.declineInvite);
  const sendInvite = useWorkspaceStore((state) => state.sendInvite);
  const currentUser = useWorkspaceStore((state) => state.currentUser);

  const [toastMsg, setToastMsg] = useState("");

  if (!isInboxOpen) return null;

  const handleAccept = (inviteId: string) => {
    triggerHaptic("click");
    acceptInvite(inviteId);
    setToastMsg("Accepted invitation. Connecting to collaborative session...");
    setTimeout(() => {
      setToastMsg("");
      setInboxOpen(false);
    }, 1000);
  };

  const handleDecline = (inviteId: string) => {
    triggerHaptic("tap");
    declineInvite(inviteId);
  };

  const handleSimulateInvite = () => {
    triggerHaptic("toggle");
    sendInvite({
      senderName: "Sarah Lin",
      senderUid: "CRX-9941-SL",
      senderEmail: "sarah@crux.dev",
      recipientUidOrEmail: currentUser.uid || "CRX-7447-HG",
      workspaceName: "crux-stream-sync",
      accessLevel: "limited",
      allowedFiles: ["stream_syncer.ts"],
      allowedLineRange: { start: 1, end: 20 },
      viewerLock: false,
    });
    setToastMsg("Simulated incoming workspace invitation received!");
    setTimeout(() => setToastMsg(""), 1500);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4 font-sans select-none animate-in fade-in duration-150">
      <div className="w-full max-w-lg bg-surface border border-grid shadow-[4px_4px_0px_#222222] flex flex-col max-h-[85vh] overflow-hidden">
        {/* Header */}
        <div className="h-11 px-4 border-b border-grid bg-void flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <Mail className="w-3.5 h-3.5 text-accent1" />
            <span className="text-xs font-bold uppercase tracking-widest text-signal">
              Collaborative Inbox // Workspace Invites
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 bg-grid text-signal">
              {inboxInvites.filter((i) => i.status === "pending").length} Pending
            </span>
          </div>
          <button
            onClick={() => setInboxOpen(false)}
            className="text-muted hover:text-signal p-1 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {toastMsg && (
          <div className="p-2.5 bg-[#00FF00]/10 border-b border-[#00FF00]/30 text-[#00FF00] text-xs font-mono shrink-0">
            {toastMsg}
          </div>
        )}

        {/* Invites List */}
        <div className="p-5 space-y-3 overflow-y-auto flex-1">
          {inboxInvites.length === 0 ? (
            <div className="py-12 text-center text-muted font-mono text-xs space-y-2">
              <Mail className="w-8 h-8 mx-auto text-grid opacity-50" />
              <div>INBOX ZERO // NO PENDING INVITATIONS</div>
              <p className="text-[11px] text-muted/70 max-w-xs mx-auto">
                When teammates dispatch share invites via UID or email, they land directly in this inbox.
              </p>
            </div>
          ) : (
            inboxInvites.map((invite) => {
              const isPending = invite.status === "pending";
              const isAccepted = invite.status === "accepted";
              const isDeclined = invite.status === "declined";

              return (
                <div
                  key={invite.id}
                  className={`p-3.5 border transition-colors space-y-2.5 ${
                    isAccepted
                      ? "bg-void border-[#00FF00]/40 opacity-90"
                      : isDeclined
                      ? "bg-void border-grid opacity-50"
                      : "bg-void border-grid hover:border-signal"
                  }`}
                >
                  {/* Top Meta Row */}
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 bg-accent1 text-void text-[10px] font-mono font-bold">
                        {invite.senderName}
                      </span>
                      <span className="text-[10px] font-mono text-muted">
                        ({invite.senderUid})
                      </span>
                    </div>

                    <span className="text-[10px] font-mono text-muted">
                      {Math.max(1, Math.floor((Date.now() - invite.timestamp) / (1000 * 60)))}m ago
                    </span>
                  </div>

                  {/* Workspace & Access Details */}
                  <div className="space-y-1 font-mono text-xs">
                    <div className="text-signal font-semibold text-[13px]">
                      Workspace: <span className="text-accent1">{invite.workspaceName}</span>
                    </div>

                    <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
                      {invite.accessLevel === "full" && (
                        <span className="px-2 py-0.5 text-[9.5px] border border-[#00FF00]/40 text-[#00FF00] bg-black">
                          FULL ACCESS (READ &amp; WRITE)
                        </span>
                      )}
                      {invite.accessLevel === "limited" && (
                        <span className="px-2 py-0.5 text-[9.5px] border border-accent1/40 text-accent1 bg-black">
                          LIMITED: {invite.allowedFiles?.join(", ") || "Specific files"}
                          {invite.allowedLineRange ? ` (Lines ${invite.allowedLineRange.start}-${invite.allowedLineRange.end})` : ""}
                        </span>
                      )}
                      {invite.accessLevel === "viewer" && (
                        <span className="px-2 py-0.5 text-[9.5px] border border-grid text-muted bg-black">
                          VIEWER (READ-ONLY)
                        </span>
                      )}

                      {invite.viewerLock && (
                        <span className="px-2 py-0.5 text-[9.5px] border border-accent2/40 text-accent2 bg-black flex items-center gap-1">
                          <Lock className="w-2.5 h-2.5" />
                          <span>VIEWER LOCK ENGAGED</span>
                        </span>
                      )}
                    </div>

                    <div className="text-[10px] text-muted pt-1">
                      Recipient: <span className="text-signal">{invite.recipientUidOrEmail}</span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-between pt-1 border-t border-grid">
                    <div className="text-[10px] font-mono">
                      {isAccepted && <span className="text-[#00FF00]">CONNECTED (ACTIVE)</span>}
                      {isDeclined && <span className="text-muted">DECLINED</span>}
                      {isPending && <span className="text-muted">PENDING RESPONSE</span>}
                    </div>

                    {isPending && (
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleDecline(invite.id)}
                          className="px-3 py-1 text-[11px] font-mono border border-grid text-muted hover:text-accent2 transition-colors uppercase"
                        >
                          Decline
                        </button>
                        <button
                          type="button"
                          onClick={() => handleAccept(invite.id)}
                          className="px-3 py-1 text-[11px] font-mono border border-grid bg-signal text-void font-bold hover:opacity-90 transition-opacity uppercase flex items-center gap-1"
                        >
                          <Check className="w-3 h-3" />
                          <span>Accept &amp; Connect</span>
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer with Simulation Trigger */}
        <div className="p-3 border-t border-grid bg-void flex items-center justify-between text-xs shrink-0 font-mono">
          <button
            type="button"
            onClick={handleSimulateInvite}
            className="text-[10.5px] text-muted hover:text-signal flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className="w-3 h-3 text-accent1" />
            <span>+ Simulate Incoming Invite from Sarah L.</span>
          </button>

          <button
            type="button"
            onClick={() => setInboxOpen(false)}
            className="px-3 py-1 text-[11px] border border-grid text-signal hover:bg-grid uppercase"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
