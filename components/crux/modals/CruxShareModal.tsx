"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { X, Send, Lock, Shield, User, FileText, Check, AlertTriangle, Link2, Copy } from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";

export default function CruxShareModal() {
  const isShareModalOpen = useWorkspaceStore((state) => state.isShareModalOpen);
  const setShareModalOpen = useWorkspaceStore((state) => state.setShareModalOpen);
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const projectName = useWorkspaceStore((state) => state.projectName);
  const files = useWorkspaceStore((state) => state.files);
  const sendInvite = useWorkspaceStore((state) => state.sendInvite);
  const viewerLock = useWorkspaceStore((state) => state.viewerLock);
  const setViewerLock = useWorkspaceStore((state) => state.setViewerLock);

  const [targetIdOrEmail, setTargetIdOrEmail] = useState("");
  const [accessLevel, setAccessLevel] = useState<"full" | "limited" | "viewer">("full");
  const [selectedFiles, setSelectedFiles] = useState<string[]>(["stream_syncer.ts"]);
  const [startLine, setStartLine] = useState<number>(1);
  const [endLine, setEndLine] = useState<number>(50);
  const [localViewerLock, setLocalViewerLock] = useState<boolean>(viewerLock);
  const [sentToast, setSentToast] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [copiedMeshLink, setCopiedMeshLink] = useState(false);

  const handleCopyDirectMeshLink = () => {
    if (typeof window === "undefined") return;
    triggerHaptic("click");
    let url = window.location.href;
    if (!window.location.hash || !window.location.hash.startsWith("#session-")) {
      const randomSession = "session-" + Math.random().toString(36).substring(2, 9);
      url = `${window.location.origin}${window.location.pathname}#${randomSession}`;
      window.location.hash = randomSession;
    }
    navigator.clipboard.writeText(url);
    setCopiedMeshLink(true);
    setTimeout(() => setCopiedMeshLink(false), 2000);
  };

  if (!isShareModalOpen) return null;

  const handleToggleFile = (fileName: string) => {
    setSelectedFiles((prev) =>
      prev.includes(fileName)
        ? prev.filter((f) => f !== fileName)
        : [...prev, fileName]
    );
  };

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = targetIdOrEmail.trim();
    if (!trimmed) {
      setErrorMsg("Please enter a collaborator UID or email address.");
      return;
    }

    triggerHaptic("click");

    sendInvite({
      senderName: currentUser.name,
      senderUid: currentUser.uid || "CRX-7447-HG",
      senderEmail: currentUser.email || "principal@crux.dev",
      recipientUidOrEmail: trimmed,
      workspaceName: projectName,
      accessLevel,
      allowedFiles: accessLevel === "limited" ? selectedFiles : undefined,
      allowedLineRange: accessLevel === "limited" ? { start: startLine, end: endLine } : undefined,
      viewerLock: localViewerLock,
    });

    if (localViewerLock !== viewerLock) {
      setViewerLock(localViewerLock);
    }

    setSentToast(true);
    setTimeout(() => {
      setSentToast(false);
      setShareModalOpen(false);
    }, 1200);
  };

  const quickSelectPeer = (idOrEmail: string) => {
    setTargetIdOrEmail(idOrEmail);
    setErrorMsg("");
    triggerHaptic("tap");
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4 font-sans select-none animate-in fade-in duration-150">
      <div className="w-full max-w-lg bg-surface border border-grid shadow-[4px_4px_0px_#222222] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="h-11 px-4 border-b border-grid bg-void flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-white" />
            <span className="text-xs font-bold uppercase tracking-widest text-signal">
              Share Workspace
            </span>
          </div>
          <button
            onClick={() => setShareModalOpen(false)}
            className="text-muted hover:text-signal p-1 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={handleSend} className="p-5 space-y-4">
          {sentToast && (
            <div className="p-3 bg-[#00FF00]/10 border-l-2 border-[#00FF00] text-[#00FF00] text-xs font-mono flex items-center gap-2">
              <Check className="w-3.5 h-3.5" />
              <span>Invite successfully dispatched directly to {targetIdOrEmail}&apos;s inbox!</span>
            </div>
          )}

          {/* Direct Share Link Box */}
          <div className="p-3 bg-black border border-[#222222] flex items-center justify-between gap-3">
            <div className="space-y-0.5 min-w-0">
              <div className="flex items-center gap-1.5 text-white">
                <Link2 className="w-3.5 h-3.5 text-white" />
                <span className="text-xs font-bold uppercase font-mono tracking-wider">
                  Direct Collaboration Link
                </span>
              </div>
              <p className="text-[10px] text-[#888888] truncate font-mono">
                Real-time collaboration link · No sign-in required
              </p>
            </div>
            <button
              type="button"
              onClick={handleCopyDirectMeshLink}
              className={`px-3 py-1.5 text-[11px] font-mono uppercase tracking-wider border transition-none shrink-0 flex items-center gap-1.5 ${
                copiedMeshLink
                  ? "bg-white text-black border-white font-bold"
                  : "bg-black text-white border-[#222222] hover:bg-white hover:text-black"
              }`}
            >
              {copiedMeshLink ? (
                <>
                  <Check className="w-3 h-3 text-black" />
                  <span>COPIED</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>COPY LINK</span>
                </>
              )}
            </button>
          </div>

          {/* 1. Recipient UID or Email */}
          <div className="space-y-1.5">
            <label className="text-[10px] font-mono uppercase tracking-widest text-muted block">
              Collaborator UID or Email Address
            </label>
            <input
              type="text"
              value={targetIdOrEmail}
              onChange={(e) => {
                setTargetIdOrEmail(e.target.value);
                setErrorMsg("");
              }}
              placeholder="e.g. CRX-9941-SL or sarah@crux.dev"
              className="w-full bg-void border border-grid px-3 py-2 text-xs text-signal font-mono outline-none focus:border-signal"
              autoFocus
            />

            {/* Quick-Pick Peer Chips */}
            <div className="flex items-center gap-1.5 pt-1 overflow-x-auto">
              <span className="text-[9.5px] font-mono text-muted uppercase">Peers:</span>
              <button
                type="button"
                onClick={() => quickSelectPeer("CRX-9941-SL")}
                className="px-2 py-0.5 text-[9.5px] font-mono border border-grid bg-void text-muted hover:text-signal hover:border-signal"
              >
                + Sarah Lin (CRX-9941-SL)
              </button>
              <button
                type="button"
                onClick={() => quickSelectPeer("CRX-0001-AI")}
                className="px-2 py-0.5 text-[9.5px] font-mono border border-grid bg-void text-muted hover:text-signal hover:border-signal"
              >
                + CruxAI (CRX-0001-AI)
              </button>
              <button
                type="button"
                onClick={() => quickSelectPeer("CRX-5520-MV")}
                className="px-2 py-0.5 text-[9.5px] font-mono border border-grid bg-void text-muted hover:text-signal hover:border-signal"
              >
                + Marcus (CRX-5520-MV)
              </button>
            </div>
          </div>

          {/* 2. Access Level Segmented Selector */}
          <div className="space-y-2">
            <label className="text-[10px] font-mono uppercase tracking-widest text-muted block">
              Access Permission Level
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setAccessLevel("full")}
                className={`p-2.5 border text-left flex flex-col justify-between transition-colors ${
                  accessLevel === "full"
                    ? "border-signal bg-grid text-signal"
                    : "border-grid bg-void text-muted hover:text-signal"
                }`}
              >
                <span className="text-[11px] font-bold uppercase font-mono">Full Access</span>
                <span className="text-[9.5px] text-muted mt-1 leading-tight">
                  Edit all files &amp; run code
                </span>
              </button>

              <button
                type="button"
                onClick={() => setAccessLevel("limited")}
                className={`p-2.5 border text-left flex flex-col justify-between transition-colors ${
                  accessLevel === "limited"
                    ? "border-signal bg-grid text-signal"
                    : "border-grid bg-void text-muted hover:text-signal"
                }`}
              >
                <span className="text-[11px] font-bold uppercase font-mono">Limited Access</span>
                <span className="text-[9.5px] text-muted mt-1 leading-tight">
                  Restrict files &amp; lines
                </span>
              </button>

              <button
                type="button"
                onClick={() => setAccessLevel("viewer")}
                className={`p-2.5 border text-left flex flex-col justify-between transition-colors ${
                  accessLevel === "viewer"
                    ? "border-signal bg-grid text-signal"
                    : "border-grid bg-void text-muted hover:text-signal"
                }`}
              >
                <span className="text-[11px] font-bold uppercase font-mono">Viewer Only</span>
                <span className="text-[9.5px] text-muted mt-1 leading-tight">
                  Read-only live stream
                </span>
              </button>
            </div>
          </div>

          {/* If Limited Access: File selection and line boundaries */}
          {accessLevel === "limited" && (
            <div className="p-3 bg-void border border-grid space-y-3 font-mono text-xs">
              <div>
                <span className="text-[10px] uppercase text-muted tracking-wider block mb-1.5">
                  Allowed Files (Check to permit editing):
                </span>
                <div className="space-y-1">
                  {files.map((file) => (
                    <label
                      key={file.id}
                      className="flex items-center gap-2 cursor-pointer text-muted hover:text-signal"
                    >
                      <input
                        type="checkbox"
                        checked={selectedFiles.includes(file.name)}
                        onChange={() => handleToggleFile(file.name)}
                        className="accent-signal"
                      />
                      <span>{file.name}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-[10px] uppercase text-muted tracking-wider block mb-1.5">
                  Line Boundary Range:
                </span>
                <div className="flex items-center gap-2 text-xs">
                  <span>Lines:</span>
                  <input
                    type="number"
                    value={startLine}
                    onChange={(e) => setStartLine(parseInt(e.target.value) || 1)}
                    className="w-16 bg-surface border border-grid px-2 py-0.5 text-signal font-mono text-xs"
                    min={1}
                  />
                  <span>to</span>
                  <input
                    type="number"
                    value={endLine}
                    onChange={(e) => setEndLine(parseInt(e.target.value) || 100)}
                    className="w-16 bg-surface border border-grid px-2 py-0.5 text-signal font-mono text-xs"
                    min={1}
                  />
                </div>
              </div>
            </div>
          )}

          {/* 3. Viewer Lock Toggle (Even if Full Access is granted) */}
          <div className="p-3 bg-void border border-grid flex items-center justify-between gap-3">
            <div className="space-y-0.5">
              <div className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-accent2" />
                <span className="text-xs font-semibold text-signal uppercase font-mono">
                  Viewer Lock (Presentation Freeze)
                </span>
              </div>
              <p className="text-[10.5px] text-muted leading-tight">
                Locks all users into view-only observation, freezing keystrokes across the workspace even if Full Access is granted.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setLocalViewerLock(!localViewerLock)}
              className={`px-3 py-1 text-xs font-mono uppercase font-bold border transition-colors ${
                localViewerLock
                  ? "bg-accent2 text-signal border-accent2"
                  : "bg-surface text-muted border-grid hover:text-signal"
              }`}
            >
              {localViewerLock ? "LOCKED" : "UNLOCKED"}
            </button>
          </div>

          {/* Actions */}
          <div className="pt-2 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => setShareModalOpen(false)}
              className="px-4 py-2 border border-grid text-muted hover:text-signal text-xs uppercase font-mono"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-5 py-2 bg-signal text-void font-bold text-xs uppercase tracking-wider hover:opacity-90 flex items-center gap-2"
            >
              <Send className="w-3 h-3" />
              <span>Dispatch Invite to Inbox</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
