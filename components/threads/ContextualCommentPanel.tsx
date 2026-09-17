"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { ContextualThread } from "@/lib/types";
import { MessageSquare, Check, Send, X } from "lucide-react";

interface ContextualCommentPanelProps {
  thread: ContextualThread;
  onClose?: () => void;
}

export default function ContextualCommentPanel({
  thread,
  onClose,
}: ContextualCommentPanelProps) {
  const [replyText, setReplyText] = useState("");
  const addReply = useWorkspaceStore((state) => state.addCommentReply);
  const resolveComment = useWorkspaceStore((state) => state.resolveComment);

  const handleSendReply = (e: React.FormEvent) => {
    e.preventDefault();
    if (!replyText.trim()) return;
    addReply(thread.id, replyText.trim());
    setReplyText("");
  };

  return (
    <div className="w-[320px] rounded-xl p-3 bg-linear-surface-1 shadow-elevation-high text-linear-ink text-xs border border-linear-hairline-strong animate-in fade-in zoom-in-95 duration-100 font-sans tracking-body">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 mb-2 border-b border-linear-hairline">
        <div className="flex items-center gap-1.5">
          <span className="p-1 rounded bg-linear-surface-2 text-linear-primary">
            <MessageSquare className="w-3.5 h-3.5" />
          </span>
          <span className="font-semibold text-linear-ink text-xs font-mono">
            Line {thread.lineNumber}
          </span>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={() => resolveComment(thread.id)}
            title="Mark as resolved"
            className="flex items-center gap-1 h-6 px-2 rounded bg-linear-surface-2 hover:bg-linear-surface-3 text-linear-success border border-linear-hairline transition text-[11px] font-medium"
          >
            <Check className="w-3 h-3" />
            <span>Resolve</span>
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="text-linear-ink-subtle hover:text-linear-ink transition p-1 rounded hover:bg-linear-surface-2"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Code Snippet Anchor Preview */}
      {thread.anchorSnippet && (
        <div className="p-2 mb-2 rounded bg-linear-canvas border border-linear-hairline font-mono text-[11px] text-linear-ink-subtle truncate">
          <span className="text-linear-ink-tertiary mr-1.5">›</span>
          <code>{thread.anchorSnippet}</code>
        </div>
      )}

      {/* Thread Messages */}
      <div className="space-y-2 max-h-[200px] overflow-y-auto pr-1 mb-2">
        {thread.messages.map((msg) => (
          <div key={msg.id} className="space-y-1">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <div
                  className="w-4 h-4 rounded-full flex items-center justify-center text-[8px] font-bold text-white shadow-sm border border-linear-hairline"
                  style={{ backgroundColor: msg.author.color }}
                >
                  {msg.author.name[0]}
                </div>
                <span className="font-semibold text-linear-ink text-xs">
                  {msg.author.name}
                </span>
              </div>
              <span className="text-[10px] text-linear-ink-subtle font-mono">
                {new Date(msg.createdAt).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </span>
            </div>

            <p className="pl-5 text-linear-ink-muted leading-relaxed text-[11.5px]">
              {msg.text}
            </p>

            {/* Reactions if any */}
            {msg.reactions && Object.keys(msg.reactions).length > 0 && (
              <div className="pl-5 flex items-center gap-1 pt-0.5">
                {Object.entries(msg.reactions).map(([emoji, users]) => (
                  <span
                    key={emoji}
                    className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-linear-surface-2 border border-linear-hairline text-[10px] text-linear-ink-muted"
                  >
                    <span>{emoji}</span>
                    <span>{users.length}</span>
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Reply Input Form */}
      <form onSubmit={handleSendReply} className="relative flex items-center">
        <input
          type="text"
          value={replyText}
          onChange={(e) => setReplyText(e.target.value)}
          placeholder="Reply to thread..."
          className="w-full pl-2.5 pr-8 py-1.5 rounded bg-linear-canvas border border-linear-hairline text-linear-ink placeholder-linear-ink-tertiary focus:outline-none focus:border-linear-primary text-xs transition"
        />
        <button
          type="submit"
          disabled={!replyText.trim()}
          className="absolute right-1 p-1 rounded text-linear-primary hover:bg-linear-surface-2 disabled:opacity-30 transition"
        >
          <Send className="w-3 h-3" />
        </button>
      </form>
    </div>
  );
}
