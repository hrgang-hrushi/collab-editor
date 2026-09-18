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
    <div className="w-[320px] rounded-none p-3 bg-[#0A0A0A] shadow-[4px_4px_0px_#222222] text-white text-xs border border-[#222222] font-sans">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 mb-2.5 border-b border-[#222222]">
        <div className="flex items-center gap-2">
          <span className="p-1 rounded-none bg-black border border-[#222222] text-white">
            <MessageSquare className="w-3.5 h-3.5 text-[#007AFF]" />
          </span>
          <span className="font-semibold text-white text-xs font-mono">
            Line {thread.lineNumber}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => resolveComment(thread.id)}
            title="Mark as resolved"
            className="flex items-center gap-1 h-5 px-2 rounded-none bg-black hover:bg-[#222222] text-white border border-[#222222] transition-colors text-[11px] font-medium"
          >
            <Check className="w-3 h-3 text-white" />
            <span>Resolve</span>
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="text-[#888888] hover:text-white transition-colors p-1 rounded-none hover:bg-[#222222]"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Code Snippet Anchor Preview */}
      {thread.anchorSnippet && (
        <div className="p-2 mb-2.5 rounded-none bg-black border border-[#222222] font-mono text-[11px] text-[#888888] truncate">
          <span className="text-[#007AFF] mr-1.5 font-bold">›</span>
          <code>{thread.anchorSnippet}</code>
        </div>
      )}

      {/* Thread Messages */}
      <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1 mb-2.5 scrollbar-none">
        {thread.messages.map((msg) => (
          <div key={msg.id} className="space-y-1 bg-black p-2 rounded-none border border-[#222222]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div
                  className="w-4 h-4 rounded-none flex items-center justify-center text-[8px] font-bold text-white border border-[#222222]"
                  style={{ backgroundColor: msg.author.color }}
                >
                  {msg.author.name[0]}
                </div>
                <span className="font-semibold text-white text-xs">
                  {msg.author.name}
                </span>
              </div>
              <span className="text-[10px] text-[#888888] font-mono">
                {new Date(msg.createdAt).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </span>
            </div>

            <p className="pl-6 text-white leading-relaxed text-[11.5px]">
              {msg.text}
            </p>

            {/* Reactions if any */}
            {msg.reactions && Object.keys(msg.reactions).length > 0 && (
              <div className="pl-6 flex items-center gap-1.5 pt-1">
                {Object.entries(msg.reactions).map(([emoji, users]) => (
                  <span
                    key={emoji}
                    className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded-none bg-[#0A0A0A] border border-[#222222] text-[10px] text-[#888888] font-mono"
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
          className="w-full pl-2.5 pr-8 py-1.5 rounded-none bg-black border border-[#222222] focus:border-[#007AFF] text-white placeholder-[#888888] focus:outline-none text-xs transition-colors font-mono"
        />
        <button
          type="submit"
          disabled={!replyText.trim()}
          className="absolute right-1 p-1 rounded-none text-[#007AFF] hover:text-white disabled:opacity-30 transition-colors"
        >
          <Send className="w-3.5 h-3.5" />
        </button>
      </form>
    </div>
  );
}
