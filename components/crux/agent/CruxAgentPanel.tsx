"use client";

import React, { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bot,
  Sparkles,
  Send,
  Check,
  X,
  FileCode,
  CheckCircle2,
  Loader2,
  Zap,
  ShieldCheck,
  FilePlus2,
  Trash2,
  ChevronRight,
  Maximize2,
  Minimize2,
  Volume2,
  VolumeX,
} from "lucide-react";
import { useWorkspaceStore } from "@/lib/store";
import {
  CruxAgentEngine,
  AgentMessage,
  AgentStep,
  AgentDiffProposal,
} from "@/lib/agentEngine";
import { triggerHaptic, toggleHaptics, isHapticsEnabled } from "@/lib/haptics";

interface CruxAgentPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function CruxAgentPanel({ isOpen, onClose }: CruxAgentPanelProps) {
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);
  const updateFileContent = useWorkspaceStore((state) => state.updateFileContent);
  const createFileInPath = useWorkspaceStore((state) => state.createFileInPath);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);

  const activeFile = files.find((f) => f.id === activeFileId) || null;

  const [inputVal, setInputVal] = useState("");
  const [isThinking, setIsThinking] = useState(false);
  const [currentSteps, setCurrentSteps] = useState<AgentStep[]>([]);
  const [hapticsOn, setHapticsOn] = useState(true);
  const [appliedDiffIds, setAppliedDiffIds] = useState<Record<string, boolean>>({});

  const [messages, setMessages] = useState<AgentMessage[]>([
    {
      id: "welcome",
      role: "agent",
      content:
        "CruxAI Autonomous Copilot online. I have full context over your workspace. I can inspect ASTs, write unit tests, refactor bottlenecks, or generate new modules directly with zero-copy CRDT streaming.",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setHapticsOn(isHapticsEnabled());
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, currentSteps, isThinking]);

  const handleToggleSound = () => {
    const newState = toggleHaptics();
    setHapticsOn(newState);
  };

  const handleSend = async (customPrompt?: string) => {
    const promptToSend = customPrompt || inputVal;
    if (!promptToSend.trim() || isThinking) return;

    triggerHaptic("click");
    const userMsg: AgentMessage = {
      id: `user-${Date.now()}`,
      role: "user",
      content: promptToSend.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputVal("");
    setIsThinking(true);
    setCurrentSteps([]);

    try {
      const result = await CruxAgentEngine.executeTask(
        {
          prompt: promptToSend,
          activeFile,
          allFiles: files,
        },
        (steps) => {
          setCurrentSteps(steps);
          triggerHaptic("agent");
        }
      );

      // If agent generated a new file, add it to the workspace
      if (result.newFile) {
        createFileInPath(result.newFile.path, result.newFile.content);
        triggerHaptic("success");
      }

      const agentMsg: AgentMessage = {
        id: `agent-${Date.now()}`,
        role: "agent",
        content: result.reply,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        diffProposal: result.diffProposal,
      };

      setMessages((prev) => [...prev, agentMsg]);
      triggerHaptic("success");
    } catch (err: any) {
      triggerHaptic("error");
      setMessages((prev) => [
        ...prev,
        {
          id: `error-${Date.now()}`,
          role: "agent",
          content: `Agent encountered an error: ${err?.message || "Operation failed."}`,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ]);
    } finally {
      setIsThinking(false);
      setCurrentSteps([]);
    }
  };

  const handleApplyDiff = (msgId: string, diff: AgentDiffProposal) => {
    triggerHaptic("success");
    updateFileContent(diff.fileId, diff.proposedContent);
    setAppliedDiffIds((prev) => ({ ...prev, [msgId]: true }));
  };

  const handleRejectDiff = (msgId: string) => {
    triggerHaptic("tap");
    setAppliedDiffIds((prev) => ({ ...prev, [msgId]: false }));
  };

  if (!isOpen) return null;

  return (
    <motion.aside
      initial={{ x: 380, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 380, opacity: 0 }}
      transition={{ type: "spring", damping: 28, stiffness: 280 }}
      className="w-96 h-full flex flex-col border-l border-[#222222] bg-[#0A0A0A] select-none shrink-0 z-30 font-sans relative"
    >
      {/* Top Header */}
      <div className="h-10 px-3 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A]">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 bg-[#8b5cf6]/15 border border-[#8b5cf6]/40 flex items-center justify-center">
            <Bot className="w-3 h-3 text-[#8b5cf6]" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-semibold text-xs text-[#f7f8f8]">CruxAI Agent</span>
              <span className="px-1 py-0.2 text-[8.5px] bg-[#8b5cf6]/20 border border-[#8b5cf6]/40 text-[#c4b5fd] font-mono">
                AUTONOMOUS
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1">
          {/* Haptic & Acoustic Sound Toggle */}
          <button
            onClick={handleToggleSound}
            title={hapticsOn ? "Tactile Audio: Enabled (Click to Mute)" : "Tactile Audio: Muted"}
            className={`p-1.5 transition-colors border ${
              hapticsOn
                ? "text-[#5e6ad2] border-[#5e6ad2]/30 bg-[#5e6ad2]/10"
                : "text-[#62666d] border-transparent hover:text-white"
            }`}
          >
            {hapticsOn ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5" />}
          </button>

          {/* Clear Chat */}
          <button
            onClick={() => {
              triggerHaptic("tap");
              setMessages([]);
            }}
            title="Clear Chat History"
            className="p-1.5 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] border border-transparent hover:border-[#222222] transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          {/* Close Panel */}
          <button
            onClick={() => {
              triggerHaptic("toggle");
              onClose();
            }}
            title="Close Copilot Panel"
            className="p-1.5 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#141516] border border-transparent hover:border-[#222222] transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Active File Context Pill */}
      <div className="px-3 py-1.5 border-b border-[#222222] bg-black flex items-center justify-between text-[11px]">
        <div className="flex items-center gap-1.5 text-[#8a8f98] truncate">
          <span className="text-[#62666d]">Context:</span>
          {activeFile ? (
            <span className="text-[#f7f8f8] font-medium truncate flex items-center gap-1">
              <FileCode className="w-3 h-3 text-[#5e6ad2]" />
              {activeFile.name}
            </span>
          ) : (
            <span className="text-[#62666d] italic">Entire Workspace</span>
          )}
        </div>
        <span className="text-[10px] text-[#27a644] font-mono">0.08ms Latency</span>
      </div>

      {/* Quick Action Chips */}
      <div className="px-3 py-2 border-b border-[#1f2022] bg-[#0A0A0A] flex items-center gap-1.5 overflow-x-auto text-[11px]">
        <button
          onClick={() => handleSend("Optimize and refactor active buffer for latency")}
          disabled={isThinking || !activeFile}
          className="flex items-center gap-1 px-2 py-0.5 bg-[#141516] hover:bg-[#191a1b] text-[#f7f8f8] border border-[#222222] hover:border-[#5e6ad2]/50 whitespace-nowrap transition-colors disabled:opacity-40"
        >
          <Zap className="w-3 h-3 text-[#f59e0b]" />
          <span>Optimize</span>
        </button>

        <button
          onClick={() => handleSend("Add comprehensive defensive error handling and validation")}
          disabled={isThinking || !activeFile}
          className="flex items-center gap-1 px-2 py-0.5 bg-[#141516] hover:bg-[#191a1b] text-[#f7f8f8] border border-[#222222] hover:border-[#5e6ad2]/50 whitespace-nowrap transition-colors disabled:opacity-40"
        >
          <ShieldCheck className="w-3 h-3 text-[#27a644]" />
          <span>Fix / Guard</span>
        </button>

        <button
          onClick={() => handleSend("Generate a comprehensive test suite for this module")}
          disabled={isThinking}
          className="flex items-center gap-1 px-2 py-0.5 bg-[#141516] hover:bg-[#191a1b] text-[#f7f8f8] border border-[#222222] hover:border-[#5e6ad2]/50 whitespace-nowrap transition-colors disabled:opacity-40"
        >
          <FilePlus2 className="w-3 h-3 text-[#06b6d4]" />
          <span>Gen Tests</span>
        </button>
      </div>

      {/* Chat Messages Container */}
      <div className="flex-1 p-3 overflow-y-auto space-y-3.5 select-text">
        <AnimatePresence>
          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.15 }}
              className={`flex flex-col ${
                msg.role === "user" ? "items-end" : "items-start"
              }`}
            >
              {/* Header: Name + Time */}
              <div className="flex items-center gap-1.5 mb-1 text-[10px] text-[#62666d]">
                <span className={msg.role === "user" ? "text-[#f7f8f8] font-medium" : "text-[#8b5cf6] font-medium"}>
                  {msg.role === "user" ? "You" : "@CruxAI"}
                </span>
                <span>·</span>
                <span>{msg.timestamp}</span>
              </div>

              {/* Message Bubble */}
              <div
                className={`p-2.5 rounded-none text-xs leading-relaxed max-w-[95%] border ${
                  msg.role === "user"
                    ? "bg-[#141516] text-white border-[#333333]"
                    : "bg-black text-[#f7f8f8] border-[#222222]"
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.content}</div>

                {/* Diff Proposal Card */}
                {msg.diffProposal && (
                  <div className="mt-2.5 pt-2 border-t border-[#222222] bg-[#0A0A0A] p-2 border">
                    <div className="flex items-center justify-between text-[11px] mb-1.5">
                      <span className="font-semibold text-white flex items-center gap-1">
                        <Sparkles className="w-3 h-3 text-[#5e6ad2]" />
                        {msg.diffProposal.diffSummary}
                      </span>
                      <span className="text-[10px] text-[#62666d] font-mono">
                        {msg.diffProposal.fileName}
                      </span>
                    </div>

                    <p className="text-[10.5px] text-[#8a8f98] mb-2">
                      {msg.diffProposal.explanation}
                    </p>

                    {/* Diff Preview box */}
                    <div className="p-2 bg-black border border-[#222222] font-mono text-[10.5px] max-h-36 overflow-y-auto mb-2 text-[#d0d6e0]">
                      <div className="text-[#27a644]">
                        + {msg.diffProposal.proposedContent.slice(0, 180)}...
                      </div>
                    </div>

                    {/* Action Buttons: Apply / Reject */}
                    {appliedDiffIds[msg.id] === undefined ? (
                      <div className="flex items-center justify-end gap-1.5 pt-1">
                        <button
                          onClick={() => handleRejectDiff(msg.id)}
                          className="flex items-center gap-1 px-2 py-0.5 text-[11px] text-[#8a8f98] hover:text-white border border-[#222222] hover:bg-[#141516] transition-colors"
                        >
                          <X className="w-3 h-3" />
                          <span>Dismiss</span>
                        </button>

                        <button
                          onClick={() => handleApplyDiff(msg.id, msg.diffProposal!)}
                          className="flex items-center gap-1 px-2.5 py-0.5 text-[11px] bg-[#5e6ad2] hover:bg-[#6c78e6] text-white font-medium border border-[#5e6ad2] transition-colors"
                        >
                          <Check className="w-3 h-3" />
                          <span>Apply to Buffer</span>
                        </button>
                      </div>
                    ) : appliedDiffIds[msg.id] ? (
                      <div className="flex items-center gap-1 text-[#27a644] text-[11px] font-medium pt-1">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Applied to {msg.diffProposal.fileName}</span>
                      </div>
                    ) : (
                      <div className="text-[#62666d] text-[11px] pt-1 italic">
                        Proposal dismissed
                      </div>
                    )}
                  </div>
                )}
              </div>
            </motion.div>
          ))}

          {/* Dynamic Thinking & Reasoning Steps */}
          {isThinking && (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-3 bg-black border border-[#5e6ad2]/40 space-y-2 text-xs"
            >
              <div className="flex items-center gap-2 text-[#8b5cf6] font-medium">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>CruxAI Synthesizing Patch...</span>
              </div>

              <div className="space-y-1.5 pt-1">
                {currentSteps.map((step) => (
                  <div
                    key={step.id}
                    className="flex items-center gap-2 text-[11px] text-[#8a8f98]"
                  >
                    {step.status === "done" ? (
                      <Check className="w-3 h-3 text-[#27a644]" />
                    ) : step.status === "running" ? (
                      <Loader2 className="w-3 h-3 text-[#5e6ad2] animate-spin" />
                    ) : (
                      <span className="w-3 h-3 border border-[#333333] inline-block" />
                    )}
                    <span
                      className={
                        step.status === "running"
                          ? "text-[#f7f8f8] font-medium"
                          : step.status === "done"
                          ? "text-[#d0d6e0]"
                          : "text-[#62666d]"
                      }
                    >
                      {step.label}
                    </span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        <div ref={messagesEndRef} />
      </div>

      {/* Input Box */}
      <div className="p-3 border-t border-[#222222] bg-[#0A0A0A]">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="relative flex flex-col gap-2"
        >
          <div className="relative">
            <textarea
              rows={2}
              value={inputVal}
              onChange={(e) => {
                setInputVal(e.target.value);
                triggerHaptic("type");
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              placeholder="Ask CruxAI or type e.g. 'refactor this file'..."
              className="w-full bg-black border border-[#222222] focus:border-[#5e6ad2] text-xs text-[#f7f8f8] placeholder-[#62666d] p-2.5 pr-8 resize-none focus:outline-none transition-colors"
            />
            <button
              type="submit"
              disabled={!inputVal.trim() || isThinking}
              className="absolute right-2 bottom-2 p-1.5 bg-[#5e6ad2] hover:bg-[#6c78e6] disabled:opacity-30 text-white transition-colors"
            >
              <Send className="w-3 h-3" />
            </button>
          </div>

          <div className="flex items-center justify-between text-[10px] text-[#62666d]">
            <span>Press Enter to send · Shift+Enter for newline</span>
            <span>CRDT Stream v1.2</span>
          </div>
        </form>
      </div>
    </motion.aside>
  );
}
