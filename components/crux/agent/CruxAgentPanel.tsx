"use client";

import React, { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ThinkingOrb } from "thinking-orbs";
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
  Code2,
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
        "CruxAI Autonomous Copilot online. Full context indexed over your workspace. I can inspect ASTs, write unit tests, refactor bottlenecks, or generate new modules directly with zero-copy CRDT streaming.",
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
      initial={{ x: 420, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 420, opacity: 0 }}
      transition={{ type: "spring", damping: 28, stiffness: 280 }}
      className="w-[380px] h-full flex flex-col border-l border-[#222222] bg-[#0A0A0A] select-none shrink-0 z-30 font-sans relative"
    >
      {/* Top Header */}
      <div className="h-9 px-3 flex items-center justify-between border-b border-[#222222] bg-[#0A0A0A]">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 rounded-none flex items-center justify-center bg-black border border-[#222222] text-[#FF453A]">
            <Bot className="w-3.5 h-3.5 text-[#FF453A]" />
          </div>
          <div className="flex items-center gap-1.5">
            <span className="font-semibold text-xs text-white font-sans">CruxAI Assistant</span>
            <span className="px-1.5 py-0.2 rounded-none text-[9.5px] bg-black border border-[#222222] text-[#FF453A] font-mono">
              AUTONOMOUS
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1">
          {/* Haptic & Acoustic Sound Toggle */}
          <button
            onClick={handleToggleSound}
            title={hapticsOn ? "Tactile Audio: Enabled (Click to Mute)" : "Tactile Audio: Muted"}
            className={`p-1 rounded-none transition-colors ${
              hapticsOn
                ? "text-white bg-[#222222]"
                : "text-[#888888] hover:text-white hover:bg-[#222222]"
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
            className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          {/* Close Panel */}
          <button
            onClick={() => {
              triggerHaptic("toggle");
              onClose();
            }}
            title="Close Assistant Panel"
            className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Active File Context Pill */}
      <div className="px-3 py-1.5 border-b border-[#222222] bg-black flex items-center justify-between text-xs">
        <div className="flex items-center gap-1.5 text-[#888888] truncate">
          <span className="text-[11px]">Context:</span>
          {activeFile ? (
            <span className="text-white truncate flex items-center gap-1.5 px-1.5 py-0.5 rounded-none bg-[#0A0A0A] border border-[#222222]">
              <FileCode className="w-3 h-3 text-[#888888]" />
              <span className="font-mono text-[11px] text-white">{activeFile.name}</span>
            </span>
          ) : (
            <span className="text-[#888888] italic">Entire Workspace</span>
          )}
        </div>
        <div className="flex items-center gap-1.5 text-[#888888] font-mono text-[10px]">
          <span className="w-1.5 h-1.5 rounded-none bg-[#007AFF]" />
          <span>0.08ms IPC</span>
        </div>
      </div>

      {/* Quick Action Chips */}
      <div className="px-3 py-1.5 border-b border-[#222222] bg-[#0A0A0A] flex items-center gap-1.5 overflow-x-auto text-xs">
        <button
          onClick={() => handleSend("Optimize and refactor active buffer for latency")}
          disabled={isThinking || !activeFile}
          className="flex items-center gap-1.5 px-2 py-0.5 rounded-none bg-black hover:bg-[#222222] text-[#888888] hover:text-white border border-[#222222] whitespace-nowrap transition-colors disabled:opacity-40 text-xs font-mono"
        >
          <Zap className="w-3 h-3 text-[#FF453A]" />
          <span>Optimize</span>
        </button>

        <button
          onClick={() => handleSend("Add comprehensive defensive error handling and validation")}
          disabled={isThinking || !activeFile}
          className="flex items-center gap-1.5 px-2 py-0.5 rounded-none bg-black hover:bg-[#222222] text-[#888888] hover:text-white border border-[#222222] whitespace-nowrap transition-colors disabled:opacity-40 text-xs font-mono"
        >
          <ShieldCheck className="w-3 h-3 text-[#888888]" />
          <span>Fix / Guard</span>
        </button>

        <button
          onClick={() => handleSend("Generate a comprehensive test suite for this module")}
          disabled={isThinking}
          className="flex items-center gap-1.5 px-2 py-0.5 rounded-none bg-black hover:bg-[#222222] text-[#888888] hover:text-white border border-[#222222] whitespace-nowrap transition-colors disabled:opacity-40 text-xs font-mono"
        >
          <FilePlus2 className="w-3 h-3 text-[#888888]" />
          <span>Gen Tests</span>
        </button>
      </div>

      {/* Chat Messages Container */}
      <div className="flex-1 p-3 overflow-y-auto space-y-3 select-text bg-black font-sans">
        <AnimatePresence>
          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.12 }}
              className={`flex flex-col ${
                msg.role === "user" ? "items-end" : "items-start"
              }`}
            >
              {/* Header: Name + Time */}
              <div className="flex items-center gap-1.5 mb-1 text-[10px] text-[#888888]">
                <span className={msg.role === "user" ? "text-[#007AFF] font-semibold" : "text-[#FF453A] font-semibold"}>
                  {msg.role === "user" ? "You" : "@CruxAI"}
                </span>
                <span>·</span>
                <span className="font-mono">{msg.timestamp}</span>
              </div>

              {/* Message Bubble */}
              <div
                className={`p-2.5 rounded-none text-xs leading-relaxed max-w-[95%] border ${
                  msg.role === "user"
                    ? "bg-[#0A0A0A] text-white border-[#222222]"
                    : "bg-black text-white border-[#222222]"
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.content}</div>

                {/* Diff Proposal Card */}
                {msg.diffProposal && (
                  <div className="mt-2.5 pt-2.5 border-t border-[#222222] rounded-none bg-[#0A0A0A] p-2.5 border">
                    <div className="flex items-center justify-between text-xs mb-1.5">
                      <span className="font-semibold text-white flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-[#FF453A]" />
                        {msg.diffProposal.diffSummary}
                      </span>
                      <span className="text-[10px] text-[#888888] font-mono px-1.5 py-0.2 rounded-none bg-black border border-[#222222]">
                        {msg.diffProposal.fileName}
                      </span>
                    </div>

                    <p className="text-xs text-[#888888] mb-2">
                      {msg.diffProposal.explanation}
                    </p>

                    {/* Diff Preview box */}
                    <div className="p-2 rounded-none bg-black border border-[#222222] font-mono text-xs max-h-40 overflow-y-auto mb-2 text-white">
                      <div className="text-[#00FF00] bg-[#00FF00]/10 border-l-2 border-[#00FF00] p-1.5">
                        + {msg.diffProposal.proposedContent.slice(0, 200)}...
                      </div>
                    </div>

                    {/* Action Buttons: Apply / Reject */}
                    {appliedDiffIds[msg.id] === undefined ? (
                      <div className="flex items-center justify-end gap-2 pt-1">
                        <button
                          onClick={() => handleRejectDiff(msg.id)}
                          className="flex items-center gap-1 px-2 py-0.5 text-xs text-[#888888] hover:text-white rounded-none border border-[#222222] bg-black hover:bg-[#222222] transition-colors"
                        >
                          <X className="w-3 h-3" />
                          <span>Dismiss</span>
                        </button>

                        <button
                          onClick={() => handleApplyDiff(msg.id, msg.diffProposal!)}
                          className="flex items-center gap-1.5 px-3 py-1 text-xs rounded-none bg-white hover:bg-[#cccccc] text-black font-semibold transition-colors cursor-pointer"
                        >
                          <Check className="w-3.5 h-3.5" />
                          <span>Apply to Buffer</span>
                        </button>
                      </div>
                    ) : appliedDiffIds[msg.id] ? (
                      <div className="flex items-center gap-1.5 text-white text-xs font-medium pt-1 font-mono">
                        <CheckCircle2 className="w-4 h-4 text-[#007AFF]" />
                        <span>Applied cleanly to {msg.diffProposal.fileName}</span>
                      </div>
                    ) : (
                      <div className="text-[#888888] text-xs pt-1 italic font-mono">
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
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-3 rounded-none bg-[#0A0A0A] border border-[#222222] space-y-2 text-xs"
            >
              <div className="flex items-center gap-2 text-white font-medium">
                <ThinkingOrb state="searching" size={20} theme="dark" />
                <span>CruxAI Synthesizing Patch...</span>
              </div>

              <div className="space-y-1.5 pt-0.5 font-mono">
                {currentSteps.map((step) => (
                  <div
                    key={step.id}
                    className="flex items-center gap-2 text-xs text-[#888888]"
                  >
                    {step.status === "done" ? (
                      <Check className="w-3.5 h-3.5 text-white" />
                    ) : step.status === "running" ? (
                      <Loader2 className="w-3.5 h-3.5 text-[#FF453A] animate-spin" />
                    ) : (
                      <span className="w-3 h-3 rounded-none border border-[#222222] inline-block" />
                    )}
                    <span
                      className={
                        step.status === "running"
                          ? "text-white font-medium"
                          : step.status === "done"
                          ? "text-[#888888]"
                          : "text-[#555555]"
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
              placeholder="Ask CruxAI or prompt e.g. 'optimize this buffer'..."
              className="w-full bg-black border border-[#222222] focus:border-[#FF453A] rounded-none text-xs text-white placeholder-[#888888] p-2.5 pr-8 resize-none focus:outline-none transition-colors font-mono"
            />
            <button
              type="submit"
              disabled={!inputVal.trim() || isThinking}
              className="absolute right-2 bottom-2.5 p-1.5 rounded-none bg-[#FF453A] hover:bg-[#e03e34] disabled:opacity-30 text-white transition-colors cursor-pointer"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="flex items-center justify-between text-[10px] text-[#888888] font-mono">
            <span>Enter to send · Shift+Enter for newline</span>
            <span>CRDT Stream v1.2</span>
          </div>
        </form>
      </div>
    </motion.aside>
  );
}
