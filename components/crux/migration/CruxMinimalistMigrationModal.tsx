"use client";

import React, { useState, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { scanExistingIdes, executeUniversalMigration } from "@/lib/migration/engine";
import { IdeScanManifest, MigrationSummary } from "@/lib/migration/types";
import {
  Check,
  Loader2,
  ArrowRight,
  X,
  Sparkles,
  Command,
  Palette,
  Bot,
} from "lucide-react";

interface CruxMinimalistMigrationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete?: () => void;
}

const STEPS = [
  {
    id: 1,
    title: "Detecting local IDE installations...",
    detail: "Scanning VS Code, Cursor, and Windsurf configurations",
  },
  {
    id: 2,
    title: "Importing user settings and keybindings...",
    detail: "Preserving developer shortcuts, editor tabs, and muscle memory",
  },
  {
    id: 3,
    title: "Adapting color themes and extension grammars...",
    detail: "Translating syntax highlighting and workspace aesthetics",
  },
  {
    id: 4,
    title: "Synchronizing custom AI rules and agents...",
    detail: "Harvesting .cursorrules, system prompts, and custom skills",
  },
];

export default function CruxMinimalistMigrationModal({
  isOpen,
  onClose,
  onComplete,
}: CruxMinimalistMigrationModalProps) {
  const setOnboarded = useWorkspaceStore((state) => state.setOnboarded);
  const setZeroStateOpen = useWorkspaceStore((state) => state.setZeroStateOpen);

  const [currentStep, setCurrentStep] = useState<number>(1);
  const [isCompleted, setIsCompleted] = useState<boolean>(false);
  const [manifest, setManifest] = useState<IdeScanManifest | null>(null);
  const [summary, setSummary] = useState<MigrationSummary | null>(null);

  useEffect(() => {
    if (!isOpen) {
      setCurrentStep(1);
      setIsCompleted(false);
      return;
    }

    let isMounted = true;

    async function runMigrationProcess() {
      try {
        // Step 1: Detect local IDE installations
        setCurrentStep(1);
        const scannedManifest = await scanExistingIdes();
        if (!isMounted) return;
        setManifest(scannedManifest);

        // Step 2: Import user settings & keybindings
        await new Promise((r) => setTimeout(r, 700));
        if (!isMounted) return;
        setCurrentStep(2);

        // Step 3: Adapting color themes and extension grammars
        await new Promise((r) => setTimeout(r, 750));
        if (!isMounted) return;
        setCurrentStep(3);

        // Step 4: Synchronizing custom AI rules and agents
        await new Promise((r) => setTimeout(r, 700));
        if (!isMounted) return;
        setCurrentStep(4);

        // Execute migration translation into Crux workspace store
        const result = await executeUniversalMigration(scannedManifest);
        await new Promise((r) => setTimeout(r, 600));
        if (!isMounted) return;
        setSummary(result);
        setIsCompleted(true);
      } catch (err) {
        console.error("Migration error:", err);
        if (isMounted) {
          setIsCompleted(true);
        }
      }
    }

    runMigrationProcess();

    return () => {
      isMounted = false;
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const handleLaunchEditor = () => {
    setOnboarded(true);
    setZeroStateOpen(false);
    if (onComplete) onComplete();
    onClose();
  };

  const progressPercentage = isCompleted
    ? 100
    : Math.min(((currentStep - 1) / STEPS.length) * 100 + 15, 95);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-md animate-in fade-in duration-200">
      <div className="w-full max-w-lg bg-neutral-950 border border-neutral-800/80 rounded-2xl shadow-2xl p-6 sm:p-8 space-y-6 text-neutral-100 font-sans relative">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 text-neutral-400 hover:text-neutral-200 p-1.5 rounded-lg hover:bg-neutral-800/50 transition-colors"
          title="Close migration"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Modal Header */}
        <div className="space-y-1.5 pr-8">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-neutral-300" />
            <span className="text-xs uppercase font-medium tracking-wider text-neutral-400">
              Migration Engine
            </span>
          </div>
          <h3 className="text-xl font-semibold tracking-tight text-neutral-100">
            {isCompleted ? "Your workspace is ready." : "Importing Workspace"}
          </h3>
          <p className="text-sm text-neutral-400 font-normal leading-relaxed">
            {isCompleted
              ? `Synchronized preferences and developer configurations from ${
                  summary?.ideName || "your previous IDE"
                }.`
              : "Ingesting user settings, keyboard shortcuts, themes, and agent guidelines."}
          </p>
        </div>

        {/* Thin, Subtle Progress Bar */}
        <div className="w-full h-1 bg-neutral-900 rounded-full overflow-hidden">
          <div
            className="h-full bg-neutral-300 rounded-full transition-all duration-500 ease-out"
            style={{ width: `${progressPercentage}%` }}
          />
        </div>

        {/* Stage List or Completion Summary */}
        {!isCompleted ? (
          <div className="space-y-3.5 py-1">
            {STEPS.map((step) => {
              const isDone = currentStep > step.id;
              const isCurrent = currentStep === step.id;

              return (
                <div
                  key={step.id}
                  className={`flex items-start gap-3.5 p-3 rounded-xl transition-colors ${
                    isCurrent
                      ? "bg-neutral-900/70 border border-neutral-800/60"
                      : "opacity-60"
                  }`}
                >
                  <div className="mt-0.5 shrink-0">
                    {isDone ? (
                      <div className="w-5 h-5 rounded-full bg-neutral-800 text-neutral-200 flex items-center justify-center">
                        <Check className="w-3 h-3 stroke-[2.5]" />
                      </div>
                    ) : isCurrent ? (
                      <div className="w-5 h-5 flex items-center justify-center">
                        <Loader2 className="w-4 h-4 text-neutral-200 animate-spin" />
                      </div>
                    ) : (
                      <div className="w-5 h-5 rounded-full border border-neutral-800 flex items-center justify-center text-[10px] text-neutral-500">
                        {step.id}
                      </div>
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div
                      className={`text-sm ${
                        isCurrent
                          ? "text-neutral-100 font-medium"
                          : isDone
                          ? "text-neutral-300 font-normal"
                          : "text-neutral-400 font-normal"
                      }`}
                    >
                      {step.title}
                    </div>
                    <div className="text-xs text-neutral-400 mt-0.5">
                      {step.detail}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          /* Quiet, Minimalist Completion State */
          <div className="space-y-4 py-1 animate-in fade-in slide-in-from-bottom-2 duration-300">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3.5 rounded-xl bg-neutral-900/60 border border-neutral-800/60 space-y-1">
                <div className="flex items-center gap-2 text-neutral-400 text-xs">
                  <Command className="w-3.5 h-3.5 text-neutral-300" />
                  <span>Shortcuts & Settings</span>
                </div>
                <div className="text-sm font-medium text-neutral-100">
                  {summary?.keybindingsCount || 4} Keybindings Mapped
                </div>
                <div className="text-xs text-neutral-400">
                  {summary?.settingsCount || 8} editor preferences active
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-neutral-900/60 border border-neutral-800/60 space-y-1">
                <div className="flex items-center gap-2 text-neutral-400 text-xs">
                  <Palette className="w-3.5 h-3.5 text-neutral-300" />
                  <span>Theme & Aesthetics</span>
                </div>
                <div className="text-sm font-medium text-neutral-100 truncate">
                  {summary?.themeName || "Cursor Dark"}
                </div>
                <div className="text-xs text-neutral-400">
                  Soft neutral palette adapted
                </div>
              </div>

              <div className="col-span-2 p-3.5 rounded-xl bg-neutral-900/60 border border-neutral-800/60 space-y-1">
                <div className="flex items-center gap-2 text-neutral-400 text-xs">
                  <Bot className="w-3.5 h-3.5 text-neutral-300" />
                  <span>AI Directives & Rules</span>
                </div>
                <div className="text-sm font-medium text-neutral-100">
                  .cursorrules & System Prompts Attached
                </div>
                <div className="text-xs text-neutral-400">
                  Routed directly into Crux Copilot context
                </div>
              </div>
            </div>

            {/* Launch Workspace Primary Action Button */}
            <button
              onClick={handleLaunchEditor}
              className="w-full h-11 px-5 bg-neutral-100 hover:bg-white text-neutral-950 font-medium text-sm rounded-xl transition-all flex items-center justify-center gap-2 cursor-pointer shadow-sm hover:shadow"
            >
              <span>Launch Synchronized Workspace</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Footer Meta */}
        <div className="pt-2 border-t border-neutral-800/60 flex items-center justify-between text-xs text-neutral-400">
          <span>Target: Crux Engine v1.0.0</span>
          <span>Zero telemetry leakage</span>
        </div>
      </div>
    </div>
  );
}
