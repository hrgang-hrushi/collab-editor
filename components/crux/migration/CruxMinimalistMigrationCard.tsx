"use client";

import React, { useState, useEffect } from "react";
import { ArrowRight, Sparkles, Sliders } from "lucide-react";
import { scanExistingIdes } from "@/lib/migration/engine";
import { IdeScanManifest } from "@/lib/migration/types";
import CruxMinimalistMigrationModal from "./CruxMinimalistMigrationModal";

interface CruxMinimalistMigrationCardProps {
  className?: string;
  onMigrationComplete?: () => void;
}

export default function CruxMinimalistMigrationCard({
  className = "",
  onMigrationComplete,
}: CruxMinimalistMigrationCardProps) {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [detectedSummary, setDetectedSummary] = useState<string>("VS Code & Cursor detected");

  useEffect(() => {
    let mounted = true;
    scanExistingIdes()
      .then((manifest: IdeScanManifest) => {
        if (!mounted) return;
        if (manifest.ides.length > 0) {
          const names = manifest.ides.map((i) => i.name).join(" & ");
          setDetectedSummary(`${names} configuration available`);
        }
      })
      .catch(() => {
        // keep gentle default
      });

    return () => {
      mounted = false;
    };
  }, []);

  return (
    <>
      <div
        className={`w-full max-w-md p-5 rounded-2xl bg-neutral-900/60 border border-neutral-800/80 text-neutral-200 font-sans transition-all hover:border-neutral-700/80 hover:bg-neutral-900/80 ${className}`}
      >
        <div className="flex items-start justify-between gap-4 mb-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400/80" />
              <span className="text-[11px] font-medium text-neutral-400 tracking-wide">
                ONE-CLICK MIGRATION
              </span>
            </div>
            <h4 className="text-sm font-semibold text-neutral-100 tracking-tight">
              Import Existing Workspace
            </h4>
          </div>
          <div className="p-2 rounded-xl bg-neutral-800/50 border border-neutral-700/40 text-neutral-300 shrink-0">
            <Sliders className="w-4 h-4" />
          </div>
        </div>

        <p className="text-xs text-neutral-400 leading-relaxed mb-4">
          Seamlessly ingest your shortcuts, themes, extensions, and AI agent rules
          from your local environment.
        </p>

        <div className="flex items-center justify-between pt-1">
          <span className="text-[11px] text-neutral-400 truncate max-w-[190px]">
            {detectedSummary}
          </span>
          <button
            onClick={() => setIsModalOpen(true)}
            className="px-3.5 py-2 bg-neutral-100 hover:bg-white text-neutral-950 text-xs font-medium rounded-xl transition-all flex items-center gap-1.5 cursor-pointer shadow-sm hover:shadow"
          >
            <span>Import from VS Code / Cursor</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <CruxMinimalistMigrationModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onComplete={onMigrationComplete}
      />
    </>
  );
}
