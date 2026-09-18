"use client";

import React, { useState } from "react";
import { useWorkspaceStore } from "@/lib/store";
import {
  X,
  Package,
  Search,
  Plus,
  Check,
  Download,
  Terminal,
  Code2,
  ExternalLink,
  Sparkles,
} from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";
import { LibraryPackage } from "@/lib/types";

export default function CruxLibraryModal() {
  const isLibraryModalOpen = useWorkspaceStore((state) => state.isLibraryModalOpen);
  const setLibraryModalOpen = useWorkspaceStore((state) => state.setLibraryModalOpen);
  const libraries = useWorkspaceStore((state) => state.libraries);
  const installLibrary = useWorkspaceStore((state) => state.installLibrary);
  const insertLibraryImport = useWorkspaceStore((state) => state.insertLibraryImport);
  const files = useWorkspaceStore((state) => state.files);
  const activeFileId = useWorkspaceStore((state) => state.activeFileId);

  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [injectedLibId, setInjectedLibId] = useState<string | null>(null);
  const [customPackageName, setCustomPackageName] = useState("");

  if (!isLibraryModalOpen) return null;

  const activeFile = files.find((f) => f.id === activeFileId) || files[0];

  const categories = [
    { id: "all", label: "All Packages" },
    { id: "core", label: "Crux Core" },
    { id: "crdt", label: "CRDT / Sync" },
    { id: "ui", label: "UI / Motion" },
    { id: "utility", label: "Utilities" },
  ];

  const filteredLibraries = libraries.filter((lib) => {
    const matchesCategory =
      selectedCategory === "all" || lib.category === selectedCategory;
    const matchesQuery =
      lib.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lib.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lib.exports.some((exp) =>
        exp.toLowerCase().includes(searchQuery.toLowerCase())
      );
    return matchesCategory && matchesQuery;
  });

  const handleInsertImport = (libId: string) => {
    triggerHaptic("click");
    insertLibraryImport(libId);
    setInjectedLibId(libId);
    setTimeout(() => {
      setInjectedLibId(null);
    }, 1500);
  };

  const handleAddCustomPackage = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = customPackageName.trim().toLowerCase();
    if (!trimmed) return;

    triggerHaptic("click");
    const safeVarName = trimmed.replace(/[^a-zA-Z0-9]/g, "");
    installLibrary({
      name: trimmed,
      version: "latest",
      description: `Installed community package ${trimmed} for workspace runtime`,
      importSnippet: `import * as ${safeVarName} from "${trimmed}";`,
      category: "npm",
      isInstalled: true,
      exports: [safeVarName, "default"],
    });

    setCustomPackageName("");
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 font-sans select-none animate-in fade-in duration-100">
      <div className="w-full max-w-2xl bg-void border border-grid shadow-2xl flex flex-col max-h-[85vh] overflow-hidden">
        {/* Header */}
        <div className="px-5 py-4 border-b border-grid flex items-center justify-between bg-surface shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 border border-grid bg-void flex items-center justify-center">
              <Package className="w-3.5 h-3.5 text-accent1" />
            </div>
            <div>
              <h2 className="text-xs font-bold tracking-widest text-signal uppercase">
                Library & Package Registry
              </h2>
              <p className="text-[11px] font-mono text-muted">
                Active target: <span className="text-signal">{activeFile?.name || "none"}</span>
              </p>
            </div>
          </div>
          <button
            onClick={() => setLibraryModalOpen(false)}
            className="p-1 border border-grid hover:border-signal text-muted hover:text-signal transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Search & Filter Bar */}
        <div className="p-4 border-b border-grid bg-void flex flex-col gap-3 shrink-0">
          <div className="relative">
            <Search className="w-4 h-4 text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search libraries, SDKs, or functions (e.g. yjs, debounce, motion)..."
              className="w-full pl-9 pr-3 py-2 bg-surface border border-grid text-xs font-mono text-signal placeholder-muted/60 focus:outline-none focus:border-accent1 transition-colors"
            />
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto">
            {categories.map((cat) => (
              <button
                key={cat.id}
                onClick={() => setSelectedCategory(cat.id)}
                className={`px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider border transition-colors shrink-0 ${
                  selectedCategory === cat.id
                    ? "bg-signal text-void border-signal font-bold"
                    : "bg-surface text-muted border-grid hover:text-signal hover:border-muted"
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>
        </div>

        {/* Packages List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-void">
          {filteredLibraries.length === 0 ? (
            <div className="py-12 flex flex-col items-center justify-center text-center text-muted font-mono text-xs border border-dashed border-grid">
              <Package className="w-8 h-8 mb-2 text-grid" />
              <span>NO PACKAGES MATCHED &quot;{searchQuery}&quot;</span>
              <p className="text-[11px] mt-1 text-muted">
                Install it directly below as an npm dependency.
              </p>
            </div>
          ) : (
            filteredLibraries.map((lib) => {
              const isInjected = injectedLibId === lib.id;
              const isAlreadyInActiveFile =
                activeFile?.content.includes(`"${lib.name}"`) ||
                activeFile?.content.includes(`'${lib.name}'`);

              return (
                <div
                  key={lib.id}
                  className="p-3.5 border border-grid bg-surface hover:border-muted/60 transition-colors flex flex-col gap-2.5"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-signal">
                          {lib.name}
                        </span>
                        <span className="px-1.5 py-0.2 text-[9px] font-mono border border-grid text-muted">
                          v{lib.version}
                        </span>
                        {lib.isInstalled && (
                          <span className="px-1.5 py-0.2 text-[9px] font-mono border border-[#00FF00]/40 text-[#00FF00] bg-[#00FF00]/10">
                            INSTALLED
                          </span>
                        )}
                        {isAlreadyInActiveFile && (
                          <span className="px-1.5 py-0.2 text-[9px] font-mono border border-accent1/40 text-accent1 bg-accent1/10">
                            IN BUFFER
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-muted font-sans mt-1">
                        {lib.description}
                      </p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleInsertImport(lib.id)}
                        title={`Insert import into ${activeFile?.name}`}
                        className={`px-2.5 py-1 text-[11px] font-mono border flex items-center gap-1.5 transition-all ${
                          isInjected
                            ? "bg-[#00FF00] text-void border-[#00FF00] font-bold"
                            : isAlreadyInActiveFile
                            ? "bg-surface border-grid text-muted hover:text-signal"
                            : "bg-signal text-void border-signal font-medium hover:opacity-90"
                        }`}
                      >
                        {isInjected ? (
                          <>
                            <Check className="w-3 h-3" />
                            <span>INJECTED</span>
                          </>
                        ) : (
                          <>
                            <Code2 className="w-3 h-3" />
                            <span>{isAlreadyInActiveFile ? "Insert Again" : "Insert Import"}</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Exports chips */}
                  <div className="flex items-center gap-1.5 flex-wrap pt-2 border-t border-grid text-[10px] font-mono text-muted">
                    <span className="text-[9px] uppercase tracking-wider text-muted/80">
                      Symbols:
                    </span>
                    {lib.exports.slice(0, 6).map((exp) => (
                      <span
                        key={exp}
                        className="px-1.5 py-0.5 border border-grid bg-void text-[#007AFF]"
                      >
                        {exp}
                      </span>
                    ))}
                    {lib.exports.length > 6 && (
                      <span className="text-muted text-[10px]">
                        +{lib.exports.length - 6} more
                      </span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer Custom Package Installer */}
        <div className="p-4 border-t border-grid bg-surface shrink-0">
          <form onSubmit={handleAddCustomPackage} className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-muted uppercase tracking-wider shrink-0">
              Install NPM:
            </span>
            <input
              type="text"
              value={customPackageName}
              onChange={(e) => setCustomPackageName(e.target.value)}
              placeholder="e.g. zustand, date-fns, three, canvas-confetti"
              className="flex-1 px-3 py-1.5 bg-void border border-grid text-xs font-mono text-signal placeholder-muted/60 focus:outline-none focus:border-accent1"
            />
            <button
              type="submit"
              disabled={!customPackageName.trim()}
              className="px-3 py-1.5 border border-grid bg-void text-muted hover:text-signal hover:border-signal disabled:opacity-40 text-xs font-mono flex items-center gap-1.5 transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Package</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
