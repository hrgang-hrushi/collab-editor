"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import { EditorState } from "@codemirror/state";
import {
  EditorView,
  keymap,
  lineNumbers,
  highlightActiveLine,
  highlightActiveLineGutter,
} from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { javascript } from "@codemirror/lang-javascript";
import { python } from "@codemirror/lang-python";
import { css } from "@codemirror/lang-css";
import { html } from "@codemirror/lang-html";
import { json } from "@codemirror/lang-json";
import { syntaxHighlighting, HighlightStyle } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";
import { useWorkspaceStore } from "@/lib/store";
import { FileNode } from "@/lib/types";
import {
  Check,
  X,
  MessageSquare,
  Sparkles,
  CornerDownLeft,
  Loader2,
  Bot,
} from "lucide-react";
import ContextualCommentPanel from "../threads/ContextualCommentPanel";

const cruxHighlightStyle = HighlightStyle.define([
  { tag: t.keyword, color: "#5e6ad2", fontWeight: "500" },
  { tag: [t.controlKeyword, t.moduleKeyword], color: "#5e6ad2", fontWeight: "500" },
  { tag: [t.name, t.deleted, t.character, t.macroName], color: "#f7f8f8" },
  { tag: [t.function(t.variableName), t.function(t.propertyName), t.labelName], color: "#f7f8f8", fontWeight: "500" },
  { tag: [t.color, t.constant(t.name), t.standard(t.name)], color: "#d0d6e0" },
  { tag: [t.definition(t.name), t.separator], color: "#f7f8f8" },
  { tag: [t.typeName, t.className, t.namespace, t.changed], color: "#d0d6e0", fontWeight: "500" },
  { tag: [t.number], color: "#8a8f98" },
  { tag: [t.bool, t.null], color: "#5e6ad2", fontWeight: "500" },
  { tag: [t.operator, t.operatorKeyword], color: "#8a8f98" },
  { tag: [t.url, t.escape, t.regexp, t.link], color: "#8a8f98" },
  { tag: [t.meta, t.comment], color: "#62666d", fontStyle: "italic" },
  { tag: t.strong, fontWeight: "bold" },
  { tag: t.emphasis, fontStyle: "italic" },
  { tag: t.strikethrough, textDecoration: "line-through" },
  { tag: t.link, color: "#5e6ad2", textDecoration: "underline" },
  { tag: t.heading, fontWeight: "bold", color: "#f7f8f8" },
  { tag: [t.atom, t.self], color: "#5e6ad2" },
  { tag: [t.string, t.special(t.string)], color: "#27a644" },
  { tag: [t.propertyName, t.attributeName], color: "#d0d6e0" },
  { tag: [t.bracket, t.punctuation], color: "#8a8f98" },
]);

const cruxEditorTheme = EditorView.theme({
  "&": {
    height: "100%",
    fontSize: "12.5px",
    backgroundColor: "#000000 !important",
    color: "#f7f8f8",
  },
  ".cm-content": {
    fontFamily: "var(--font-geist-mono), 'Geist Mono', 'SF Mono', 'JetBrains Mono', Menlo, monospace",
    padding: "8px 0",
    caretColor: "#5e6ad2",
  },
  ".cm-cursor": {
    borderLeftColor: "#5e6ad2 !important",
    borderLeftWidth: "2px !important",
  },
  "&.cm-focused .cm-cursor": {
    borderLeftColor: "#5e6ad2 !important",
  },
  "&.cm-focused .cm-selectionBackground, ::selection, .cm-selectionLayer .cm-selectionBackground": {
    backgroundColor: "rgba(94, 106, 210, 0.25) !important",
  },
  ".cm-activeLine": {
    backgroundColor: "#0A0A0A !important",
  },
  ".cm-gutters": {
    backgroundColor: "#000000 !important",
    color: "#62666d !important",
    borderRight: "1px solid #222222 !important",
    paddingRight: "6px",
  },
  ".cm-activeLineGutter": {
    backgroundColor: "#0A0A0A !important",
    color: "#f7f8f8 !important",
    fontWeight: "600",
  },
  ".cm-lineNumbers .cm-gutterElement": {
    padding: "0 10px 0 6px !important",
    fontSize: "11px",
    minWidth: "32px",
    textAlign: "right",
    color: "#62666d",
  },
});

interface CodeMirrorEditorProps {
  file: FileNode;
}

export default function CodeMirrorEditor({ file }: CodeMirrorEditorProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);

  const updateFileContent = useWorkspaceStore((state) => state.updateFileContent);
  const suggestions = useWorkspaceStore((state) => state.suggestions);
  const comments = useWorkspaceStore((state) => state.comments);
  const acceptSuggestion = useWorkspaceStore((state) => state.acceptSuggestion);
  const rejectSuggestion = useWorkspaceStore((state) => state.rejectSuggestion);
  const addSuggestion = useWorkspaceStore((state) => state.addSuggestion);
  const addComment = useWorkspaceStore((state) => state.addComment);
  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const setCursorPos = useWorkspaceStore((state) => state.setCursorPos);
  const triggerAiGenerate = useWorkspaceStore((state) => state.triggerAiGenerate);
  const isAiGenerating = useWorkspaceStore((state) => state.isAiGenerating);

  // Active selection state for floating HUD
  const [selectedRange, setSelectedRange] = useState<{
    from: number;
    to: number;
    text: string;
    coords?: { top: number; left: number };
  } | null>(null);

  const [activeThreadId, setActiveThreadId] = useState<string | null>(null);

  // Inline AI Co-Pilot prompt bar
  const [isAiBarOpen, setIsAiBarOpen] = useState(false);
  const [aiPromptText, setAiPromptText] = useState("");

  // Modals for manual comment & suggestion
  const [suggestionModal, setSuggestionModal] = useState<{
    isOpen: boolean;
    from: number;
    to: number;
    originalText: string;
    suggestedText: string;
    description: string;
  } | null>(null);

  const [commentModal, setCommentModal] = useState<{
    isOpen: boolean;
    lineNumber: number;
    snippet: string;
    text: string;
  } | null>(null);

  // Language extension selector
  const getLanguageExtension = useCallback((lang: string) => {
    switch (lang) {
      case "typescript":
      case "javascript":
        return javascript({ typescript: true, jsx: true });
      case "python":
        return python();
      case "css":
        return css();
      case "html":
        return html();
      case "json":
        return json();
      default:
        return javascript({ typescript: true });
    }
  }, []);

  // Mount CodeMirror 6 instance
  useEffect(() => {
    if (typeof window !== "undefined") {
      (window as any).__cm_mounted__ = ((window as any).__cm_mounted__ || 0) + 1;
      (window as any).__cm_last_file__ = file.id;
    }
    if (!containerRef.current) return;

    const startState = EditorState.create({
      doc: file.content,
      extensions: [
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightActiveLine(),
        history(),
        getLanguageExtension(file.language),
        syntaxHighlighting(cruxHighlightStyle),
        cruxEditorTheme,
        keymap.of([...defaultKeymap, ...historyKeymap]),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            const newContent = update.state.doc.toString();
            updateFileContent(file.id, newContent);
          }

          if (update.selectionSet) {
            const sel = update.state.selection.main;
            const line = update.state.doc.lineAt(sel.head);
            setCursorPos({
              line: line.number,
              col: sel.head - line.from + 1,
            });

            if (!sel.empty) {
              const selectedText = update.state.doc.sliceString(sel.from, sel.to);
              const coords = viewRef.current?.coordsAtPos(sel.to);
              if (coords && containerRef.current) {
                const rect = containerRef.current.getBoundingClientRect();
                setSelectedRange({
                  from: sel.from,
                  to: sel.to,
                  text: selectedText,
                  coords: {
                    top: Math.max(8, coords.top - rect.top - 38),
                    left: Math.max(16, coords.left - rect.left - 40),
                  },
                });
              }
            } else {
              setSelectedRange(null);
            }
          }
        }),
      ],
    });

    const view = new EditorView({
      state: startState,
      parent: containerRef.current,
    });

    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
  }, [file.id, getLanguageExtension]);

  // Keep editor content in sync when updated externally (e.g. accepted suggestion)
  useEffect(() => {
    if (viewRef.current) {
      const currentDoc = viewRef.current.state.doc.toString();
      if (currentDoc !== file.content) {
        viewRef.current.dispatch({
          changes: { from: 0, to: currentDoc.length, insert: file.content },
        });
      }
    }
  }, [file.content]);

  // Hotkey listener for Cmd+I (AI Assistant)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "i") {
        e.preventDefault();
        setIsAiBarOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Pending suggestions for this file
  const pendingSuggestions = suggestions.filter(
    (s) => s.fileId === file.id && s.status === "pending"
  );

  // Active contextual comments for this file
  const fileComments = comments.filter((c) => c.fileId === file.id && !c.resolved);

  const handleAcceptSuggestion = (sugId: string) => {
    acceptSuggestion(sugId);
  };

  const handleOpenCommentFromSelection = () => {
    if (!selectedRange || !viewRef.current) return;
    const line = viewRef.current.state.doc.lineAt(selectedRange.from);
    setCommentModal({
      isOpen: true,
      lineNumber: line.number,
      snippet: selectedRange.text.split("\n")[0] || line.text,
      text: "",
    });
    setSelectedRange(null);
  };

  const handleOpenSuggestFromSelection = () => {
    if (!selectedRange) return;
    setSuggestionModal({
      isOpen: true,
      from: selectedRange.from,
      to: selectedRange.to,
      originalText: selectedRange.text,
      suggestedText: selectedRange.text,
      description: "",
    });
    setSelectedRange(null);
  };

  const handleOpenAiFromSelection = () => {
    setIsAiBarOpen(true);
    if (selectedRange) {
      setAiPromptText(`Refactor: "${selectedRange.text.slice(0, 30)}..." `);
    }
    setSelectedRange(null);
  };

  const handleSubmitSuggestion = (e: React.FormEvent) => {
    e.preventDefault();
    if (!suggestionModal) return;
    addSuggestion({
      fileId: file.id,
      author: currentUser,
      from: suggestionModal.from,
      to: suggestionModal.to,
      originalText: suggestionModal.originalText,
      suggestedText: suggestionModal.suggestedText,
      description: suggestionModal.description || "Proposed inline refinement",
    });
    setSuggestionModal(null);
  };

  const handleSubmitComment = (e: React.FormEvent) => {
    e.preventDefault();
    if (!commentModal || !commentModal.text.trim()) return;
    addComment(
      file.id,
      commentModal.lineNumber,
      commentModal.snippet,
      commentModal.text.trim()
    );
    setCommentModal(null);
  };

  const handleAiSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!aiPromptText.trim() || isAiGenerating) return;
    await triggerAiGenerate(aiPromptText.trim());
    setAiPromptText("");
    setIsAiBarOpen(false);
  };

  return (
    <div className="relative w-full h-full flex flex-col bg-linear-canvas font-code overflow-hidden select-text">
      {/* CodeMirror Mount Point */}
      <div ref={containerRef} className="flex-1 w-full h-full overflow-auto" />

      {/* Floating Selection Tooltip (Linear Style) */}
      {selectedRange && selectedRange.coords && (
        <div
          className="absolute z-40 flex items-center gap-1 p-1 bg-[#141516] border border-[#222222] animate-in fade-in duration-100"
          style={{
            top: `${selectedRange.coords.top}px`,
            left: `${selectedRange.coords.left}px`,
          }}
        >
          <button
            onClick={handleOpenCommentFromSelection}
            className="flex items-center gap-1.5 px-2 py-0.5 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#191a1b] text-xs font-mono transition"
          >
            <MessageSquare className="w-3.5 h-3.5 text-[#5e6ad2]" />
            <span>Comment</span>
          </button>
          <div className="w-[1px] h-3 bg-[#222222]" />
          <button
            onClick={handleOpenSuggestFromSelection}
            className="flex items-center gap-1.5 px-2 py-0.5 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#191a1b] text-xs font-mono transition"
          >
            <Sparkles className="w-3.5 h-3.5 text-[#5e6ad2]" />
            <span>Suggest</span>
          </button>
          <div className="w-[1px] h-3 bg-[#222222]" />
          <button
            onClick={handleOpenAiFromSelection}
            className="flex items-center gap-1.5 px-2 py-0.5 text-[#8a8f98] hover:text-[#f7f8f8] hover:bg-[#191a1b] text-xs font-mono transition"
          >
            <Bot className="w-3.5 h-3.5 text-[#5e6ad2]" />
            <span>Ask AI</span>
          </button>
        </div>
      )}

      {/* Floating AI Co-Pilot Prompt Bar (Cmd+I) */}
      {isAiBarOpen && (
        <div className="absolute top-4 left-1/2 -translate-x-1/2 z-40 w-full max-w-lg p-2 bg-[#0A0A0A] border border-[#222222] animate-in slide-in-from-top-3 duration-150 font-mono">
          <form onSubmit={handleAiSubmit} className="flex items-center gap-2">
            <div className="p-1 bg-[#141516] border border-[#222222] text-[#5e6ad2]">
              <Sparkles className="w-4 h-4" />
            </div>
            <input
              type="text"
              autoFocus
              value={aiPromptText}
              onChange={(e) => setAiPromptText(e.target.value)}
              placeholder="Ask CruxAI to refactor or generate code..."
              className="flex-1 bg-transparent text-xs text-linear-ink placeholder-linear-ink-tertiary focus:outline-none font-sans"
            />
            {isAiGenerating ? (
              <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-linear-surface-2 text-linear-ink-subtle text-xs font-mono">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-linear-primary" />
                <span>Thinking...</span>
              </div>
            ) : (
              <button
                type="submit"
                disabled={!aiPromptText.trim()}
                className="btn-primary h-7 px-2.5 text-xs disabled:opacity-40"
              >
                <span>Generate</span>
                <CornerDownLeft className="w-3 h-3" />
              </button>
            )}
            <button
              type="button"
              onClick={() => setIsAiBarOpen(false)}
              className="p-1 text-linear-ink-subtle hover:text-linear-ink rounded"
            >
              <X className="w-4 h-4" />
            </button>
          </form>

          {/* Quick presets */}
          <div className="flex items-center gap-1.5 pt-1.5 mt-1.5 border-t border-linear-hairline text-[11px] font-sans text-linear-ink-subtle">
            <span className="text-[10px] text-linear-ink-tertiary uppercase font-mono">Presets:</span>
            <button
              type="button"
              onClick={() => setAiPromptText("Add exponential backoff with full jitter to reconnection loop")}
              className="px-1.5 py-0.5 rounded bg-linear-surface-2 hover:bg-linear-surface-3 text-linear-ink-muted transition text-[11px]"
            >
              + Exponential Jitter
            </button>
            <button
              type="button"
              onClick={() => setAiPromptText("Add zero-knowledge signature verification guard")}
              className="px-1.5 py-0.5 rounded bg-linear-surface-2 hover:bg-linear-surface-3 text-linear-ink-muted transition text-[11px]"
            >
              + Signature Guard
            </button>
          </div>
        </div>
      )}



      {/* Living Comment Gutter Markers */}
      <div className="absolute top-3 right-3 z-20 space-y-1.5">
        {fileComments.map((thread) => (
          <div key={thread.id} className="relative">
            <button
              onClick={() =>
                setActiveThreadId(activeThreadId === thread.id ? null : thread.id)
              }
              className="flex items-center gap-1.5 px-2 py-0.5 bg-[#141516] hover:bg-[#191a1b] border border-[#222222] text-[#5e6ad2] text-[11px] font-mono transition"
            >
              <MessageSquare className="w-3 h-3" />
              <span>Line {thread.lineNumber}</span>
              <span className="w-1.5 h-1.5 bg-[#5e6ad2]" />
            </button>

            {/* Anchored Expanded Thread */}
            {activeThreadId === thread.id && (
              <div className="absolute top-7 right-0 z-50">
                <ContextualCommentPanel
                  thread={thread}
                  onClose={() => setActiveThreadId(null)}
                />
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Suggestion Modal */}
      {suggestionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 font-mono">
          <div className="w-full max-w-md p-4 bg-[#0A0A0A] border border-[#222222] text-[#f7f8f8] space-y-3 font-mono">
            <div className="flex items-center justify-between pb-2 border-b border-[#222222]">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[#5e6ad2]" />
                <h3 className="font-semibold text-xs">Propose Inline Diff</h3>
              </div>
              <button
                onClick={() => setSuggestionModal(null)}
                className="text-[#8a8f98] hover:text-[#f7f8f8] p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <label className="text-[11px] text-linear-ink-subtle uppercase tracking-wider font-mono">
                Original Buffer
              </label>
              <div className="p-2 mt-1 rounded bg-linear-canvas border border-rose-500/20 font-code text-xs text-rose-300 line-through">
                {suggestionModal.originalText}
              </div>
            </div>

            <div>
              <label className="text-[11px] text-linear-ink-subtle uppercase tracking-wider font-mono">
                Proposed Replacement
              </label>
              <textarea
                rows={3}
                value={suggestionModal.suggestedText}
                onChange={(e) =>
                  setSuggestionModal({
                    ...suggestionModal,
                    suggestedText: e.target.value,
                  })
                }
                className="w-full mt-1 p-2 rounded bg-linear-canvas border border-linear-hairline font-code text-xs text-linear-success focus:outline-none focus:border-linear-primary transition"
              />
            </div>

            <div>
              <label className="text-[11px] text-linear-ink-subtle uppercase tracking-wider font-mono">
                Rationale
              </label>
              <input
                type="text"
                value={suggestionModal.description}
                onChange={(e) =>
                  setSuggestionModal({
                    ...suggestionModal,
                    description: e.target.value,
                  })
                }
                placeholder="e.g. Prevent reconnection lock storm"
                className="w-full mt-1 px-3 py-1.5 rounded bg-linear-canvas border border-linear-hairline text-xs text-linear-ink placeholder-linear-ink-tertiary focus:outline-none focus:border-linear-primary"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-linear-hairline">
              <button
                type="button"
                onClick={() => setSuggestionModal(null)}
                className="btn-secondary"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSubmitSuggestion}
                className="btn-primary"
              >
                <span>Propose Diff</span>
                <CornerDownLeft className="w-3 h-3" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Comment Modal */}
      {commentModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 font-mono">
          <div className="w-full max-w-sm p-4 bg-[#0A0A0A] border border-[#222222] text-[#f7f8f8] space-y-3 font-mono">
            <div className="flex items-center justify-between pb-2 border-b border-[#222222]">
              <div className="flex items-center gap-2">
                <MessageSquare className="w-4 h-4 text-[#5e6ad2]" />
                <h3 className="font-semibold text-xs">
                  Comment on Line {commentModal.lineNumber}
                </h3>
              </div>
              <button
                onClick={() => setCommentModal(null)}
                className="text-[#8a8f98] hover:text-[#f7f8f8] p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-2 bg-black border border-[#222222] font-mono text-xs text-[#8a8f98] truncate">
              <code>{commentModal.snippet}</code>
            </div>

            <form onSubmit={handleSubmitComment} className="space-y-3">
              <textarea
                rows={3}
                autoFocus
                value={commentModal.text}
                onChange={(e) =>
                  setCommentModal({
                    ...commentModal,
                    text: e.target.value,
                  })
                }
                placeholder="Leave feedback or ask a question..."
                className="w-full p-2 rounded bg-linear-canvas border border-linear-hairline text-xs text-linear-ink placeholder-linear-ink-tertiary focus:outline-none focus:border-linear-primary transition"
              />

              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setCommentModal(null)}
                  className="btn-secondary"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!commentModal.text.trim()}
                  className="btn-primary disabled:opacity-40"
                >
                  Post Comment
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
