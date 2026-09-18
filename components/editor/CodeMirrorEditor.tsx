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

// Official VS Code Dark+ Color Palette
const cruxHighlightStyle = HighlightStyle.define([
  { tag: t.keyword, color: "#569cd6" },
  { tag: [t.controlKeyword, t.moduleKeyword], color: "#c586c0" },
  { tag: [t.name, t.deleted, t.character, t.macroName], color: "#d4d4d4" },
  { tag: [t.function(t.variableName), t.function(t.propertyName), t.labelName], color: "#dcdcaa" },
  { tag: [t.color, t.constant(t.name), t.standard(t.name)], color: "#4fc1ff" },
  { tag: [t.definition(t.name), t.separator], color: "#d4d4d4" },
  { tag: [t.typeName, t.className, t.namespace, t.changed], color: "#4ec9b0" },
  { tag: [t.number], color: "#b5cea8" },
  { tag: [t.bool, t.null], color: "#569cd6" },
  { tag: [t.operator, t.operatorKeyword], color: "#d4d4d4" },
  { tag: [t.url, t.escape, t.regexp, t.link], color: "#d7ba7d" },
  { tag: [t.meta, t.comment], color: "#6a9955", fontStyle: "italic" },
  { tag: t.strong, fontWeight: "bold" },
  { tag: t.emphasis, fontStyle: "italic" },
  { tag: t.strikethrough, textDecoration: "line-through" },
  { tag: t.link, color: "#4fc1ff", textDecoration: "underline" },
  { tag: t.heading, fontWeight: "bold", color: "#d4d4d4" },
  { tag: [t.atom, t.self], color: "#569cd6" },
  { tag: [t.string, t.special(t.string)], color: "#ce9178" },
  { tag: [t.propertyName, t.attributeName], color: "#9cdcfe" },
  { tag: [t.variableName], color: "#9cdcfe" },
  { tag: [t.bracket, t.punctuation], color: "#ffd700" },
]);

const cruxEditorTheme = EditorView.theme({
  "&": {
    height: "100%",
    fontSize: "13px",
    backgroundColor: "#1e1e1e !important",
    color: "#d4d4d4",
  },
  ".cm-content": {
    fontFamily: "Menlo, Monaco, 'Courier New', var(--font-geist-mono), monospace",
    padding: "8px 0",
    caretColor: "#aeafad",
    lineHeight: "1.55",
  },
  ".cm-cursor": {
    borderLeftColor: "#aeafad !important",
    borderLeftWidth: "2px !important",
  },
  "&.cm-focused .cm-cursor": {
    borderLeftColor: "#aeafad !important",
  },
  "&.cm-focused .cm-selectionBackground, ::selection, .cm-selectionLayer .cm-selectionBackground": {
    backgroundColor: "#264f78 !important",
  },
  ".cm-activeLine": {
    backgroundColor: "#282828 !important",
  },
  ".cm-gutters": {
    backgroundColor: "#1e1e1e !important",
    color: "#858585 !important",
    borderRight: "1px solid #2b2b2b !important",
    paddingRight: "6px",
  },
  ".cm-activeLineGutter": {
    backgroundColor: "#282828 !important",
    color: "#c6c6c6 !important",
  },
  ".cm-lineNumbers .cm-gutterElement": {
    padding: "0 10px 0 8px !important",
    fontSize: "12px",
    minWidth: "38px",
    textAlign: "right",
    color: "#858585",
  },
});

interface CodeMirrorEditorProps {
  file: FileNode;
  readOnly?: boolean;
}

export default function CodeMirrorEditor({ file, readOnly = false }: CodeMirrorEditorProps) {
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
  const aiInputRef = useRef<HTMLInputElement>(null);

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
        ...(readOnly ? [EditorState.readOnly.of(true)] : []),
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
  }, [file.id, getLanguageExtension, readOnly]);

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
    <div className="relative w-full h-full flex flex-col bg-[#07080b] font-code overflow-hidden select-text">
      {/* CodeMirror Mount Point */}
      <div ref={containerRef} className="flex-1 w-full h-full overflow-auto" />

      {/* Floating Selection Tooltip */}
      {selectedRange && selectedRange.coords && (
        <div
          className="absolute z-40 flex items-center gap-1 p-1 rounded bg-[#252526] border border-[#2d2d2d] shadow-xl animate-in fade-in duration-100"
          style={{
            top: `${selectedRange.coords.top}px`,
            left: `${selectedRange.coords.left}px`,
          }}
        >
          <button
            onClick={handleOpenCommentFromSelection}
            className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[#cccccc] hover:text-white hover:bg-[#333333] text-xs font-sans transition-colors"
          >
            <MessageSquare className="w-3.5 h-3.5 text-[#4ec9b0]" />
            <span>Comment</span>
          </button>
          <div className="w-[1px] h-3 bg-[#3e3e42]" />
          <button
            onClick={handleOpenSuggestFromSelection}
            className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[#cccccc] hover:text-white hover:bg-[#333333] text-xs font-sans transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5 text-[#dcdcaa]" />
            <span>Suggest</span>
          </button>
          <div className="w-[1px] h-3 bg-[#3e3e42]" />
          <button
            onClick={handleOpenAiFromSelection}
            className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[#cccccc] hover:text-white hover:bg-[#333333] text-xs font-sans transition-colors"
          >
            <Bot className="w-3.5 h-3.5 text-[#007acc]" />
            <span>Ask AI</span>
          </button>
        </div>
      )}

      {/* Floating AI Co-Pilot Prompt Bar (Cmd+I) */}
      {isAiBarOpen && (
        <div className="absolute top-4 left-1/2 -translate-x-1/2 z-40 w-full max-w-lg p-2.5 rounded bg-[#252526] border border-[#2d2d2d] shadow-2xl animate-in slide-in-from-top-2 duration-100 font-sans">
          <form onSubmit={handleAiSubmit} className="flex items-center gap-2">
            <Bot className="w-4 h-4 text-[#007acc] shrink-0" />
            <input
              ref={aiInputRef}
              type="text"
              value={aiPromptText}
              onChange={(e) => setAiPromptText(e.target.value)}
              placeholder="Ask CruxAI to edit, refactor or synthesize..."
              className="flex-1 bg-[#1e1e1e] border border-[#3e3e42] focus:border-[#007acc] rounded text-xs text-[#cccccc] placeholder-[#858585] px-2.5 py-1.5 focus:outline-none"
            />
            <button
              type="submit"
              className="px-2.5 py-1 bg-[#007acc] hover:bg-[#0062a3] text-white rounded text-xs font-medium transition-colors"
            >
              Generate
            </button>
            <button
              type="button"
              onClick={() => setIsAiBarOpen(false)}
              className="p-1 rounded text-[#858585] hover:text-[#cccccc] hover:bg-[#333333]"
            >
              <X className="w-4 h-4" />
            </button>
          </form>

          {/* Quick presets */}
          <div className="flex items-center gap-1.5 pt-2 mt-2 border-t border-[#2d2d2d] text-xs text-[#858585]">
            <span className="text-[10px] uppercase font-mono font-medium">Presets:</span>
            <button
              type="button"
              onClick={() => setAiPromptText("Add exponential backoff with full jitter to reconnection loop")}
              className="px-1.5 py-0.2 rounded bg-[#333333] hover:bg-[#3e3e42] text-[#cccccc] border border-[#3e3e42] transition-colors text-[11px]"
            >
              + Exponential Jitter
            </button>
            <button
              type="button"
              onClick={() => setAiPromptText("Add zero-knowledge signature verification guard")}
              className="px-1.5 py-0.2 rounded bg-[#333333] hover:bg-[#3e3e42] text-[#cccccc] border border-[#3e3e42] transition-colors text-[11px]"
            >
              + Signature Guard
            </button>
          </div>
        </div>
      )}

      {/* Living Comment Gutter Markers */}
      <div className="absolute top-4 right-4 z-20 space-y-2">
        {fileComments.map((thread) => (
          <div key={thread.id} className="relative">
            <button
              onClick={() =>
                setActiveThreadId(activeThreadId === thread.id ? null : thread.id)
              }
              className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#252526] border border-[#3e3e42] hover:border-[#007acc] text-[#cccccc] text-xs font-mono transition-colors"
            >
              <MessageSquare className="w-3.5 h-3.5 text-[#4ec9b0]" />
              <span>Line {thread.lineNumber}</span>
              <span className="w-1.5 h-1.5 rounded-full bg-[#4ec9b0]" />
            </button>

            {/* Anchored Expanded Thread */}
            {activeThreadId === thread.id && (
              <div className="absolute top-8 right-0 z-50">
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
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 font-sans animate-in fade-in duration-100">
          <div className="w-full max-w-md p-4 bg-[#252526] border border-[#2d2d2d] rounded text-[#cccccc] space-y-3.5 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-[#2d2d2d]">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[#007acc]" />
                <h3 className="font-semibold text-xs text-white font-sans">Propose Inline Diff</h3>
              </div>
              <button
                onClick={() => setSuggestionModal(null)}
                className="text-[#858585] hover:text-white p-1 rounded hover:bg-[#333333] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <label className="text-[10px] text-[#858585] uppercase tracking-wider font-mono font-medium">
                Original Buffer
              </label>
              <div className="p-2 mt-1 rounded bg-[#1e1e1e] border border-[#3e3e42] font-mono text-xs text-[#f87171] line-through">
                {suggestionModal.originalText}
              </div>
            </div>

            <div>
              <label className="text-[10px] text-[#858585] uppercase tracking-wider font-mono font-medium">
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
                className="w-full mt-1 p-2 rounded bg-[#1e1e1e] border border-[#3e3e42] focus:border-[#007acc] font-mono text-xs text-[#4ec9b0] focus:outline-none transition-colors"
              />
            </div>

            <div>
              <label className="text-[10px] text-[#858585] uppercase tracking-wider font-mono font-medium">
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
                className="w-full mt-1 px-2.5 py-1.5 rounded bg-[#1e1e1e] border border-[#3e3e42] text-xs text-[#cccccc] placeholder-[#858585] focus:outline-none focus:border-[#007acc] transition-colors"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#2d2d2d]">
              <button
                type="button"
                onClick={() => setSuggestionModal(null)}
                className="px-2.5 py-1 rounded text-xs text-[#858585] hover:text-[#cccccc] hover:bg-[#333333] transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSubmitSuggestion}
                className="px-3 py-1 bg-[#007acc] hover:bg-[#0062a3] text-white rounded text-xs font-medium transition-colors flex items-center gap-1"
              >
                <span>Propose Diff</span>
                <CornerDownLeft className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Comment Modal */}
      {commentModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 font-sans animate-in fade-in duration-100">
          <div className="w-full max-w-sm p-4 bg-[#252526] border border-[#2d2d2d] rounded text-[#cccccc] space-y-3.5 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-[#2d2d2d]">
              <div className="flex items-center gap-2">
                <MessageSquare className="w-4 h-4 text-[#007acc]" />
                <h3 className="font-semibold text-xs text-white font-sans">
                  Comment on Line {commentModal.lineNumber}
                </h3>
              </div>
              <button
                onClick={() => setCommentModal(null)}
                className="text-[#858585] hover:text-white p-1 rounded hover:bg-[#333333] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-2 bg-[#1e1e1e] rounded border border-[#2d2d2d] font-mono text-xs text-[#858585] truncate">
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
                className="w-full p-2 rounded bg-[#1e1e1e] border border-[#3e3e42] text-xs text-[#cccccc] placeholder-[#858585] focus:outline-none focus:border-[#007acc] transition-colors"
              />

              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setCommentModal(null)}
                  className="px-2.5 py-1 rounded text-xs text-[#858585] hover:text-[#cccccc] hover:bg-[#333333] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!commentModal.text.trim()}
                  className="px-3 py-1 bg-[#007acc] hover:bg-[#0062a3] text-white rounded text-xs font-medium disabled:opacity-40 transition-colors"
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
