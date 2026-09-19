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
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import {
  closeBrackets,
  closeBracketsKeymap,
  autocompletion,
  acceptCompletion,
  completeAnyWord,
  Completion,
  CompletionContext,
  CompletionResult,
  snippetCompletion,
} from "@codemirror/autocomplete";
import { linter, lintGutter, Diagnostic } from "@codemirror/lint";
import { javascript } from "@codemirror/lang-javascript";
import { python } from "@codemirror/lang-python";
import { css } from "@codemirror/lang-css";
import { html } from "@codemirror/lang-html";
import { json } from "@codemirror/lang-json";
import { syntaxHighlighting, HighlightStyle, defaultHighlightStyle, syntaxTree } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";
import { useWorkspaceStore } from "@/lib/store";
import { FileNode, LibraryPackage } from "@/lib/types";
import CruxPointerCursor from "../crux/CruxPointerCursor";
import {
  Check,
  X,
  MessageSquare,
  Sparkles,
  CornerDownLeft,
  Loader2,
  Bot,
  AlertTriangle,
} from "lucide-react";
import ContextualCommentPanel from "../threads/ContextualCommentPanel";
import { initCrexCRDTSession, CrexCRDTSession } from "@/lib/crdt/yjsProvider";
import { createCrexBrutalistCursorExtension } from "@/lib/crdt/codemirrorCursorPlugin";
import RemoteCursorInterpolator from "./RemoteCursorInterpolator";
import { ySyncFacet, ySync, YSyncConfig } from "y-codemirror.next";

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

// Crux Pure Black & White (Monochrome Brutalist) Syntax Highlighting
const cruxMonochromeHighlightStyle = HighlightStyle.define([
  { tag: [t.keyword, t.controlKeyword, t.moduleKeyword], color: "#FFFFFF", fontWeight: "700" },
  { tag: [t.typeName, t.className, t.namespace], color: "#FFFFFF", fontWeight: "600", textDecoration: "underline", textUnderlineOffset: "3px" },
  { tag: [t.function(t.variableName), t.function(t.propertyName), t.labelName], color: "#FFFFFF", fontWeight: "600" },
  { tag: [t.definition(t.name)], color: "#FFFFFF", fontWeight: "500" },
  { tag: [t.variableName, t.propertyName, t.attributeName], color: "#E0E0E0" },
  { tag: [t.name, t.deleted, t.character, t.macroName], color: "#D4D4D4" },
  { tag: [t.string, t.special(t.string)], color: "#A8A8A8", fontStyle: "italic" },
  { tag: [t.number, t.bool, t.null, t.atom, t.self], color: "#FFFFFF", fontWeight: "500" },
  { tag: [t.operator, t.operatorKeyword], color: "#FFFFFF" },
  { tag: [t.bracket, t.punctuation, t.separator], color: "#777777" },
  { tag: [t.meta, t.comment], color: "#555555", fontStyle: "italic" },
  { tag: [t.url, t.escape, t.regexp, t.link], color: "#E0E0E0" },
  { tag: t.strong, fontWeight: "bold" },
  { tag: t.emphasis, fontStyle: "italic" },
  { tag: t.strikethrough, textDecoration: "line-through" },
]);

const cruxEditorTheme = EditorView.theme({
  "&": {
    height: "100%",
    fontSize: "13px",
    backgroundColor: "#000000 !important",
    color: "#FFFFFF",
  },
  ".cm-content": {
    fontFamily: "var(--font-geist-mono), 'JetBrains Mono', Menlo, Monaco, monospace",
    padding: "12px 0",
    caretColor: "#FFFFFF",
    lineHeight: "1.6",
  },
  ".cm-cursor": {
    borderLeftColor: "#FFFFFF !important",
    borderLeftWidth: "2px !important",
  },
  "&.cm-focused .cm-cursor": {
    borderLeftColor: "#FFFFFF !important",
  },
  "&.cm-focused .cm-selectionBackground, ::selection, .cm-selectionLayer .cm-selectionBackground": {
    backgroundColor: "#222222 !important",
  },
  ".cm-activeLine": {
    backgroundColor: "#0A0A0A !important",
  },
  ".cm-gutters": {
    backgroundColor: "#000000 !important",
    color: "#444444 !important",
    borderRight: "1px solid #222222 !important",
    width: "48px !important",
  },
  ".cm-activeLineGutter": {
    backgroundColor: "#111111 !important",
    color: "#FFFFFF !important",
  },
  ".cm-lineNumbers .cm-gutterElement": {
    padding: "0 8px 0 0 !important",
    fontSize: "12px",
    width: "48px !important",
    textAlign: "right",
    color: "#444444",
  },
  // Red Curvy Squiggly Underline for missing tokens / brackets / syntax errors
  ".cm-lintRange-error": {
    backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 6 3' width='6' height='3'%3E%3Cpath d='M0 2.5 Q 1.5 0.5, 3 2.5 T 6 2.5' fill='none' stroke='%23FF453A' stroke-width='1.2'/%3E%3C/svg%3E") !important`,
    backgroundRepeat: "repeat-x !important",
    backgroundPosition: "bottom left !important",
    paddingBottom: "2px !important",
    textDecoration: "underline wavy #FF453A !important",
    textDecorationThickness: "1.5px !important",
    textUnderlineOffset: "3px !important",
  },
  ".cm-lintRange-warning": {
    textDecoration: "underline wavy #ffd700 !important",
  },
  ".cm-lint-marker-error": {
    display: "none !important",
  },
  ".cm-lint-marker-warning": {
    display: "none !important",
  },
  ".cm-gutter-lint": {
    width: "0px !important",
    display: "none !important",
  },
  // Crux Brutalist Autocomplete Popup
  ".cm-tooltip.cm-tooltip-autocomplete": {
    backgroundColor: "#0A0A0A !important",
    border: "1px solid #222222 !important",
    borderRadius: "0px !important",
    boxShadow: "0 12px 32px rgba(0,0,0,0.95) !important",
    padding: "4px !important",
    fontFamily: "var(--font-geist-mono), 'JetBrains Mono', monospace !important",
    minWidth: "260px !important",
  },
  ".cm-completionList": {
    fontFamily: "var(--font-geist-mono), 'JetBrains Mono', monospace !important",
    fontSize: "12px !important",
  },
  ".cm-completionList ul": {
    maxHeight: "220px !important",
  },
  ".cm-completionList li": {
    padding: "4px 8px !important",
    borderRadius: "0px !important",
    color: "#888888 !important",
    display: "flex !important",
    alignItems: "center !important",
    gap: "8px !important",
  },
  ".cm-completionList li[aria-selected]": {
    backgroundColor: "#181818 !important",
    color: "#FFFFFF !important",
    borderLeft: "2px solid #007AFF !important",
  },
  ".cm-completionLabel": {
    fontWeight: "500 !important",
    color: "#FFFFFF !important",
  },
  ".cm-completionDetail": {
    fontStyle: "normal !important",
    fontSize: "10px !important",
    color: "#777777 !important",
    marginLeft: "auto !important",
    fontFamily: "var(--font-geist-mono), monospace !important",
  },
  ".cm-completionMatchedText": {
    color: "#007AFF !important",
    textDecoration: "none !important",
    fontWeight: "bold !important",
  },
  // Crux Brutalist Lint Tooltip
  ".cm-tooltip-lint": {
    backgroundColor: "#0A0A0A !important",
    border: "1px solid #222222 !important",
    borderLeft: "2px solid #FF453A !important",
    color: "#FFFFFF !important",
    fontFamily: "var(--font-geist-mono), monospace !important",
    fontSize: "11px !important",
    borderRadius: "0px !important",
    boxShadow: "0 8px 24px rgba(0,0,0,0.9) !important",
    padding: "6px 10px !important",
  },
  ".cm-diagnostic-error": {
    borderLeft: "none !important",
    padding: "2px 0 !important",
    color: "#FFFFFF !important",
  },
});

// Real-time Syntax & Unclosed Bracket Linter
function cruxLinter(view: EditorView): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const doc = view.state.doc;
  const docString = doc.toString();

  // 1. Bracket & string balance check
  const bracketStack: Array<{ char: string; pos: number }> = [];
  let inDoubleQuote = false;
  let doubleQuoteStart = -1;
  let inSingleQuote = false;
  let singleQuoteStart = -1;
  let inBacktick = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < docString.length; i++) {
    const ch = docString[i];
    const prev = i > 0 ? docString[i - 1] : "";
    const next = i < docString.length - 1 ? docString[i + 1] : "";

    // Comments handling
    if (!inDoubleQuote && !inSingleQuote && !inBacktick) {
      if (ch === "/" && next === "/" && !inBlockComment) {
        inLineComment = true;
        i++;
        continue;
      }
      if (inLineComment && ch === "\n") {
        inLineComment = false;
        continue;
      }
      if (inLineComment) continue;

      if (ch === "/" && next === "*" && !inLineComment) {
        inBlockComment = true;
        i++;
        continue;
      }
      if (inBlockComment && ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
        continue;
      }
      if (inBlockComment) continue;
    }

    if (inLineComment || inBlockComment) continue;

    // Quotes handling
    if (ch === '"' && prev !== "\\" && !inSingleQuote && !inBacktick) {
      if (!inDoubleQuote) {
        inDoubleQuote = true;
        doubleQuoteStart = i;
      } else {
        inDoubleQuote = false;
        doubleQuoteStart = -1;
      }
      continue;
    }
    if (ch === "'" && prev !== "\\" && !inDoubleQuote && !inBacktick) {
      if (!inSingleQuote) {
        inSingleQuote = true;
        singleQuoteStart = i;
      } else {
        inSingleQuote = false;
        singleQuoteStart = -1;
      }
      continue;
    }
    if (ch === "`" && prev !== "\\" && !inDoubleQuote && !inSingleQuote) {
      inBacktick = !inBacktick;
      continue;
    }

    if (inDoubleQuote || inSingleQuote) {
      if (ch === "\n") {
        const start = inDoubleQuote ? doubleQuoteStart : singleQuoteStart;
        diagnostics.push({
          from: start,
          to: i,
          severity: "error",
          message: inDoubleQuote
            ? 'Unclosed string literal — missing \'"\''
            : "Unclosed string literal — missing \"'\"",
        });
        inDoubleQuote = false;
        inSingleQuote = false;
      }
      continue;
    }

    if (inBacktick) continue;

    // Brackets check
    if (ch === "(" || ch === "{" || ch === "[") {
      bracketStack.push({ char: ch, pos: i });
    } else if (ch === ")" || ch === "}" || ch === "]") {
      const match = { ")": "(", "}": "{", "]": "[" }[ch];
      if (bracketStack.length > 0 && bracketStack[bracketStack.length - 1].char === match) {
        bracketStack.pop();
      } else {
        diagnostics.push({
          from: i,
          to: i + 1,
          severity: "error",
          message: `Unexpected closing '${ch}' without matching '${match}'`,
        });
      }
    }
  }

  // Unclosed brackets remaining in stack
  for (const item of bracketStack) {
    const pair = { "(": ")", "{": "}", "[": "]" }[item.char];
    diagnostics.push({
      from: item.pos,
      to: Math.min(doc.length, item.pos + 1),
      severity: "error",
      message: `Unclosed '${item.char}' — missing matching '${pair}'`,
    });
  }

  // Unclosed string at EOF
  if (inDoubleQuote && doubleQuoteStart >= 0) {
    diagnostics.push({
      from: doubleQuoteStart,
      to: doc.length,
      severity: "error",
      message: 'Unclosed string literal — missing closing \'"\'',
    });
  }
  if (inSingleQuote && singleQuoteStart >= 0) {
    diagnostics.push({
      from: singleQuoteStart,
      to: doc.length,
      severity: "error",
      message: "Unclosed string literal — missing closing \"'\"",
    });
  }

  // 2. Syntax Tree error detection (from Lezer AST with precision token targeting)
  try {
    const tree = syntaxTree(view.state);
    tree.iterate({
      enter(node) {
        if (node.type.isError) {
          let start = node.from;
          let end = node.to;

          if (start === end) {
            let i = start - 1;
            while (
              i >= 0 &&
              (docString[i] === " " ||
                docString[i] === "\t" ||
                docString[i] === "\n" ||
                docString[i] === "\r")
            ) {
              i--;
            }
            if (i < 0) return;

            end = i + 1;
            let j = i;
            if (/[a-zA-Z0-9_$]/.test(docString[j])) {
              while (j >= 0 && /[a-zA-Z0-9_$]/.test(docString[j])) {
                j--;
              }
              start = j + 1;
            } else if (docString[j] === "." || docString[j] === ":" || docString[j] === ",") {
              if (j > 0 && /[a-zA-Z0-9_$]/.test(docString[j - 1])) {
                let k = j - 1;
                while (k >= 0 && /[a-zA-Z0-9_$]/.test(docString[k])) {
                  k--;
                }
                start = k + 1;
              } else {
                start = j;
              }
            } else {
              start = Math.max(0, j);
            }
          }

          const snippet = docString.slice(start, end).trim();
          // Never flag valid closing or opening braces unless genuine unclosed mismatch
          if (snippet === "}" || snippet === ")" || snippet === "]" || !snippet) return;

          let message = "Syntax error";
          if (snippet === "const" || snippet === "let" || snippet === "var") {
            message = `Syntax error: unexpected '${snippet}' keyword in class body`;
          } else if (snippet.endsWith(".")) {
            message = "Syntax error: identifier expected after '.'";
          } else {
            message = `Syntax error near '${snippet.slice(0, 18)}'`;
          }

          const finalEnd = Math.max(end, start + 1);
          if (!diagnostics.some((d) => Math.abs(d.from - start) <= 1 && Math.abs(d.to - finalEnd) <= 1)) {
            diagnostics.push({
              from: start,
              to: finalEnd,
              severity: "error",
              message,
            });
          }
        }
      },
    });
  } catch (err) {
    // AST safety
  }

  return diagnostics;
}

// Crux Autocompletion Provider
function getCruxCompletions(
  context: CompletionContext,
  libraries: LibraryPackage[],
  language: string
): CompletionResult | null {
  const word = context.matchBefore(/[\w$]*/);
  if (!word || (word.from === word.to && !context.explicit)) return null;

  const options: Completion[] = [];

  // 1. Dynamic Library Exports from WorkspaceStore
  libraries
    .filter((l) => l.isInstalled)
    .forEach((lib) => {
      lib.exports.forEach((exp) => {
        options.push({
          label: exp,
          type: "function",
          detail: lib.name,
          info: `Exported by ${lib.name} (v${lib.version})`,
          boost: 3,
        });
      });
    });

  // 2. Core Crux Daemon & Mesh Architecture Symbols
  options.push(
    { label: "LocalDaemonClient", type: "class", detail: "@crux/daemon", info: "Client connection to local Crux mesh daemon (port 7447)", boost: 4 },
    { label: "CruxCluster", type: "class", detail: "@crux/daemon", info: "Distributed state orchestrator for edge nodes", boost: 4 },
    { label: "broadcastMesh", type: "function", detail: "@crux/daemon", info: "Broadcast low-latency message across local subnet", boost: 4 },
    { label: "subscribeChannel", type: "function", detail: "@crux/daemon", boost: 3 },
    { label: "acquireLock", type: "function", detail: "Crux Lock", info: "Acquire distributed mutex lock with timeout", boost: 4 },
    { label: "acquireStreamLock", type: "function", detail: "Crux Lock", info: "Acquire stream mutex lock for peer sync", boost: 4 },
    { label: "dispatchSignal", type: "function", detail: "@crux/daemon", boost: 3 },
    { label: "StreamSyncer", type: "class", detail: "Crux Sync", boost: 3 },
    { label: "ZenithNode", type: "class", detail: "Crux IDE", boost: 2 },
    { label: "NexusPipeline", type: "class", detail: "Crux Pipeline", boost: 2 }
  );

  // 3. High-Value Snippets & Built-ins
  options.push(
    snippetCompletion("console.log(${1:data});", {
      label: "console.log",
      detail: "Log to output",
      type: "function",
      boost: 5,
    }),
    snippetCompletion("console.error(${1:err});", {
      label: "console.error",
      detail: "Log error to output",
      type: "function",
      boost: 4,
    }),
    snippetCompletion('import { ${1} } from "${2}";', {
      label: "import",
      detail: "ES Module import statement",
      type: "keyword",
      boost: 5,
    }),
    snippetCompletion("export async function ${1:name}(${2:params}): Promise<${3:void}> {\n\t${4}\n}", {
      label: "async function",
      detail: "Async function declaration",
      type: "keyword",
      boost: 4,
    }),
    snippetCompletion("const [${1:state}, set${2:State}] = useState(${3:initial});", {
      label: "useState",
      detail: "React state hook",
      type: "function",
      boost: 4,
    }),
    snippetCompletion("useEffect(() => {\n\t${1}\n\treturn () => {\n\t\t${2}\n\t};\n}, [${3}]);", {
      label: "useEffect",
      detail: "React effect hook",
      type: "function",
      boost: 4,
    }),
    snippetCompletion("try {\n\t${1}\n} catch (err) {\n\tconsole.error(err);\n}", {
      label: "try-catch",
      detail: "Try-catch error block",
      type: "keyword",
      boost: 4,
    }),
    snippetCompletion("interface ${1:Name} {\n\t${2:property}: ${3:string};\n}", {
      label: "interface",
      detail: "TypeScript interface declaration",
      type: "keyword",
      boost: 4,
    })
  );

  // 4. Common keywords
  const keywords = [
    "const", "let", "var", "function", "return", "async", "await",
    "export", "import", "class", "interface", "type", "extends",
    "implements", "public", "private", "protected", "readonly", "static",
    "new", "throw", "try", "catch", "finally", "if", "else", "switch",
    "case", "break", "continue", "default", "true", "false", "null",
    "undefined", "typeof", "instanceof", "void", "Promise", "Record", "Array"
  ];
  keywords.forEach((kw) => {
    options.push({ label: kw, type: "keyword", boost: 1 });
  });

  return {
    from: word.from,
    options,
    validFor: /^[\w$]*$/,
  };
}

interface CodeMirrorEditorProps {
  file: FileNode;
  readOnly?: boolean;
}

export default function CodeMirrorEditor({ file, readOnly = false }: CodeMirrorEditorProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const [activeEditorView, setActiveEditorView] = useState<EditorView | null>(null);

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
  const remoteCursors = useWorkspaceStore((state) => state.remoteCursors);
  const libraries = useWorkspaceStore((state) => state.libraries);
  const isMonochromeTheme = useWorkspaceStore((state) => state.isMonochromeTheme);
  const librariesRef = useRef(libraries);
  librariesRef.current = libraries;

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

  // Active Yjs CRDT Session for real-time WebRTC P2P mesh
  const crdtSessionRef = useRef<CrexCRDTSession | null>(null);
  const [awarenessInstance, setAwarenessInstance] = useState<any>(null);

  // Mount CodeMirror 6 instance with native Yjs CRDT & WebRTC bindings
  useEffect(() => {
    if (typeof window !== "undefined") {
      (window as any).__cm_mounted__ = ((window as any).__cm_mounted__ || 0) + 1;
      (window as any).__cm_last_file__ = file.id;
    }
    if (!containerRef.current) return;

    // 1. Initialize P2P Yjs document & awareness via WebRTC
    const session = initCrexCRDTSession(file.id, file.content, {
      name: currentUser.name || "Principal Developer",
      color: currentUser.color || "#FFFFFF",
      uid: currentUser.uid || "CRX-7447-HG",
    });
    crdtSessionRef.current = session;
    setAwarenessInstance(session.awareness);

    // Initial content from Y.Text or fallback to file.content
    const initialDoc = session.ytext.toString() || file.content;
    if (session.ytext.length === 0 && file.content) {
      session.ytext.insert(0, file.content);
    }

    // 2. Build CodeMirror state with Yjs sync and Brutalist cursor plugins
    const syncConfig = new YSyncConfig(session.ytext, session.awareness);

    const startState = EditorState.create({
      doc: initialDoc,
      extensions: [
        ySyncFacet.of(syncConfig),
        ySync,
        createCrexBrutalistCursorExtension(session.awareness),
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightActiveLine(),
        history(),
        closeBrackets(),
        autocompletion({
          activateOnTyping: true,
          maxRenderedOptions: 12,
          override: [
            (context) => getCruxCompletions(context, librariesRef.current, file.language),
            completeAnyWord,
          ],
        }),
        linter(cruxLinter, { delay: 100 }),
        lintGutter(),
        getLanguageExtension(file.language),
        syntaxHighlighting(cruxHighlightStyle),
        syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
        cruxEditorTheme,
        keymap.of([
          {
            key: "Tab",
            run: (view) => {
              if (acceptCompletion(view)) {
                return true;
              }
              return false;
            },
          },
          indentWithTab,
          ...closeBracketsKeymap,
          ...defaultKeymap,
          ...historyKeymap,
        ]),
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

            const headCoords = viewRef.current?.coordsAtPos(sel.head);
            if (headCoords) {
              useWorkspaceStore.getState().setCursorScreenCoords({
                x: Math.round(headCoords.left),
                y: Math.round(headCoords.bottom),
              });
            }

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
    setActiveEditorView(view);

    // Sync Yjs text changes into local workspace store
    const ytextObserver = () => {
      const updatedText = session.ytext.toString();
      updateFileContent(file.id, updatedText);
    };
    session.ytext.observe(ytextObserver);

    // Sync remote peer mouse movements from awareness into remoteCursors store
    const awarenessMouseObserver = () => {
      try {
        const states = session.awareness.getStates();
        states.forEach((state: any, clientID: number) => {
          if (clientID === session.ydoc.clientID) return;
          if (state && state.mouse && state.user) {
            const u = state.user;
            useWorkspaceStore.getState().updateRemoteCursor(`client-${clientID}`, {
              userName: u.name || `Peer-${clientID.toString().slice(-4)}`,
              userColor: u.color || "#FFFFFF",
              userUid: u.uid || `CRX-${clientID.toString().slice(-4)}`,
              activeFileId: state.mouse.fileId || file.id,
              x: state.mouse.x,
              y: state.mouse.y,
            });
          }
        });
      } catch {
        // ignore
      }
    };
    session.awareness.on("change", awarenessMouseObserver);

    return () => {
      session.ytext.unobserve(ytextObserver);
      session.awareness.off("change", awarenessMouseObserver);
      view.destroy();
      viewRef.current = null;
      setActiveEditorView(null);
    };
  }, [file.id, getLanguageExtension, readOnly, isMonochromeTheme]);

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

  const handleContainerMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!crdtSessionRef.current || !containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = Math.round(e.clientX - rect.left);
    const y = Math.round(e.clientY - rect.top);
    crdtSessionRef.current.awareness.setLocalStateField("mouse", {
      x,
      y,
      fileId: file.id,
    });
  };

  const handleContainerMouseLeave = () => {
    if (!crdtSessionRef.current) return;
    crdtSessionRef.current.awareness.setLocalStateField("mouse", null);
  };

  return (
    <div className="relative w-full h-full flex flex-col bg-void font-mono overflow-hidden select-text">
      {/* Collaborative Suggestion Banner (if any pending for this file) */}
      {pendingSuggestions.length > 0 && (
        <div className="h-9 px-3 bg-surface border-b border-grid flex items-center justify-between text-xs font-mono select-none">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 bg-accent1" />
            <span className="text-signal font-semibold">{pendingSuggestions[0].author.name}</span>
            <span className="text-muted">suggests an update:</span>
            <span className="text-[11px] text-muted truncate max-w-sm border border-grid px-1.5 py-0.5 bg-void">
              {pendingSuggestions[0].description}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleAcceptSuggestion(pendingSuggestions[0].id)}
              className="px-2.5 py-0.5 bg-signal text-void font-bold text-[10px] uppercase border border-signal hover:opacity-90 transition-opacity"
            >
              Accept Diff
            </button>
            <button
              onClick={() => rejectSuggestion(pendingSuggestions[0].id)}
              className="px-2.5 py-0.5 bg-void text-muted font-bold text-[10px] uppercase border border-grid hover:text-signal hover:border-signal transition-colors"
            >
              Reject
            </button>
          </div>
        </div>
      )}

      {/* CodeMirror Mount Point with Real-Time Lerping Remote Cursor Overlay */}
      <div
        ref={containerRef}
        onMouseMove={handleContainerMouseMove}
        onMouseLeave={handleContainerMouseLeave}
        className="flex-1 w-full h-full overflow-auto relative"
      >
        <RemoteCursorInterpolator view={activeEditorView} awareness={awarenessInstance} />

        {Object.entries(remoteCursors)
          .filter(
            ([_, cursor]) =>
              cursor.activeFileId === file.id &&
              cursor.x !== undefined &&
              cursor.y !== undefined
          )
          .map(([userId, cursor]) => (
            <div
              key={userId}
              className="absolute pointer-events-none z-50 transition-all duration-75"
              style={{ top: `${cursor.y}px`, left: `${cursor.x}px` }}
            >
              <CruxPointerCursor
                name={cursor.userName}
                uid={cursor.userUid}
                color={cursor.userColor}
              />
            </div>
          ))}
      </div>

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
      <div className={`absolute right-4 z-20 space-y-2 ${pendingSuggestions.length > 0 ? "top-12" : "top-3"}`}>
        {fileComments.map((thread) => (
          <div key={thread.id} className="relative">
            <button
              onClick={() =>
                setActiveThreadId(activeThreadId === thread.id ? null : thread.id)
              }
              className="flex items-center gap-1.5 px-2 py-0.5 rounded-none bg-[#0A0A0A] border border-[#222222] hover:border-[#444444] text-[#888888] hover:text-white text-[10.5px] font-mono transition-colors shadow-[2px_2px_0px_#161616]"
            >
              <MessageSquare className="w-3 h-3 text-[#38b6ff]" />
              <span>Line {thread.lineNumber}</span>
              <span className="w-1.5 h-1.5 rounded-none bg-[#38b6ff]" />
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
