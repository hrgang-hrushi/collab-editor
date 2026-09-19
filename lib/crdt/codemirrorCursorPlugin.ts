/**
 * Crex Hardware Brutalism CodeMirror Cursor & Selection Plugin
 * 
 * Strict Architectural Rules:
 * - 0px border radius everywhere.
 * - Remote cursors: 2px solid vertical line (Peer 1: #FFFFFF, Peer 2: #888888, Peer 3: #444444).
 * - Sharp name tag pinned directly above the cursor line in Arial MT Pro, text-[10px], zero tracking.
 * - Solid cursor when typing; dotted border (border-dashed border-[#444444]) & 50% opacity tag when idle > 3s.
 * - Selection ribbon: Flat 15% opacity fill with zero rounded corners and zero glow.
 */

import { ViewPlugin, ViewUpdate, EditorView, Decoration, DecorationSet, WidgetType } from "@codemirror/view";
import { Range } from "@codemirror/state";
import * as Y from "yjs";
import { Awareness } from "y-protocols/awareness";
import { ySyncFacet } from "y-codemirror.next";

export interface RemoteCaretInfo {
  name: string;
  color: string;
  uid?: string;
  isTyping?: boolean;
  isIdle?: boolean;
}

/**
 * Custom Hardware Brutalist Caret Widget for CodeMirror 6
 */
export class CrexBrutalistCaretWidget extends WidgetType {
  color: string;
  name: string;
  uid: string;
  isIdle: boolean;
  isTyping: boolean;

  constructor(info: RemoteCaretInfo) {
    super();
    this.color = info.color;
    this.name = info.name;
    this.uid = info.uid || "PEER";
    this.isIdle = !!info.isIdle;
    this.isTyping = !!info.isTyping;
  }

  toDOM(): HTMLElement {
    const wrap = document.createElement("span");
    wrap.className = "crex-remote-caret-container select-none pointer-events-none";
    wrap.style.position = "relative";
    wrap.style.display = "inline";
    wrap.style.zIndex = "100";

    // 1. Remote Cursor Line (2px vertical line, 0px radius)
    const line = document.createElement("span");
    line.className = "crex-remote-cursor-line";
    line.style.position = "absolute";
    line.style.top = "0px";
    line.style.left = "-1px";
    line.style.width = "2px";
    line.style.height = "1.25em";
    line.style.backgroundColor = this.color;
    line.style.borderRadius = "0px";
    line.style.zIndex = "101";

    if (this.isIdle) {
      line.style.backgroundColor = "transparent";
      line.style.borderLeft = `2px dashed #444444`;
      line.style.width = "2px";
    }

    // 2. Sharp Name Tag pinned above cursor line in Arial MT Pro, text-[10px]
    const tag = document.createElement("div");
    tag.className = "crex-remote-name-tag";
    tag.style.position = "absolute";
    tag.style.bottom = "100%";
    tag.style.left = "-1px";
    tag.style.marginBottom = "2px";
    tag.style.padding = "1px 4px";
    tag.style.fontFamily = '"Arial MT Pro", "Arial MT", Arial, Helvetica, sans-serif';
    tag.style.fontSize = "10px";
    tag.style.fontWeight = "600";
    tag.style.lineHeight = "1";
    tag.style.letterSpacing = "0px";
    tag.style.textTransform = "uppercase";
    tag.style.borderRadius = "0px";
    tag.style.whiteSpace = "nowrap";
    tag.style.boxSizing = "border-box";
    tag.style.zIndex = "102";

    // Monochromatic inversion for peer 1 (#FFFFFF) vs darker tones
    const isLight = this.color.toLowerCase() === "#ffffff" || this.color.toLowerCase() === "#fff";
    tag.style.backgroundColor = this.color;
    tag.style.color = isLight ? "#000000" : "#FFFFFF";
    tag.style.border = "1px solid #222222";

    if (this.isIdle) {
      tag.style.opacity = "0.5";
      tag.style.borderColor = "#444444";
    }

    tag.textContent = this.name;

    wrap.appendChild(line);
    wrap.appendChild(tag);
    return wrap;
  }

  eq(other: CrexBrutalistCaretWidget): boolean {
    return (
      other.color === this.color &&
      other.name === this.name &&
      other.isIdle === this.isIdle &&
      other.isTyping === this.isTyping
    );
  }

  ignoreEvent(): boolean {
    return true;
  }
}

/**
 * Creates the CodeMirror 6 extension that listens to y-protocols awareness
 * and renders Brutalist remote carets and 15% opacity selection ribbons.
 */
export function createCrexBrutalistCursorExtension(awareness: Awareness) {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;
      private awarenessListener: () => void;
      private typingTimer: NodeJS.Timeout | null = null;

      constructor(view: EditorView) {
        this.decorations = Decoration.none;

        // Broadcast initial cursor position immediately upon mount
        try {
          const conf = view.state.facet(ySyncFacet);
          if (conf && conf.ytext && conf.ytext.doc) {
            const mainSel = view.state.selection.main;
            const anchor = Y.createRelativePositionFromTypeIndex(conf.ytext, mainSel.anchor);
            const head = Y.createRelativePositionFromTypeIndex(conf.ytext, mainSel.head);
            awareness.setLocalStateField("cursor", { anchor, head });
            awareness.setLocalStateField("lastActive", Date.now());
          }
        } catch {
          // ignore
        }

        this.awarenessListener = () => {
          view.requestMeasure();
          view.dispatch({}); // trigger update
        };

        awareness.on("change", this.awarenessListener);
      }

      destroy() {
        awareness.off("change", this.awarenessListener);
        if (this.typingTimer) clearTimeout(this.typingTimer);
      }

      update(update: ViewUpdate) {
        const conf = update.view.state.facet(ySyncFacet);
        if (!conf) {
          this.decorations = Decoration.none;
          return;
        }

        const ytext = conf.ytext;
        const ydoc = ytext.doc;
        if (!ydoc) {
          this.decorations = Decoration.none;
          return;
        }

        // Track local cursor position into awareness
        const localState = awareness.getLocalState();
        if ((update.view.hasFocus || update.selectionSet || update.docChanged) && localState) {
          const mainSel = update.state.selection.main;
          const anchor = Y.createRelativePositionFromTypeIndex(ytext, mainSel.anchor);
          const head = Y.createRelativePositionFromTypeIndex(ytext, mainSel.head);

          const isDocChanged = update.docChanged;
          const currentTyping = isDocChanged;

          awareness.setLocalStateField("cursor", { anchor, head });
          awareness.setLocalStateField("lastActive", Date.now());

          if (currentTyping) {
            awareness.setLocalStateField("isTyping", true);
            if (this.typingTimer) clearTimeout(this.typingTimer);
            this.typingTimer = setTimeout(() => {
              awareness.setLocalStateField("isTyping", false);
            }, 3000);
          }
        }

        // Generate remote decorations for all peer states
        const decos: Range<Decoration>[] = [];
        const now = Date.now();

        awareness.getStates().forEach((state: any, clientID: number) => {
          if (clientID === ydoc.clientID) return; // Ignore self
          if (!state || !state.cursor) return;

          const anchorPos = Y.createAbsolutePositionFromRelativePosition(state.cursor.anchor, ydoc);
          const headPos = Y.createAbsolutePositionFromRelativePosition(state.cursor.head, ydoc);

          if (!anchorPos || !headPos || anchorPos.type !== ytext || headPos.type !== ytext) {
            return;
          }

          const user = state.user || {};
          const name = user.name || `Peer-${clientID.toString().slice(-4)}`;
          const color = user.color || "#FFFFFF";
          const uid = user.uid || "CRX-PEER";
          const lastActive = state.lastActive || 0;
          const isIdle = now - lastActive > 3000;
          const isTyping = !isIdle && !!state.isTyping;

          const from = Math.min(anchorPos.index, headPos.index);
          const to = Math.max(anchorPos.index, headPos.index);

          // 1. Selection Ribbon: 15% opacity flat fill (no rounded corners, no glow)
          if (from !== to) {
            // Convert hex color to rgba with 0.15 opacity
            const r = parseInt(color.slice(1, 3) || "ff", 16);
            const g = parseInt(color.slice(3, 5) || "ff", 16);
            const b = parseInt(color.slice(5, 7) || "ff", 16);
            const rgbaFill = `rgba(${isNaN(r) ? 255 : r}, ${isNaN(g) ? 255 : g}, ${isNaN(b) ? 255 : b}, 0.15)`;

            decos.push(
              Decoration.mark({
                class: "crex-remote-selection-ribbon",
                attributes: {
                  style: `background-color: ${rgbaFill} !important; border-radius: 0px !important; outline: none !important; box-shadow: none !important;`,
                },
              }).range(from, to)
            );
            // Selection Ribbon is handled natively by CodeMirror decorations.
            // Caret line and name badge are smoothly rendered via RemoteCursorInterpolator (Framer Motion 60fps lerp).
          }
        });

        this.decorations = Decoration.set(decos, true);
      }
    },
    {
      decorations: (v) => v.decorations,
    }
  );
}
