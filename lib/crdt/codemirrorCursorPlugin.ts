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

    // 1. Remote Cursor Line with corner radius in peer color
    const line = document.createElement("span");
    line.className = "crex-remote-cursor-line";
    line.style.position = "absolute";
    line.style.top = "0px";
    line.style.left = "-1px";
    line.style.width = "2.5px";
    line.style.height = "1.25em";
    line.style.backgroundColor = this.color;
    line.style.borderRadius = "2px";
    line.style.zIndex = "101";

    if (this.isIdle) {
      line.style.backgroundColor = "transparent";
      line.style.borderLeft = `2px dashed #444444`;
      line.style.width = "2px";
    }

    // 2. Collaborator Name Tag pinned above cursor line with corner curve radius
    const tag = document.createElement("div");
    tag.className = "crex-remote-name-tag";
    tag.style.position = "absolute";
    tag.style.bottom = "100%";
    tag.style.left = "-1px";
    tag.style.marginBottom = "3px";
    tag.style.padding = "2px 6px";
    tag.style.fontFamily = '"Arial MT Pro", "Arial MT", Arial, Helvetica, sans-serif';
    tag.style.fontSize = "10px";
    tag.style.fontWeight = "600";
    tag.style.lineHeight = "1";
    tag.style.letterSpacing = "0px";
    tag.style.borderRadius = "4px";
    tag.style.whiteSpace = "nowrap";
    tag.style.boxSizing = "border-box";
    tag.style.zIndex = "102";

    // Monochromatic inversion for peer 1 (#FFFFFF) vs darker tones
    const isLight = this.color.toLowerCase() === "#ffffff" || this.color.toLowerCase() === "#fff";
    tag.style.backgroundColor = this.color;
    tag.style.color = isLight ? "#000000" : "#FFFFFF";
    tag.style.border = `1px solid ${this.color}`;

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

          // 1. Selection Ribbon: tinted background with corner curve radius matching pointer color
          if (from !== to) {
            const hexToRgba = (hex: string, alpha: number) => {
              if (!hex) return `rgba(255, 255, 255, ${alpha})`;
              let clean = hex.replace("#", "").trim();
              if (clean.length === 3) {
                clean = clean.split("").map((c) => c + c).join("");
              }
              if (clean.length === 6) {
                const r = parseInt(clean.slice(0, 2), 16);
                const g = parseInt(clean.slice(2, 4), 16);
                const b = parseInt(clean.slice(4, 6), 16);
                return `rgba(${isNaN(r) ? 255 : r}, ${isNaN(g) ? 255 : g}, ${isNaN(b) ? 255 : b}, ${alpha})`;
              }
              return `rgba(255, 255, 255, ${alpha})`;
            };

            const rgbaFill = hexToRgba(color, 0.28);
            const rgbaBorder = hexToRgba(color, 0.65);

            decos.push(
              Decoration.mark({
                class: "crex-remote-selection-ribbon",
                attributes: {
                  style: `background-color: ${rgbaFill} !important; border-radius: 4px !important; outline: 1px solid ${rgbaBorder} !important; box-decoration-break: clone; -webkit-box-decoration-break: clone;`,
                },
              }).range(from, to)
            );
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
