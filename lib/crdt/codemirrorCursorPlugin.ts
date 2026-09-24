/**
 * Crex Hardware Brutalism CodeMirror Collaborative Cursor & Selection Plugin
 * 
 * Renders native CodeMirror decorations:
 * 1. Text Selection Highlight Ribbon:
 *    - Tinted background in collaborator's pointer color (28% opacity)
 *    - Matching 1px border outline (65% opacity)
 *    - Smooth 4px corner radius with single-line & multi-line support
 * 2. Remote Caret Line:
 *    - 2.5px vertical bar in collaborator's pointer color with 2px corner radius
 *    - Active glow in pointer color when typing
 * 3. Collaborator Name Badge:
 *    - Pinned directly above the caret line
 *    - Smooth 4px corner curve radius matching pointer
 *    - Filled and bordered in collaborator's assigned pointer color
 *    - Dynamic states:
 *      * Typing: collaborator name + "typing" with 3 animated bouncing dots
 *      * Selecting: collaborator name + "selecting"
 *      * Idle: collaborator name
 */

import { ViewPlugin, ViewUpdate, EditorView, Decoration, DecorationSet, WidgetType } from "@codemirror/view";
import { Range, Annotation } from "@codemirror/state";
import * as Y from "yjs";
import { Awareness } from "y-protocols/awareness";
import { ySyncFacet } from "y-codemirror.next";

export const crexCursorAnnotation = Annotation.define<void>();

function isLightColor(hex?: string): boolean {
  if (!hex) return false;
  const c = hex.replace("#", "").trim();
  if (c.length === 3) {
    const r = parseInt(c[0] + c[0], 16);
    const g = parseInt(c[1] + c[1], 16);
    const b = parseInt(c[2] + c[2], 16);
    return (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.65;
  }
  if (c.length === 6) {
    const r = parseInt(c.slice(0, 2), 16);
    const g = parseInt(c.slice(2, 4), 16);
    const b = parseInt(c.slice(4, 6), 16);
    return (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.65;
  }
  return false;
}

function hexToRgba(hex: string, alpha: number): string {
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
}

/**
 * Native CodeMirror Caret & Name Badge Widget
 */
export class CrexRemoteCaretWidget extends WidgetType {
  color: string;
  name: string;
  uid: string;
  isTyping: boolean;
  isSelecting: boolean;
  isIdle: boolean;

  constructor(
    color: string,
    name: string,
    uid: string,
    isTyping: boolean,
    isSelecting: boolean,
    isIdle: boolean
  ) {
    super();
    this.color = color;
    this.name = name;
    this.uid = uid;
    this.isTyping = isTyping;
    this.isSelecting = isSelecting;
    this.isIdle = isIdle;
  }

  toDOM(): HTMLElement {
    const isLight = isLightColor(this.color);
    const textColor = isLight ? "#000000" : "#FFFFFF";

    // 0-width anchor positioned right at character index
    const wrap = document.createElement("span");
    wrap.className = "cm-crex-remote-caret-anchor select-none pointer-events-none";
    wrap.style.position = "relative";
    wrap.style.display = "inline-block";
    wrap.style.width = "0px";
    wrap.style.height = "0px";
    wrap.style.verticalAlign = "text-bottom";
    wrap.style.zIndex = "100";

    // 1. Caret Line: 2.5px vertical bar with rounded corners in peer pointer color
    const caret = document.createElement("span");
    caret.className = "cm-crex-remote-caret-line";
    caret.style.position = "absolute";
    caret.style.bottom = "0px";
    caret.style.left = "-1px";
    caret.style.width = "2.5px";
    caret.style.height = "1.25em";
    caret.style.backgroundColor = this.isIdle ? "transparent" : this.color;
    caret.style.borderRadius = "2px";
    if (this.isIdle) {
      caret.style.borderLeft = "2px dashed #666666";
      caret.style.width = "2px";
    }
    if (this.isTyping) {
      caret.style.boxShadow = `0 0 8px ${this.color}`;
    }

    // 2. Collaborator Name Badge: Pinned right above the caret
    const badge = document.createElement("div");
    badge.className = "cm-crex-remote-caret-badge";
    badge.style.position = "absolute";
    badge.style.bottom = "1.25em";
    badge.style.left = "-2px";
    badge.style.marginBottom = "3px";
    badge.style.padding = "2px 6px";
    badge.style.backgroundColor = this.color;
    badge.style.color = textColor;
    badge.style.border = `1.2px solid ${this.color}`;
    badge.style.borderRadius = "0px";
    badge.style.fontFamily = '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif';
    badge.style.fontSize = "10px";
    badge.style.fontWeight = "700";
    badge.style.lineHeight = "1";
    badge.style.whiteSpace = "nowrap";
    badge.style.boxShadow = "none";
    badge.style.display = "flex";
    badge.style.alignItems = "center";
    badge.style.gap = "4px";
    badge.style.zIndex = "110";
    if (this.isIdle) {
      badge.style.opacity = "0.6";
    }

    const nameSpan = document.createElement("span");
    nameSpan.textContent = this.name;
    badge.appendChild(nameSpan);

    if (this.isTyping) {
      const typingSpan = document.createElement("span");
      typingSpan.style.fontSize = "9px";
      typingSpan.style.fontWeight = "500";
      typingSpan.style.opacity = "0.95";
      typingSpan.style.display = "inline-flex";
      typingSpan.style.alignItems = "center";
      typingSpan.style.gap = "2px";
      typingSpan.innerHTML = `<span>typing</span><span style="display:inline-flex;gap:1.5px;margin-left:2px;"><span class="crex-dot-1" style="width:3px;height:3px;border-radius:50%;background-color:currentColor;"></span><span class="crex-dot-2" style="width:3px;height:3px;border-radius:50%;background-color:currentColor;"></span><span class="crex-dot-3" style="width:3px;height:3px;border-radius:50%;background-color:currentColor;"></span></span>`;
      badge.appendChild(typingSpan);
    } else if (this.isSelecting) {
      const selectingSpan = document.createElement("span");
      selectingSpan.style.fontSize = "9px";
      selectingSpan.style.fontWeight = "500";
      selectingSpan.style.opacity = "0.9";
      selectingSpan.textContent = "selecting";
      badge.appendChild(selectingSpan);
    }

    wrap.appendChild(caret);
    wrap.appendChild(badge);
    return wrap;
  }

  eq(other: CrexRemoteCaretWidget): boolean {
    return (
      other.color === this.color &&
      other.name === this.name &&
      other.uid === this.uid &&
      other.isTyping === this.isTyping &&
      other.isSelecting === this.isSelecting &&
      other.isIdle === this.isIdle
    );
  }

  ignoreEvent(): boolean {
    return true;
  }
}

/**
 * Creates the CodeMirror 6 extension that listens to y-protocols awareness
 * and renders native CodeMirror remote carets and text selection ribbons.
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
        const updateInitial = () => {
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
        };
        updateInitial();

        // When awareness updates from peers, dispatch an annotated transaction to immediately refresh decorations
        this.awarenessListener = () => {
          view.dispatch({ annotations: [crexCursorAnnotation.of()] });
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
        if (localState && (update.selectionSet || update.docChanged || update.view.hasFocus)) {
          const mainSel = update.state.selection.main;
          const anchor = Y.createRelativePositionFromTypeIndex(ytext, mainSel.anchor);
          const head = Y.createRelativePositionFromTypeIndex(ytext, mainSel.head);

          awareness.setLocalStateField("cursor", { anchor, head });
          awareness.setLocalStateField("lastActive", Date.now());

          if (update.docChanged) {
            awareness.setLocalStateField("isTyping", true);
            if (this.typingTimer) clearTimeout(this.typingTimer);
            this.typingTimer = setTimeout(() => {
              awareness.setLocalStateField("isTyping", false);
            }, 1800);
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
          const color = user.color || "#38b6ff";
          const uid = user.uid || "CRX-PEER";
          const lastActive = state.lastActive || 0;
          const isIdle = now - lastActive > 3000;
          const isTyping = !isIdle && !!state.isTyping;

          const start = Math.min(anchorPos.index, headPos.index);
          const end = Math.max(anchorPos.index, headPos.index);
          const isSelecting = start !== end;

          // 1. Text Selection Highlight Ribbon
          if (isSelecting) {
            const rgbaFill = hexToRgba(color, 0.28);
            const rgbaBorder = hexToRgba(color, 0.65);

            const startLine = update.view.state.doc.lineAt(start);
            const endLine = update.view.state.doc.lineAt(end);

            if (startLine.number === endLine.number) {
              // Single-line selection
              decos.push(
                Decoration.mark({
                  class: "crex-remote-selection-ribbon",
                  attributes: {
                    style: `background-color: ${rgbaFill} !important; outline: 1px solid ${rgbaBorder} !important; border-radius: 4px !important;`,
                  },
                }).range(start, end)
              );
            } else {
              // Multi-line selection: line 1, middle lines, last line
              decos.push(
                Decoration.mark({
                  class: "crex-remote-selection-ribbon",
                  attributes: {
                    style: `background-color: ${rgbaFill} !important; outline: 1px solid ${rgbaBorder} !important; border-radius: 4px 4px 0 0 !important;`,
                  },
                }).range(start, startLine.from + startLine.length)
              );
              decos.push(
                Decoration.mark({
                  class: "crex-remote-selection-ribbon",
                  attributes: {
                    style: `background-color: ${rgbaFill} !important; outline: 1px solid ${rgbaBorder} !important; border-radius: 0 0 4px 4px !important;`,
                  },
                }).range(endLine.from, end)
              );
              for (let i = startLine.number + 1; i < endLine.number; i++) {
                const line = update.view.state.doc.line(i);
                if (line.length > 0) {
                  decos.push(
                    Decoration.mark({
                      class: "crex-remote-selection-ribbon",
                      attributes: {
                        style: `background-color: ${rgbaFill} !important; outline: 1px solid ${rgbaBorder} !important; border-radius: 0 !important;`,
                      },
                    }).range(line.from, line.to)
                  );
                }
              }
            }
          }

          // 2. Remote Caret & Name Badge at the active head position
          decos.push(
            Decoration.widget({
              side: headPos.index - anchorPos.index > 0 ? -1 : 1,
              block: false,
              widget: new CrexRemoteCaretWidget(
                color,
                name,
                uid,
                isTyping,
                isSelecting,
                isIdle
              ),
            }).range(headPos.index)
          );
        });

        // CodeMirror requires ranges to be sorted by position
        this.decorations = Decoration.set(decos, true);
      }
    },
    {
      decorations: (v) => v.decorations,
    }
  );
}
