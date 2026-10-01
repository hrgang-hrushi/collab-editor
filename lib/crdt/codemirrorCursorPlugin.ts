/**
 * Crex Hardware Brutalism CodeMirror Collaborative Cursor, Selection & Active Editing Plugin
 * 
 * Implements native CodeMirror 6 decorations:
 * 1. Line of the Selected Place:
 *    - Whenever a user (local or remote) stops hovering and selects text or places caret,
 *      the line(s) spanned by the selection are highlighted in that user's color with a 3px
 *      left border and subtle 8% background tint.
 * 2. Text Selection Highlight Ribbon:
 *    - Selected words are enclosed in that user's color with a 4px rounded pill, 1.2px solid
 *      outline, 22% background fill, and subtle luminous glow.
 * 3. Active Change Range ("from the starting point to the end point of the changes"):
 *    - As users write, from the start of the changes to the end of the changes, that area
 *      is highlighted in that specific person's color, clearly attributing who authored the code.
 * 4. Caret Line & Name Badge:
 *    - Pinned above caret with 4px corner curve radius, vibrant color fill, and dynamic status
 *      (typing with animated dots, selecting, editing).
 * 5. Simulation Engine:
 *    - Built-in simulation for Erik (#ff70a6) and Muhaymin (#16a34a) to demonstrate multi-peer
 *      real-time highlights live inside the actual IDE.
 */

import { ViewPlugin, ViewUpdate, EditorView, Decoration, DecorationSet, WidgetType } from "@codemirror/view";
import { Range, Annotation } from "@codemirror/state";
import * as Y from "yjs";
import { Awareness } from "y-protocols/awareness";
import { ySyncFacet } from "y-codemirror.next";

export const crexCursorAnnotation = Annotation.define<void>();

export interface CollabUserIdentity {
  name: string;
  color: string;
  uid: string;
  avatarType?: string;
}

export function isLightColor(hex?: string): boolean {
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

export function hexToRgba(hex: string, alpha: number): string {
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
 * Native CodeMirror Caret & Collaborator Name Badge Widget
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
      caret.style.boxShadow = `0 0 10px ${this.color}`;
    }

    // 2. Collaborator Name Badge: Pinned right above the caret with smooth 4px border radius
    const badge = document.createElement("div");
    badge.className = "cm-crex-remote-caret-badge";
    badge.style.position = "absolute";
    badge.style.bottom = "1.3em";
    badge.style.left = "-2px";
    badge.style.marginBottom = "3px";
    badge.style.padding = "2px 6px";
    badge.style.backgroundColor = this.color;
    badge.style.color = textColor;
    badge.style.border = `1.2px solid ${this.color}`;
    badge.style.borderRadius = "4px";
    badge.style.fontFamily = '"Arial MT", "ArialMT", Arial, "Arial MT Pro", Helvetica, sans-serif';
    badge.style.fontSize = "10px";
    badge.style.fontWeight = "700";
    badge.style.lineHeight = "1";
    badge.style.whiteSpace = "nowrap";
    badge.style.boxShadow = `0 4px 14px ${hexToRgba(this.color, 0.45)}`;
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
      typingSpan.innerHTML = `<span>typing</span><span style="display:inline-flex;gap:1.5px;margin-left:2px;"><span style="width:3px;height:3px;border-radius:50%;background-color:currentColor;animation:pulse 1s infinite;"></span><span style="width:3px;height:3px;border-radius:50%;background-color:currentColor;animation:pulse 1s infinite 0.2s;"></span><span style="width:3px;height:3px;border-radius:50%;background-color:currentColor;animation:pulse 1s infinite 0.4s;"></span></span>`;
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
 * Creates the CodeMirror 6 extension that listens to y-protocols awareness,
 * tracks continuous writing/change ranges, and renders colored highlights for:
 * 1. The line of the selected place (in the person's color)
 * 2. The selected words (rounded pill in the person's color)
 * 3. The writing range from starting point to end point of changes (in the person's color)
 * 4. Carets and name badges (Erik, Muhaymin, Hrushi, etc.)
 */
export function createCrexBrutalistCursorExtension(
  awareness: Awareness,
  currentUser?: CollabUserIdentity
) {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;
      private awarenessListener: () => void;
      private typingTimer: NodeJS.Timeout | null = null;
      private changeIdleTimer: NodeJS.Timeout | null = null;
      private refreshQueued = false;
      private destroyed = false;

      // Active continuous writing range for the local user: [from, to]
      private localChangeRange: { from: number; to: number; timestamp: number } | null = null;

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

        // Awareness listener for remote peer updates
        this.awarenessListener = () => {
          if (this.refreshQueued || this.destroyed) return;
          this.refreshQueued = true;
          queueMicrotask(() => {
            this.refreshQueued = false;
            if (!this.destroyed) {
              view.dispatch({ annotations: [crexCursorAnnotation.of()] });
            }
          });
        };

        awareness.on("change", this.awarenessListener);
      }

      destroy() {
        this.destroyed = true;
        awareness.off("change", this.awarenessListener);
        if (this.typingTimer) clearTimeout(this.typingTimer);
        if (this.changeIdleTimer) clearTimeout(this.changeIdleTimer);
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

        const now = Date.now();
        const docLength = update.state.doc.length;

        // -------------------------------------------------------------------
        // 1. TRACK LOCAL USER EDITING & CONTINUOUS WRITING RANGE
        // -------------------------------------------------------------------
        const localState = awareness.getLocalState();
        const localUser = localState?.user || currentUser || { name: "You", color: "#0055FF" };
        const localColor = localUser.color || "#0055FF";

        if (update.docChanged) {
          let minFrom = Infinity;
          let maxTo = -Infinity;
          update.changes.iterChanges((fromA, toA, fromB, toB) => {
            minFrom = Math.min(minFrom, fromB);
            maxTo = Math.max(maxTo, toB);
          });

          if (minFrom !== Infinity && maxTo !== -Infinity) {
            // If editing continuously near the previous change within 6 seconds, expand range
            if (
              this.localChangeRange &&
              now - this.localChangeRange.timestamp < 6000 &&
              Math.abs(minFrom - this.localChangeRange.to) < 80
            ) {
              this.localChangeRange.from = Math.min(this.localChangeRange.from, minFrom);
              this.localChangeRange.to = Math.max(this.localChangeRange.to, maxTo);
              this.localChangeRange.timestamp = now;
            } else {
              // Start a new contiguous change range
              this.localChangeRange = {
                from: minFrom,
                to: Math.max(minFrom + 1, maxTo),
                timestamp: now,
              };
            }

            // Broadcast active writing change in Yjs awareness
            try {
              const relAnchor = Y.createRelativePositionFromTypeIndex(ytext, this.localChangeRange.from);
              const relHead = Y.createRelativePositionFromTypeIndex(ytext, this.localChangeRange.to);
              awareness.setLocalStateField("activeChange", {
                anchor: relAnchor,
                head: relHead,
                timestamp: now,
                isTyping: true,
              });
            } catch {
              // ignore
            }

            // Set typing state
            awareness.setLocalStateField("isTyping", true);
            if (this.typingTimer) clearTimeout(this.typingTimer);
            this.typingTimer = setTimeout(() => {
              awareness.setLocalStateField("isTyping", false);
            }, 2500);

            // Keep the change highlight visible for a while after writing
            if (this.changeIdleTimer) clearTimeout(this.changeIdleTimer);
            this.changeIdleTimer = setTimeout(() => {
              // Transition change range to stable state
              if (this.localChangeRange && Date.now() - this.localChangeRange.timestamp >= 7000) {
                this.localChangeRange = null;
                awareness.setLocalStateField("activeChange", null);
                if (!this.destroyed) {
                  update.view.dispatch({ annotations: [crexCursorAnnotation.of()] });
                }
              }
            }, 7500);
          }
        }

        // Broadcast local cursor/selection to awareness
        if (update.selectionSet || update.docChanged) {
          const mainSel = update.state.selection.main;
          const anchor = Y.createRelativePositionFromTypeIndex(ytext, mainSel.anchor);
          const head = Y.createRelativePositionFromTypeIndex(ytext, mainSel.head);

          awareness.setLocalStateField("cursor", { anchor, head });
          awareness.setLocalStateField("lastActive", now);

          // If user jumped far away from the active change range, reset local change tracking
          if (
            this.localChangeRange &&
            (mainSel.head < this.localChangeRange.from - 40 || mainSel.head > this.localChangeRange.to + 40)
          ) {
            this.localChangeRange = null;
            awareness.setLocalStateField("activeChange", null);
          }
        }

        // -------------------------------------------------------------------
        // 2. GENERATE DECORATIONS (LINES, SELECTIONS, ACTIVE WRITING CHANGES)
        // -------------------------------------------------------------------
        const decos: Range<Decoration>[] = [];
        // Guard: At most ONE Decoration.line per line number in CodeMirror 6
        const decoratedLines = new Set<number>();

        // -------------------------------------------------------------------
        // A. LOCAL USER DECORATIONS
        // -------------------------------------------------------------------
        const mainSel = update.state.selection.main;
        const localStart = Math.max(0, Math.min(docLength, Math.min(mainSel.anchor, mainSel.head)));
        const localEnd = Math.max(0, Math.min(docLength, Math.max(mainSel.anchor, mainSel.head)));
        const isLocalSelecting = localStart !== localEnd;

        // 1. Line of the selected place in local user's color
        // "Whenever a user stops hovering and selects some text, the line of the selected place should be in their color"
        const localStartLine = update.state.doc.lineAt(localStart);
        const localEndLine = update.state.doc.lineAt(localEnd);

        for (let l = localStartLine.number; l <= localEndLine.number; l++) {
          if (!decoratedLines.has(l)) {
            decoratedLines.add(l);
            const line = update.state.doc.line(l);
            decos.push(
              Decoration.line({
                attributes: {
                  class: "cm-crex-user-selected-line",
                  style: `background-color: ${hexToRgba(localColor, 0.08)} !important; border-left: 3px solid ${localColor} !important;`,
                },
              }).range(line.from)
            );
          }
        }

        // 2. Selected words in local user's color
        // "As they keep selecting words..."
        if (isLocalSelecting) {
          decos.push(
            Decoration.mark({
              class: "cm-crex-user-selection-ribbon",
              attributes: {
                style: `background-color: ${hexToRgba(localColor, 0.22)} !important; outline: 1.2px solid ${localColor} !important; border-radius: 4px !important; box-shadow: 0 0 10px ${hexToRgba(localColor, 0.25)} !important; color: #FFFFFF !important;`,
              },
            }).range(localStart, localEnd)
          );
        }

        // 3. Local writing / change area in local user's color
        // "...or writing, from the starting point to the end point of the changes, that area should be in that color"
        if (this.localChangeRange && !isLocalSelecting) {
          const cStart = Math.max(0, Math.min(docLength, this.localChangeRange.from));
          const cEnd = Math.max(0, Math.min(docLength, this.localChangeRange.to));
          if (cStart < cEnd) {
            decos.push(
              Decoration.mark({
                class: "cm-crex-user-change-highlight",
                attributes: {
                  style: `background-color: ${hexToRgba(localColor, 0.16)} !important; outline: 1.2px solid ${localColor} !important; border-radius: 4px !important; padding: 1px 2px !important; box-shadow: 0 0 10px ${hexToRgba(localColor, 0.22)} !important; color: #FFFFFF !important;`,
                },
              }).range(cStart, cEnd)
            );
          }
        }

        // -------------------------------------------------------------------
        // B. REMOTE COLLABORATORS (PEERS)
        // -------------------------------------------------------------------
        awareness.getStates().forEach((state: any, clientID: number) => {
          if (clientID === ydoc.clientID) return; // Skip local user (already rendered)
          if (!state) return;

          const user = state.user || {};
          const name = user.name || `Peer-${clientID.toString().slice(-4)}`;
          const color = user.color || "#ff70a6";
          const uid = user.uid || "CRX-PEER";
          const lastActive = state.lastActive || 0;
          const isIdle = now - lastActive > 6000;
          const isTyping = !isIdle && !!state.isTyping;

          // 1. Remote Peer Cursor & Selection Highlight
          if (state.cursor && state.cursor.anchor && state.cursor.head) {
            const anchorPos = Y.createAbsolutePositionFromRelativePosition(state.cursor.anchor, ydoc);
            const headPos = Y.createAbsolutePositionFromRelativePosition(state.cursor.head, ydoc);

            if (anchorPos && headPos && anchorPos.type === ytext && headPos.type === ytext) {
              const pStart = Math.max(0, Math.min(docLength, anchorPos.index, headPos.index));
              const pEnd = Math.max(0, Math.min(docLength, Math.max(anchorPos.index, headPos.index)));
              const isPeerSelecting = pStart !== pEnd;

              // Line highlight for remote peer
              const pStartLine = update.state.doc.lineAt(pStart);
              const pEndLine = update.state.doc.lineAt(pEnd);
              for (let l = pStartLine.number; l <= pEndLine.number; l++) {
                if (!decoratedLines.has(l)) {
                  decoratedLines.add(l);
                  const line = update.state.doc.line(l);
                  decos.push(
                    Decoration.line({
                      attributes: {
                        class: "cm-crex-peer-selected-line",
                        style: `background-color: ${hexToRgba(color, 0.08)} !important; border-left: 3px solid ${color} !important;`,
                      },
                    }).range(line.from)
                  );
                }
              }

              // Selected words highlight for peer
              if (isPeerSelecting) {
                decos.push(
                  Decoration.mark({
                    class: "cm-crex-peer-selection-ribbon",
                    attributes: {
                      style: `background-color: ${hexToRgba(color, 0.22)} !important; outline: 1.2px solid ${color} !important; border-radius: 4px !important; box-shadow: 0 0 10px ${hexToRgba(color, 0.25)} !important; color: #FFFFFF !important;`,
                    },
                  }).range(pStart, pEnd)
                );
              }

              // Remote Caret & Name Badge Widget
              decos.push(
                Decoration.widget({
                  side: headPos.index - anchorPos.index > 0 ? -1 : 1,
                  block: false,
                  widget: new CrexRemoteCaretWidget(
                    color,
                    name,
                    uid,
                    isTyping,
                    isPeerSelecting,
                    isIdle
                  ),
                }).range(Math.max(0, Math.min(docLength, headPos.index)))
              );
            }
          }

          // 2. Remote Peer Active Writing / Changes Highlight
          // "from the starting point to the end point of the changes, that area should be in that color"
          if (state.activeChange && state.activeChange.anchor && state.activeChange.head) {
            const chStartPos = Y.createAbsolutePositionFromRelativePosition(state.activeChange.anchor, ydoc);
            const chEndPos = Y.createAbsolutePositionFromRelativePosition(state.activeChange.head, ydoc);

            if (chStartPos && chEndPos && chStartPos.type === ytext && chEndPos.type === ytext) {
              const cStart = Math.max(0, Math.min(docLength, chStartPos.index, chEndPos.index));
              const cEnd = Math.max(0, Math.min(docLength, Math.max(chStartPos.index, chEndPos.index)));

              if (cStart < cEnd) {
                decos.push(
                  Decoration.mark({
                    class: "cm-crex-peer-change-highlight",
                    attributes: {
                      style: `background-color: ${hexToRgba(color, 0.16)} !important; outline: 1.2px solid ${color} !important; border-radius: 4px !important; padding: 1px 2px !important; box-shadow: 0 0 10px ${hexToRgba(color, 0.22)} !important; color: #FFFFFF !important;`,
                    },
                  }).range(cStart, cEnd)
                );
              }
            }
          }
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

// -------------------------------------------------------------------
// 3. COLLABORATIVE MULTI-PEER SIMULATION ENGINE
// Allows live testing of Erik (Pink #ff70a6) and Muhaymin (Green #16a34a)
// in the actual IDE editor.
// -------------------------------------------------------------------

let simInterval: NodeJS.Timeout | null = null;
let simStep = 0;

export function isCrexCollabSimulationActive(): boolean {
  return simInterval !== null;
}

export function startCrexCollabSimulation(awareness: Awareness, ydoc: Y.Doc, ytext: Y.Text) {
  if (simInterval) clearInterval(simInterval);
  simStep = 0;

  const erikId = 9101;
  const muhayminId = 9102;

  simInterval = setInterval(() => {
    if (!ydoc || !ytext || !awareness) {
      stopCrexCollabSimulation(awareness);
      return;
    }

    const docStr = ytext.toString();
    const docLen = docStr.length;
    if (docLen < 20) return;

    simStep = (simStep + 1) % 6;

    // STEP 0: Erik (#ff70a6, Pink) selects words on line 3
    if (simStep === 0) {
      const line3 = docStr.indexOf("timeout");
      const start = line3 !== -1 ? line3 : Math.floor(docLen * 0.25);
      const end = line3 !== -1 ? line3 + "timeout".length : start + 7;

      const anchor = Y.createRelativePositionFromTypeIndex(ytext, start);
      const head = Y.createRelativePositionFromTypeIndex(ytext, end);

      awareness.states.set(erikId, {
        user: { name: "Erik", color: "#ff70a6", uid: "CRX-ERIK-PK" },
        cursor: { anchor, head },
        isTyping: false,
        lastActive: Date.now(),
      });
      awareness.emit("change", [{ added: [], updated: [erikId], removed: [] }, "sim"]);
    }

    // STEP 1: Erik (#ff70a6, Pink) writes changes with active change highlight
    else if (simStep === 1) {
      const line3 = docStr.indexOf("timeout");
      const start = line3 !== -1 ? line3 : Math.floor(docLen * 0.25);
      const end = start + 12;

      const anchor = Y.createRelativePositionFromTypeIndex(ytext, start);
      const head = Y.createRelativePositionFromTypeIndex(ytext, end);

      awareness.states.set(erikId, {
        user: { name: "Erik", color: "#ff70a6", uid: "CRX-ERIK-PK" },
        cursor: { anchor: head, head },
        activeChange: { anchor, head, isTyping: true },
        isTyping: true,
        lastActive: Date.now(),
      });
      awareness.emit("change", [{ added: [], updated: [erikId], removed: [] }, "sim"]);
    }

    // STEP 2: Muhaymin (#16a34a, Green) selects words on line 7
    else if (simStep === 2) {
      const line7 = docStr.indexOf("ticket");
      const start = line7 !== -1 ? line7 : Math.floor(docLen * 0.65);
      const end = line7 !== -1 ? line7 + "ticket".length : start + 6;

      const anchor = Y.createRelativePositionFromTypeIndex(ytext, start);
      const head = Y.createRelativePositionFromTypeIndex(ytext, end);

      awareness.states.set(muhayminId, {
        user: { name: "Muhaymin", color: "#16a34a", uid: "CRX-MUHAYMIN-GR" },
        cursor: { anchor, head },
        isTyping: false,
        lastActive: Date.now(),
      });
      awareness.emit("change", [{ added: [], updated: [muhayminId], removed: [] }, "sim"]);
    }

    // STEP 3: Muhaymin (#16a34a, Green) writes changes with active change highlight
    else if (simStep === 3) {
      const line7 = docStr.indexOf("ticket");
      const start = line7 !== -1 ? line7 : Math.floor(docLen * 0.65);
      const end = start + 16;

      const anchor = Y.createRelativePositionFromTypeIndex(ytext, start);
      const head = Y.createRelativePositionFromTypeIndex(ytext, end);

      awareness.states.set(muhayminId, {
        user: { name: "Muhaymin", color: "#16a34a", uid: "CRX-MUHAYMIN-GR" },
        cursor: { anchor: head, head },
        activeChange: { anchor, head, isTyping: true },
        isTyping: true,
        lastActive: Date.now(),
      });
      awareness.emit("change", [{ added: [], updated: [muhayminId], removed: [] }, "sim"]);
    }

    // STEP 4: Both peers resting with stable caret and author highlights
    else if (simStep === 4) {
      const line3 = docStr.indexOf("timeout");
      const posE = line3 !== -1 ? line3 + 7 : Math.floor(docLen * 0.25);
      const anchorE = Y.createRelativePositionFromTypeIndex(ytext, posE);

      awareness.states.set(erikId, {
        user: { name: "Erik", color: "#ff70a6", uid: "CRX-ERIK-PK" },
        cursor: { anchor: anchorE, head: anchorE },
        isTyping: false,
        lastActive: Date.now(),
      });

      const line7 = docStr.indexOf("ticket");
      const posM = line7 !== -1 ? line7 + 6 : Math.floor(docLen * 0.65);
      const anchorM = Y.createRelativePositionFromTypeIndex(ytext, posM);

      awareness.states.set(muhayminId, {
        user: { name: "Muhaymin", color: "#16a34a", uid: "CRX-MUHAYMIN-GR" },
        cursor: { anchor: anchorM, head: anchorM },
        isTyping: false,
        lastActive: Date.now(),
      });

      awareness.emit("change", [{ added: [], updated: [erikId, muhayminId], removed: [] }, "sim"]);
    }
  }, 2200);
}

export function stopCrexCollabSimulation(awareness?: Awareness) {
  if (simInterval) {
    clearInterval(simInterval);
    simInterval = null;
  }
  if (awareness) {
    awareness.states.delete(9101);
    awareness.states.delete(9102);
    awareness.emit("change", [{ added: [], updated: [], removed: [9101, 9102] }, "sim"]);
  }
}
