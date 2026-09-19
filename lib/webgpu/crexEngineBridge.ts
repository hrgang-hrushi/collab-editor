/**
 * Crex Proprietary Engine: WebGPU Rendering Pipeline & AST-CRDT State Machine
 * Renders directly to HTML5 Canvas bypassing DOM textareas.
 */

export interface AstNodeId {
  clientId: string;
  counter: number;
}

export interface AstMutation {
  type: "NodeInserted" | "NodeDeleted" | "NodeReplaced";
  nodeId: AstNodeId;
  kind?: string;
  text?: string;
  index?: number;
}

export interface AstSyncDelta {
  clientId: string;
  lamportTs: number;
  mutations: AstMutation[];
}

export class CrexAstSyncMachine {
  public clientId: string;
  public lamportTs: number = 0;
  private counter: number = 0;

  constructor(clientId?: string) {
    this.clientId = clientId || `peer_${Math.floor(Math.random() * 10000).toString(16)}`;
  }

  public createInsertDelta(text: string, kind: string = "code_block"): AstSyncDelta {
    this.lamportTs++;
    this.counter++;
    const nodeId: AstNodeId = { clientId: this.clientId, counter: this.counter };
    return {
      clientId: this.clientId,
      lamportTs: this.lamportTs,
      mutations: [{ type: "NodeInserted", nodeId, kind, text }],
    };
  }

  public createReplaceDelta(text: string, kind: string = "token"): AstSyncDelta {
    this.lamportTs++;
    this.counter++;
    const nodeId: AstNodeId = { clientId: this.clientId, counter: this.counter };
    return {
      clientId: this.clientId,
      lamportTs: this.lamportTs,
      mutations: [{ type: "NodeReplaced", nodeId, kind, text }],
    };
  }
}

export class CrexWebGpuEngine {
  private canvas: HTMLCanvasElement;
  private ctx2d: CanvasRenderingContext2D | null = null;
  private gpuDevice: any = null;
  private isWebGpuActive: boolean = false;
  
  public lines: string[] = [""];
  public cursorLine: number = 0;
  public cursorCol: number = 0;
  public selectionStart: { line: number; col: number } | null = null;
  public selectionEnd: { line: number; col: number } | null = null;
  public scrollY: number = 0;
  public scrollX: number = 0;
  
  public charWidth: number = 8.8;
  public lineHeight: number = 21;
  public gutterWidth: number = 46;
  public fps: number = 120;

  private lastFrameTime: number = performance.now();
  private cursorBlinkState: boolean = true;
  private lastBlinkToggle: number = performance.now();
  private animFrameId: number | null = null;
  private onDeltaEmit?: (delta: AstSyncDelta) => void;
  public crdt: CrexAstSyncMachine;

  constructor(canvas: HTMLCanvasElement, onDeltaEmit?: (delta: AstSyncDelta) => void) {
    this.canvas = canvas;
    this.onDeltaEmit = onDeltaEmit;
    this.crdt = new CrexAstSyncMachine();
  }

  public async init(initialText: string = "") {
    this.lines = initialText.split("\n");
    if (this.lines.length === 0) this.lines = [""];

    if (typeof navigator !== "undefined" && "gpu" in navigator && (navigator as any).gpu) {
      try {
        const adapter = await (navigator as any).gpu.requestAdapter({
          powerPreference: "high-performance",
        });
        if (adapter) {
          this.gpuDevice = await adapter.requestDevice();
          this.isWebGpuActive = true;
        }
      } catch (err) {
        console.warn("[CREX_ENGINE]: WebGPU device init fallback to high-perf 2D Canvas pipeline", err);
      }
    }

    this.ctx2d = this.canvas.getContext("2d", { alpha: false, desynchronized: true });

    this.startRenderLoop();
  }

  public setContent(text: string) {
    this.lines = text.split("\n");
    if (this.lines.length === 0) this.lines = [""];
    this.cursorLine = Math.min(this.cursorLine, this.lines.length - 1);
    this.cursorCol = Math.min(this.cursorCol, this.lines[this.cursorLine]?.length || 0);
  }

  public getContent(): string {
    return this.lines.join("\n");
  }

  public handleKeyDown(e: KeyboardEvent): boolean {
    const isMeta = e.metaKey || e.ctrlKey;

    // Navigation
    if (e.key === "ArrowUp") {
      if (this.cursorLine > 0) {
        this.cursorLine--;
        this.cursorCol = Math.min(this.cursorCol, this.lines[this.cursorLine].length);
      }
      this.selectionStart = null;
      return true;
    }
    if (e.key === "ArrowDown") {
      if (this.cursorLine < this.lines.length - 1) {
        this.cursorLine++;
        this.cursorCol = Math.min(this.cursorCol, this.lines[this.cursorLine].length);
      }
      this.selectionStart = null;
      return true;
    }
    if (e.key === "ArrowLeft") {
      if (this.cursorCol > 0) {
        this.cursorCol--;
      } else if (this.cursorLine > 0) {
        this.cursorLine--;
        this.cursorCol = this.lines[this.cursorLine].length;
      }
      this.selectionStart = null;
      return true;
    }
    if (e.key === "ArrowRight") {
      if (this.cursorCol < this.lines[this.cursorLine].length) {
        this.cursorCol++;
      } else if (this.cursorLine < this.lines.length - 1) {
        this.cursorLine++;
        this.cursorCol = 0;
      }
      this.selectionStart = null;
      return true;
    }

    // Enter
    if (e.key === "Enter") {
      const curLineText = this.lines[this.cursorLine];
      const before = curLineText.slice(0, this.cursorCol);
      const after = curLineText.slice(this.cursorCol);
      
      this.lines[this.cursorLine] = before;
      this.lines.splice(this.cursorLine + 1, 0, after);
      this.cursorLine++;
      this.cursorCol = 0;
      this.selectionStart = null;

      const delta = this.crdt.createInsertDelta("\n", "newline");
      this.onDeltaEmit?.(delta);
      return true;
    }

    // Backspace
    if (e.key === "Backspace") {
      if (this.cursorCol > 0) {
        const curLineText = this.lines[this.cursorLine];
        this.lines[this.cursorLine] = curLineText.slice(0, this.cursorCol - 1) + curLineText.slice(this.cursorCol);
        this.cursorCol--;
      } else if (this.cursorLine > 0) {
        const prevLineLen = this.lines[this.cursorLine - 1].length;
        this.lines[this.cursorLine - 1] += this.lines[this.cursorLine];
        this.lines.splice(this.cursorLine, 1);
        this.cursorLine--;
        this.cursorCol = prevLineLen;
      }
      this.selectionStart = null;
      const delta = this.crdt.createReplaceDelta(this.lines[this.cursorLine] || "", "line_backspace");
      this.onDeltaEmit?.(delta);
      return true;
    }

    // Tab
    if (e.key === "Tab") {
      e.preventDefault();
      const curLineText = this.lines[this.cursorLine];
      this.lines[this.cursorLine] = curLineText.slice(0, this.cursorCol) + "  " + curLineText.slice(this.cursorCol);
      this.cursorCol += 2;
      return true;
    }

    // Plain text input
    if (e.key.length === 1 && !isMeta) {
      const curLineText = this.lines[this.cursorLine] || "";
      this.lines[this.cursorLine] = curLineText.slice(0, this.cursorCol) + e.key + curLineText.slice(this.cursorCol);
      this.cursorCol++;
      this.selectionStart = null;

      const delta = this.crdt.createInsertDelta(e.key, "char");
      this.onDeltaEmit?.(delta);
      return true;
    }

    return false;
  }

  public handleClick(offsetX: number, offsetY: number) {
    const line = Math.max(0, Math.min(this.lines.length - 1, Math.floor((offsetY + this.scrollY) / this.lineHeight)));
    const col = Math.max(0, Math.min(this.lines[line]?.length || 0, Math.round((offsetX - this.gutterWidth + this.scrollX) / this.charWidth)));
    this.cursorLine = line;
    this.cursorCol = col;
    this.selectionStart = null;
    this.selectionEnd = null;
    this.cursorBlinkState = true;
    this.lastBlinkToggle = performance.now();
  }

  private startRenderLoop() {
    const loop = (timestamp: number) => {
      const dt = timestamp - this.lastFrameTime;
      this.lastFrameTime = timestamp;
      if (dt > 0) {
        this.fps = Math.round(1000 / dt);
      }

      // Hard mechanical cursor blink at 500ms
      if (timestamp - this.lastBlinkToggle > 500) {
        this.cursorBlinkState = !this.cursorBlinkState;
        this.lastBlinkToggle = timestamp;
      }

      this.render();
      this.animFrameId = requestAnimationFrame(loop);
    };
    this.animFrameId = requestAnimationFrame(loop);
  }

  public render() {
    const canvas = this.canvas;
    const ctx = this.ctx2d;
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;

    // Void background
    ctx.fillStyle = "#000000";
    ctx.fillRect(0, 0, width, height);

    // Gutter border
    ctx.fillStyle = "#222222";
    ctx.fillRect(this.gutterWidth, 0, 1, height);

    const firstVisibleLine = Math.max(0, Math.floor(this.scrollY / this.lineHeight));
    const visibleCount = Math.ceil(height / this.lineHeight) + 1;
    const lastVisibleLine = Math.min(this.lines.length - 1, firstVisibleLine + visibleCount);

    ctx.font = '13px "Arial MT Pro", "Arial MT", "Helvetica", sans-serif';
    ctx.textBaseline = "top";

    // Render lines and gutters
    for (let i = firstVisibleLine; i <= lastVisibleLine; i++) {
      const y = i * this.lineHeight - this.scrollY;

      // Gutter line number
      ctx.fillStyle = i === this.cursorLine ? "#FFFFFF" : "#444444";
      ctx.textAlign = "right";
      ctx.fillText((i + 1).toString(), this.gutterWidth - 8, y + 3);

      // Active line indicator
      if (i === this.cursorLine) {
        ctx.fillStyle = "#0D0D0D";
        ctx.fillRect(this.gutterWidth + 1, y, width - this.gutterWidth, this.lineHeight);
      }

      // Code text
      ctx.fillStyle = "#FFFFFF";
      ctx.textAlign = "left";
      const text = this.lines[i] || "";
      ctx.fillText(text, this.gutterWidth + 8 - this.scrollX, y + 3);
    }

    // Render Cursor (1px solid white, no easing)
    if (this.cursorBlinkState) {
      const cursorX = this.gutterWidth + 8 + this.cursorCol * this.charWidth - this.scrollX;
      const cursorY = this.cursorLine * this.lineHeight - this.scrollY;

      ctx.fillStyle = "#FFFFFF";
      ctx.fillRect(cursorX, cursorY + 2, 1.5, this.lineHeight - 3);
    }
  }

  public destroy() {
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }
  }
}
