/**
 * Zero-dependency ANSI escape sequence & file-link tokenizer for CRUX Terminal.
 * Translates VT100 / ANSI 256 / TrueColor escapes into structured styled spans.
 */

export interface AnsiSpan {
  text: string;
  color?: string;
  bgColor?: string;
  bold?: boolean;
  dim?: boolean;
  underline?: boolean;
  fileLink?: {
    path: string;
    line?: number;
    col?: number;
  };
}

export interface AnsiLine {
  id: string;
  rawText: string;
  spans: AnsiSpan[];
  timestamp?: number;
  isError?: boolean;
  executorName?: string;
  executorColor?: string;
}

// 16 standard ANSI colors mapped to industrial brutalist palette
const STANDARD_COLORS: Record<number, string> = {
  30: "#1A1A1A", // Black
  31: "#FF453A", // Red
  32: "#00FF00", // Green
  33: "#FFD60A", // Yellow
  34: "#007AFF", // Blue
  35: "#BF5AF2", // Magenta
  36: "#00E5FF", // Cyan
  37: "#E5E5E5", // White
  90: "#666666", // Bright Black / Gray
  91: "#FF6961", // Bright Red
  92: "#30D158", // Bright Green
  93: "#FFEE55", // Bright Yellow
  94: "#5AC8FA", // Bright Blue
  95: "#DA8FFF", // Bright Magenta
  96: "#70D7FF", // Bright Cyan
  97: "#FFFFFF", // Bright White
};

const BG_COLORS: Record<number, string> = {
  40: "#111111",
  41: "#3D0000",
  42: "#003300",
  43: "#332B00",
  44: "#00204D",
  45: "#2E004D",
  46: "#00334D",
  47: "#333333",
};

// File link regex pattern matches filenames with optional :line:col
const FILE_LINK_REGEX = /([a-zA-Z0-9_\-\./]+\.(?:ts|tsx|js|jsx|json|md|py|css|html|yaml|yml))(?::(\d+)(?::(\d+))?)?/g;

export function parseAnsiText(text: string): AnsiSpan[] {
  if (!text) return [];

  const spans: AnsiSpan[] = [];
  let currentColor: string | undefined = undefined;
  let currentBgColor: string | undefined = undefined;
  let isBold = false;
  let isDim = false;
  let isUnderline = false;

  // Split text by ANSI escape sequence \x1b\[[0-9;]*[a-zA-Z]
  const ansiRegex = /\x1b\[([0-9;]*)([a-zA-Z])/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = ansiRegex.exec(text)) !== null) {
    const rawChunk = text.slice(lastIndex, match.index);
    if (rawChunk) {
      appendSpansWithLinks(spans, rawChunk, {
        color: currentColor,
        bgColor: currentBgColor,
        bold: isBold,
        dim: isDim,
        underline: isUnderline,
      });
    }

    const codes = match[1] ? match[1].split(";").map(Number) : [0];
    const command = match[2];

    if (command === "m") {
      let i = 0;
      while (i < codes.length) {
        const c = codes[i];
        if (c === 0) {
          currentColor = undefined;
          currentBgColor = undefined;
          isBold = false;
          isDim = false;
          isUnderline = false;
        } else if (c === 1) {
          isBold = true;
        } else if (c === 2) {
          isDim = true;
        } else if (c === 4) {
          isUnderline = true;
        } else if (c === 22) {
          isBold = false;
          isDim = false;
        } else if (c === 24) {
          isUnderline = false;
        } else if (c === 39) {
          currentColor = undefined;
        } else if (c === 49) {
          currentBgColor = undefined;
        } else if (STANDARD_COLORS[c]) {
          currentColor = STANDARD_COLORS[c];
        } else if (BG_COLORS[c]) {
          currentBgColor = BG_COLORS[c];
        } else if (c === 38 && codes[i + 1] === 2) {
          // TrueColor RGB: \x1b[38;2;R;G;Bm
          const r = codes[i + 2];
          const g = codes[i + 3];
          const b = codes[i + 4];
          if (r !== undefined && g !== undefined && b !== undefined) {
            currentColor = `rgb(${r},${g},${b})`;
            i += 4;
          }
        } else if (c === 48 && codes[i + 1] === 2) {
          const r = codes[i + 2];
          const g = codes[i + 3];
          const b = codes[i + 4];
          if (r !== undefined && g !== undefined && b !== undefined) {
            currentBgColor = `rgb(${r},${g},${b})`;
            i += 4;
          }
        }
        i++;
      }
    }

    lastIndex = ansiRegex.lastIndex;
  }

  const remaining = text.slice(lastIndex);
  if (remaining) {
    appendSpansWithLinks(spans, remaining, {
      color: currentColor,
      bgColor: currentBgColor,
      bold: isBold,
      dim: isDim,
      underline: isUnderline,
    });
  }

  return spans;
}

function appendSpansWithLinks(
  outSpans: AnsiSpan[],
  chunk: string,
  style: Omit<AnsiSpan, "text" | "fileLink">
) {
  // Check if chunk contains file references
  let lastIdx = 0;
  FILE_LINK_REGEX.lastIndex = 0;
  let m: RegExpExecArray | null;

  while ((m = FILE_LINK_REGEX.exec(chunk)) !== null) {
    const before = chunk.slice(lastIdx, m.index);
    if (before) {
      outSpans.push({ ...style, text: before });
    }

    const filePath = m[1];
    const line = m[2] ? parseInt(m[2], 10) : undefined;
    const col = m[3] ? parseInt(m[3], 10) : undefined;

    outSpans.push({
      ...style,
      text: m[0],
      fileLink: { path: filePath, line, col },
      underline: true,
    });

    lastIdx = FILE_LINK_REGEX.lastIndex;
  }

  const remainder = chunk.slice(lastIdx);
  if (remainder) {
    outSpans.push({ ...style, text: remainder });
  }
}

/**
 * Appends streaming chunks to an existing line buffer, respecting \r carriage returns
 * for progress bars and \n line breaks.
 */
export function appendStreamChunkToLines(
  lines: AnsiLine[],
  chunk: string,
  isError = false
): AnsiLine[] {
  const result = [...lines];
  const parts = chunk.split("\n");

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];

    // Handle carriage returns within the line (e.g. progress updates overwrite the line)
    const crSplit = part.split("\r");
    const activeText = crSplit[crSplit.length - 1];

    if (i === 0 && result.length > 0 && !chunk.startsWith("\n")) {
      // Append or overwrite existing last line
      const lastLine = result[result.length - 1];
      if (crSplit.length > 1) {
        // \r occurred, replace line content
        result[result.length - 1] = {
          ...lastLine,
          rawText: activeText,
          spans: parseAnsiText(activeText),
          isError: isError || lastLine.isError,
        };
      } else {
        const combined = lastLine.rawText + activeText;
        result[result.length - 1] = {
          ...lastLine,
          rawText: combined,
          spans: parseAnsiText(combined),
          isError: isError || lastLine.isError,
        };
      }
    } else if (activeText.length > 0 || i < parts.length - 1) {
      result.push({
        id: `line-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        rawText: activeText,
        spans: parseAnsiText(activeText),
        timestamp: Date.now(),
        isError,
      });
    }
  }

  // Bound maximum scrollback lines to 2500 for optimal memory & 120fps scrolling
  if (result.length > 2500) {
    return result.slice(result.length - 2500);
  }

  return result;
}
