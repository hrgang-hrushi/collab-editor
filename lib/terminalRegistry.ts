import { ChildProcess } from "child_process";

export type StdinHandler = (input: string) => void | Promise<void>;

// Global process and interactive handler registry for active terminal sessions in Next.js runtime
const globalProcesses = globalThis as unknown as {
  _cruxTerminalProcesses?: Map<number, ChildProcess>;
  _cruxStdinHandlers?: Map<number, StdinHandler>;
};

if (!globalProcesses._cruxTerminalProcesses) {
  globalProcesses._cruxTerminalProcesses = new Map();
}

if (!globalProcesses._cruxStdinHandlers) {
  globalProcesses._cruxStdinHandlers = new Map();
}

export const terminalProcesses = globalProcesses._cruxTerminalProcesses;
export const terminalStdinHandlers = globalProcesses._cruxStdinHandlers;

export function registerProcess(pid: number, proc: ChildProcess) {
  terminalProcesses.set(pid, proc);
}

export function unregisterProcess(pid: number) {
  terminalProcesses.delete(pid);
}

export function registerStdinHandler(pid: number, handler: StdinHandler) {
  terminalStdinHandlers.set(pid, handler);
}

export function unregisterStdinHandler(pid: number) {
  terminalStdinHandlers.delete(pid);
}

export function killProcess(pid: number, signal: NodeJS.Signals = "SIGINT"): boolean {
  if (terminalStdinHandlers.has(pid)) {
    const handler = terminalStdinHandlers.get(pid);
    if (handler) {
      try {
        handler("\x03"); // send Ctrl+C to virtual handler
      } catch {
        // ignore
      }
    }
    terminalStdinHandlers.delete(pid);
    return true;
  }

  const child = terminalProcesses.get(pid);
  if (child) {
    try {
      child.kill(signal);
      terminalProcesses.delete(pid);
      return true;
    } catch {
      // fallback to OS kill
    }
  }

  try {
    process.kill(pid, signal);
    return true;
  } catch {
    return false;
  }
}

export function writeToProcessStdin(pid: number, input: string): boolean {
  // 1. Check if there is an interactive session handler (e.g. Anti-Gravity or Claude REPL)
  if (terminalStdinHandlers.has(pid)) {
    const handler = terminalStdinHandlers.get(pid);
    if (handler) {
      try {
        handler(input);
        return true;
      } catch {
        return false;
      }
    }
  }

  // 2. Fallback to child OS process stdin
  const child = terminalProcesses.get(pid);
  if (child && child.stdin && !child.stdin.destroyed) {
    try {
      const data = input.endsWith("\n") ? input : `${input}\n`;
      child.stdin.write(data);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}
