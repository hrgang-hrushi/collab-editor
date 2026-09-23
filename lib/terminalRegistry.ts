import { ChildProcess } from "child_process";

// Global process registry for active terminal processes in Next.js runtime
const globalProcesses = globalThis as unknown as {
  _cruxTerminalProcesses?: Map<number, ChildProcess>;
};

if (!globalProcesses._cruxTerminalProcesses) {
  globalProcesses._cruxTerminalProcesses = new Map();
}

export const terminalProcesses = globalProcesses._cruxTerminalProcesses;

export function registerProcess(pid: number, proc: ChildProcess) {
  terminalProcesses.set(pid, proc);
}

export function unregisterProcess(pid: number) {
  terminalProcesses.delete(pid);
}

export function killProcess(pid: number, signal: NodeJS.Signals = "SIGINT"): boolean {
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
