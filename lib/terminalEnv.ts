import os from "os";

export function getTerminalExtendedPath(): string {
  const userHome = process.env.HOME || os.homedir() || "/Users/hrushikeshgangala";
  const searchPaths = [
    `${userHome}/.local/bin`,
    `${userHome}/.npm-global/bin`,
    `${userHome}/.bun/bin`,
    `${userHome}/.cargo/bin`,
    `${userHome}/.gemini/antigravity-cli/bin`,
    `${userHome}/.nvm/current/bin`,
    `${userHome}/.yarn/bin`,
    `/opt/homebrew/bin`,
    `/opt/homebrew/sbin`,
    `/usr/local/bin`,
    `/Applications/Cursor.app/Contents/Resources/app/bin`,
    `/Applications/Visual Studio Code.app/Contents/Resources/app/bin`,
    process.env.PATH || "",
    `/usr/bin`,
    `/bin`,
    `/usr/sbin`,
    `/sbin`,
  ];

  return Array.from(new Set(searchPaths.filter(Boolean))).join(":");
}
