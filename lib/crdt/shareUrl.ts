/** A native window uses tauri://, which a browser cannot open as a join link. */
export function getBrowserShareBaseUrl(): string {
  if (typeof window === "undefined") return "";
  if (window.location.protocol === "tauri:") {
    return process.env.NEXT_PUBLIC_CRUX_WEB_IDE_URL || "http://localhost:3000/ide";
  }
  return `${window.location.origin}${window.location.pathname}`;
}
