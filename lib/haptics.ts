/**
 * Crux Studio Haptic Feedback Engine
 * Silent physical haptics via the Web Haptics API (navigator.vibrate).
 * All audio synthesizer / acoustic SFX have been completely removed.
 */

export type HapticPattern =
  | "click"     // Navigation clicks, tab switches, button presses
  | "tap"       // Subtle selection, item hover/focus
  | "toggle"    // Drawer open/close, toggle switches
  | "type"      // Subtle keypress tick in editor/terminal
  | "run"       // Code execution triggered
  | "success"   // Build succeeded, file saved, git commit created
  | "error"     // Execution error, syntax error, failed command
  | "agent"     // AI Agent token emitted / thinking pulse
  | "drop";     // Node dragged / file dropped

class HapticEngine {
  private isEnabled: boolean = true;

  constructor() {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("crux_haptics_enabled");
      if (saved !== null) {
        this.isEnabled = saved === "true";
      }
    }
  }

  public setEnabled(val: boolean) {
    this.isEnabled = val;
    if (typeof window !== "undefined") {
      localStorage.setItem("crux_haptics_enabled", String(val));
    }
  }

  public getEnabled(): boolean {
    return this.isEnabled;
  }

  public toggle(): boolean {
    this.setEnabled(!this.isEnabled);
    return this.isEnabled;
  }

  public trigger(type: HapticPattern = "click") {
    if (!this.isEnabled || typeof window === "undefined") return;

    // Silent Hardware Vibration Haptic (Mobile / Android / Trackpad bridge)
    if (typeof navigator !== "undefined" && "vibrate" in navigator) {
      try {
        switch (type) {
          case "tap":
            navigator.vibrate(6);
            break;
          case "click":
          case "toggle":
            navigator.vibrate(12);
            break;
          case "run":
            navigator.vibrate([10, 30, 15]);
            break;
          case "success":
            navigator.vibrate([8, 40, 16]);
            break;
          case "error":
            navigator.vibrate([30, 40, 30]);
            break;
          case "agent":
            navigator.vibrate(8);
            break;
          default:
            navigator.vibrate(10);
            break;
        }
      } catch {
        // Fallback silently
      }
    }
  }
}

export const hapticEngine = new HapticEngine();

export function triggerHaptic(type: HapticPattern = "click") {
  hapticEngine.trigger(type);
}

export function toggleHaptics(): boolean {
  return hapticEngine.toggle();
}

export function isHapticsEnabled(): boolean {
  return hapticEngine.getEnabled();
}
