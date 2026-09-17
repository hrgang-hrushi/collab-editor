/**
 * Crux Studio Haptic & Tactile Feedback Engine
 * Synthesizes subtle physical haptics via the Web Haptics API (navigator.vibrate)
 * and procedural micro-acoustics via the Web Audio API for an ultra-tactile IDE experience.
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
  private audioCtx: AudioContext | null = null;
  private isEnabled: boolean = true;
  private soundVolume: number = 0.08; // Delicate, non-intrusive volume

  constructor() {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("crux_haptics_enabled");
      if (saved !== null) {
        this.isEnabled = saved === "true";
      }
    }
  }

  private initAudio() {
    if (typeof window === "undefined") return null;
    if (!this.audioCtx) {
      const AudioContextClass =
        window.AudioContext || (window as any).webkitAudioContext;
      if (AudioContextClass) {
        this.audioCtx = new AudioContextClass();
      }
    }
    if (this.audioCtx && this.audioCtx.state === "suspended") {
      this.audioCtx.resume();
    }
    return this.audioCtx;
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
    if (this.isEnabled) {
      this.trigger("success");
    }
    return this.isEnabled;
  }

  public trigger(type: HapticPattern = "click") {
    if (!this.isEnabled || typeof window === "undefined") return;

    // 1. Hardware Vibration Haptic (Mobile / Android / macOS Trackpad bridge)
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
        // Fallback silently if vibration blocked by browser policy
      }
    }

    // 2. Synthesized Procedural Acoustics (Web Audio API)
    try {
      const ctx = this.initAudio();
      if (!ctx) return;

      const now = ctx.currentTime;
      const gain = ctx.createGain();
      gain.connect(ctx.destination);

      switch (type) {
        case "click": {
          // Sharp mechanical micro-click (like a premium tactile mouse switch)
          const osc = ctx.createOscillator();
          osc.type = "sine";
          osc.frequency.setValueAtTime(1400, now);
          osc.frequency.exponentialRampToValueAtTime(320, now + 0.015);

          gain.gain.setValueAtTime(this.soundVolume * 0.9, now);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.018);

          osc.connect(gain);
          osc.start(now);
          osc.stop(now + 0.02);
          break;
        }

        case "tap": {
          // Ultra-soft muted tap
          const osc = ctx.createOscillator();
          osc.type = "triangle";
          osc.frequency.setValueAtTime(800, now);
          osc.frequency.exponentialRampToValueAtTime(200, now + 0.01);

          gain.gain.setValueAtTime(this.soundVolume * 0.4, now);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.012);

          osc.connect(gain);
          osc.start(now);
          osc.stop(now + 0.015);
          break;
        }

        case "toggle": {
          // Dual frequency snappy toggle click
          const osc = ctx.createOscillator();
          osc.type = "sine";
          osc.frequency.setValueAtTime(600, now);
          osc.frequency.exponentialRampToValueAtTime(1100, now + 0.025);

          gain.gain.setValueAtTime(this.soundVolume * 0.8, now);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.028);

          osc.connect(gain);
          osc.start(now);
          osc.stop(now + 0.03);
          break;
        }

        case "type": {
          // Subtle mechanical switch keystroke
          const osc = ctx.createOscillator();
          osc.type = "triangle";
          const baseFreq = 750 + Math.random() * 150;
          osc.frequency.setValueAtTime(baseFreq, now);
          osc.frequency.exponentialRampToValueAtTime(180, now + 0.012);

          gain.gain.setValueAtTime(this.soundVolume * 0.25, now);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.014);

          osc.connect(gain);
          osc.start(now);
          osc.stop(now + 0.016);
          break;
        }

        case "run": {
          // Futuristic charge-up pulse
          const osc = ctx.createOscillator();
          osc.type = "sawtooth";
          osc.frequency.setValueAtTime(220, now);
          osc.frequency.exponentialRampToValueAtTime(880, now + 0.05);

          const filter = ctx.createBiquadFilter();
          filter.type = "lowpass";
          filter.frequency.setValueAtTime(1200, now);

          gain.gain.setValueAtTime(this.soundVolume * 0.7, now);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.055);

          osc.connect(filter);
          filter.connect(gain);
          osc.start(now);
          osc.stop(now + 0.06);
          break;
        }

        case "success": {
          // Two-tone harmonious chime (C6 -> G6)
          const osc1 = ctx.createOscillator();
          const osc2 = ctx.createOscillator();
          osc1.type = "sine";
          osc2.type = "sine";

          osc1.frequency.setValueAtTime(1046.5, now); // C6
          osc2.frequency.setValueAtTime(1567.98, now + 0.04); // G6

          const gain1 = ctx.createGain();
          const gain2 = ctx.createGain();

          gain1.gain.setValueAtTime(this.soundVolume * 0.7, now);
          gain1.gain.exponentialRampToValueAtTime(0.0001, now + 0.08);

          gain2.gain.setValueAtTime(0, now);
          gain2.gain.setValueAtTime(this.soundVolume * 0.9, now + 0.04);
          gain2.gain.exponentialRampToValueAtTime(0.0001, now + 0.14);

          osc1.connect(gain1);
          gain1.connect(ctx.destination);
          osc2.connect(gain2);
          gain2.connect(ctx.destination);

          osc1.start(now);
          osc1.stop(now + 0.09);
          osc2.start(now + 0.04);
          osc2.stop(now + 0.15);
          break;
        }

        case "error": {
          // Low damped double buzzer
          const osc = ctx.createOscillator();
          osc.type = "sawtooth";
          osc.frequency.setValueAtTime(180, now);
          osc.frequency.setValueAtTime(130, now + 0.04);

          const filter = ctx.createBiquadFilter();
          filter.type = "lowpass";
          filter.frequency.setValueAtTime(450, now);

          gain.gain.setValueAtTime(this.soundVolume * 0.9, now);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.09);

          osc.connect(filter);
          filter.connect(gain);
          osc.start(now);
          osc.stop(now + 0.1);
          break;
        }

        case "agent": {
          // Neural soft synth ping
          const osc = ctx.createOscillator();
          osc.type = "sine";
          osc.frequency.setValueAtTime(1200 + Math.random() * 400, now);
          osc.frequency.exponentialRampToValueAtTime(600, now + 0.02);

          gain.gain.setValueAtTime(this.soundVolume * 0.35, now);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.025);

          osc.connect(gain);
          osc.start(now);
          osc.stop(now + 0.03);
          break;
        }

        case "drop": {
          // Woody click on drop
          const osc = ctx.createOscillator();
          osc.type = "sine";
          osc.frequency.setValueAtTime(320, now);
          osc.frequency.exponentialRampToValueAtTime(90, now + 0.03);

          gain.gain.setValueAtTime(this.soundVolume * 0.8, now);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.035);

          osc.connect(gain);
          osc.start(now);
          osc.stop(now + 0.04);
          break;
        }
      }
    } catch {
      // AudioContext might be blocked until first user gesture
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
