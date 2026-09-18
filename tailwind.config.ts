import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "SF Pro Display",
          "Segoe UI",
          "sans-serif",
        ],
        mono: [
          "var(--font-geist-mono)",
          "Geist Mono",
          "JetBrains Mono",
          "SF Mono",
          "ui-monospace",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      colors: {
        // Crux Brutalist Color Palette (DESIGN.md)
        void: "#000000",
        surface: "#0A0A0A",
        grid: "#222222",
        signal: "#FFFFFF",
        dim: "#888888",
        crux: {
          blue: "#007AFF",       // Accent 1 (User 1 Cursor, Primary action)
          crimson: "#FF453A",    // Accent 2 (CruxAI Crimson)
          green: "#00FF00",      // Diff Addition
        },
        border: {
          DEFAULT: "#222222",
          subtle: "#161616",
          strong: "#333333",
        },
      },
      borderRadius: {
        none: "0px",
        xs: "2px",
        sm: "2px",
        DEFAULT: "2px",
        md: "4px",
        lg: "4px",
        xl: "4px",
        "2xl": "4px",
        full: "9999px",
      },
      boxShadow: {
        none: "none",
        hard: "4px 4px 0px #222222", // Canvas cards hard drop shadow (Section 6)
      },
    },
  },
  plugins: [],
};

export default config;
