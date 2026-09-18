import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        brand: [
          "var(--font-space)",
          "Space Grotesk",
          "var(--font-hanken)",
          "Hanken Grotesk",
          "Etna Sans Serif",
          "Arial Black",
          "sans-serif",
        ],
        display: [
          "var(--font-space)",
          "Space Grotesk",
          "var(--font-hanken)",
          "Hanken Grotesk",
          "-apple-system",
          "sans-serif",
        ],
        space: [
          "var(--font-space)",
          "Space Grotesk",
          "sans-serif",
        ],
        sans: [
          "var(--font-hanken)",
          "Hanken Grotesk",
          "Arial MT Pro",
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "sans-serif",
        ],
        mono: [
          "var(--font-geist-mono)",
          "Geist Mono",
          "JetBrains Mono",
          "SF Mono",
          "ui-monospace",
          "Menlo",
          "monospace",
        ],
      },
      colors: {
        // Crex Hardware Brutalism Monochrome Palette
        void: "#000000",
        silk: "#FFFFFF",
        silicon: "#111111",
        grid: "#222222",
        muted: "#444444",

        // Aliases for system compatibility
        surface: "#111111",
        signal: "#FFFFFF",
        dim: "#444444",

        border: {
          DEFAULT: "#222222",
          subtle: "#111111",
          strong: "#222222",
        },
      },
      borderRadius: {
        none: "0px",
        xs: "0px",
        sm: "0px",
        DEFAULT: "0px",
        md: "0px",
        lg: "0px",
        xl: "0px",
        "2xl": "0px",
        full: "0px",
      },
      boxShadow: {
        none: "none",
        DEFAULT: "none",
        sm: "none",
        md: "none",
        lg: "none",
        xl: "none",
        "2xl": "none",
      },
      animation: {
        "spin-slow": "spin 30s linear infinite",
        "hard-blink": "hardBlink 1s steps(1, start) infinite",
      },
      keyframes: {
        hardBlink: {
          "0%, 49%": { opacity: "1" },
          "50%, 100%": { opacity: "0" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
