import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { ThinkingOrb, type OrbState } from "thinking-orbs";

const orbs: { state: OrbState; description: string }[] = [
  { state: "working", description: "Particles move on tilted orbits" },
  { state: "searching", description: "A scan line sweeps a dotted globe" },
  { state: "solving", description: "Bands scramble, then resolve" },
  { state: "listening", description: "A wave moves through the rings" },
  { state: "connecting", description: "Points link into a constellation" },
  { state: "weaving", description: "Three strands plait together" },
  { state: "composing", description: "Bands undulate around the sphere" },
  { state: "breathing", description: "A ring slowly changes shape" },
  { state: "shaping", description: "Dots morph from circle to triangle to square" },
];

function OrbGallery() {
  const [selected, setSelected] = useState<OrbState | null>(() => {
    try {
      const saved = window.localStorage.getItem("crux-loading-orb-choice");
      return orbs.find(({ state }) => state === saved)?.state ?? null;
    } catch {
      return null;
    }
  });

  const chooseOrb = (state: OrbState | null) => {
    setSelected(state);
    try {
      if (state) window.localStorage.setItem("crux-loading-orb-choice", state);
      else window.localStorage.removeItem("crux-loading-orb-choice");
    } catch {
      // The preview still works when browser storage is unavailable.
    }
  };

  return (
    <main>
      <header className="page-header">
        <div className="eyebrow">CRUX / MOTION STUDY 01</div>
        <h1>Loading orb comparison</h1>
        <p>All nine animations are live. Select a tile to mark your favorite for the IDE loading indicator.</p>
        <div className="selection-row">
          <div className="selection" role="status" aria-live="polite">
            CURRENT FAVORITE <strong>{selected ? selected.toUpperCase() : "NONE SELECTED"}</strong>
          </div>
          {selected && <button className="clear-choice" type="button" onClick={() => chooseOrb(null)}>CLEAR CHOICE</button>}
        </div>
      </header>
      <section className="grid" aria-label="Orb animation choices">
        {orbs.map(({ state, description }, index) => (
          <button
            className="orb-card"
            data-selected={selected === state}
            type="button"
            key={state}
            onClick={() => chooseOrb(state)}
            aria-pressed={selected === state}
            aria-label={`${state}: ${description}`}
          >
            <div className="card-top"><span>{String(index + 1).padStart(2, "0")}</span><span>{selected === state ? "SELECTED" : "PREVIEW"}</span></div>
            <div className="orb-stage"><ThinkingOrb state={state} size={64} theme="dark" aria-hidden="true" /></div>
            <div className="card-title">{state}</div>
            <div className="card-description">{description}</div>
            <div className="inline-preview"><ThinkingOrb state={state} size={20} theme="dark" aria-hidden="true" /><span>20 PX LOADING SIZE</span></div>
          </button>
        ))}
      </section>
      <footer>64 PX DETAIL VIEW / 20 PX IDE LOADING VIEW · SELECT ONE TO FINALIZE LATER</footer>
    </main>
  );
}

createRoot(document.getElementById("orb-gallery")!).render(<OrbGallery />);
