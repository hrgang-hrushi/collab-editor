"use client";

import React, { useState, useRef } from "react";
import { ThinkingOrb } from "thinking-orbs";
import { BorderBeam } from "border-beam";
import { Liquid } from "liquid-gooey";
import { MetalFx, MetalText, MetalBadge, useMetalBend } from "metal-fx";
import { Play, Pause, ArrowUpRight } from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick } from "@/lib/sound";

interface CruxLibrariesDirectViewProps {
  onLaunchIde?: () => void;
}

type OrbState =
  | "working"
  | "searching"
  | "solving"
  | "listening"
  | "connecting"
  | "weaving"
  | "composing"
  | "breathing"
  | "shaping";

const ORB_STATES: OrbState[] = [
  "working",
  "searching",
  "solving",
  "listening",
  "connecting",
  "weaving",
  "composing",
  "breathing",
  "shaping",
];

export default function CruxLibrariesDirectView({ onLaunchIde }: CruxLibrariesDirectViewProps) {
  // Orb State
  const [orbState, setOrbState] = useState<OrbState>("composing");
  const [orbSize, setOrbSize] = useState<64 | 20>(64);
  const [orbSpeed, setOrbSpeed] = useState(1);
  const [orbPaused, setOrbPaused] = useState(false);

  // Beam State
  const [beamSize, setBeamSize] = useState<"md" | "sm" | "line" | "pulse-inner" | "pulse-outside">("line");
  const [beamColor, setBeamColor] = useState<"mono" | "colorful" | "ocean" | "sunset">("ocean");
  const [beamStrength, setBeamStrength] = useState(0.85);
  const [beamActive, setBeamActive] = useState(true);

  // Gooey State
  const [gooeyOpen, setGooeyOpen] = useState(false);
  const [gooeyBlur, setGooeyBlur] = useState(6);
  const [gooeyContrast, setGooeyContrast] = useState(18);

  // Metal State
  const [metalPreset, setMetalPreset] = useState<"silver" | "chromatic" | "gold">("chromatic");
  const [metalStrength, setMetalStrength] = useState(1);
  const [metalInnerShadow, setMetalInnerShadow] = useState(true);
  const metalButtonRef = useRef<HTMLButtonElement>(null);

  // Hook for metal cursor bend
  useMetalBend(metalButtonRef);

  return (
    <div className="w-screen min-h-screen bg-[#000000] text-white flex flex-col font-sans select-none overflow-x-hidden selection:bg-[#222222]">
      {/* 1. TOP HARDWARE BAR */}
      <header className="h-12 border-b border-[#222222] bg-[#0A0A0A] flex items-center justify-between px-4 z-30 shrink-0 select-none">
        <div className="flex items-center gap-3">
          <span className="font-brand font-black text-xl text-white tracking-[0px]">
            Crux
          </span>
          <div className="h-3.5 w-[1px] bg-[#222222]" />
          <div className="flex items-center gap-2 font-mono text-[11px]">
            <span className="w-1.5 h-1.5 bg-white animate-hard-blink" />
            <span className="font-bold uppercase tracking-wider text-white">Component Effects</span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3 font-mono text-[10px]">
          <span className="text-[#666666] hidden sm:inline">
            Thinking Orb · Border Beam · Liquid Gooey · Metal FX
          </span>
          {onLaunchIde && (
            <button
              onClick={() => {
                triggerHaptic("click");
                onLaunchIde();
              }}
              className="px-2.5 py-1 border border-[#222222] bg-transparent text-[#888888] hover:text-white hover:border-white transition-none uppercase flex items-center gap-1"
            >
              <span>Open Code Editor</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          )}
        </div>
      </header>

      {/* 2. MAIN 2x2 HARDWARE BRUTALIST MATRIX */}
      <main className="flex-1 p-4 md:p-6 grid grid-cols-1 md:grid-cols-2 gap-4 bg-[#000000] max-w-7xl mx-auto w-full">
        {/* 01 // THINKING_ORB */}
        <section className="border border-[#222222] bg-[#0A0A0A] p-4 flex flex-col gap-3 rounded-none">
          <div className="flex items-center justify-between border-b border-[#222222] pb-2 font-mono text-xs">
            <span className="font-bold text-white uppercase tracking-wider">01 // THINKING_ORB</span>
            <span className="text-[10px] text-[#888888]">npm i thinking-orbs</span>
          </div>

          {/* Orb Stage Canvas */}
          <div className="h-48 bg-[#000000] border border-[#222222] flex flex-col items-center justify-center relative p-3">
            <ThinkingOrb
              state={orbState}
              size={orbSize}
              speed={orbSpeed}
              theme="dark"
              paused={orbPaused}
            />
            <div className="absolute bottom-2 font-mono text-[9px] text-[#666666] uppercase tracking-widest">
              STATE: [{orbState.toUpperCase()}] · SIZE: {orbSize}PX
            </div>
          </div>

          {/* Controls */}
          <div className="space-y-2 font-mono text-[10px]">
            <div>
              <label className="text-[#888888] uppercase block mb-1">SELECT ANIMATION STATE:</label>
              <div className="grid grid-cols-3 gap-1">
                {ORB_STATES.map((st) => (
                  <button
                    key={st}
                    onClick={() => {
                      playMechanicalClick("mid");
                      triggerHaptic("tap");
                      setOrbState(st);
                    }}
                    className={`px-1.5 py-1 text-center border uppercase transition-none ${
                      orbState === st
                        ? "bg-white text-black border-white font-bold"
                        : "bg-transparent text-[#888888] border-[#222222] hover:text-white"
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-1.5">
                <span className="text-[#888888]">SIZE:</span>
                {[64, 20].map((sz) => (
                  <button
                    key={sz}
                    onClick={() => setOrbSize(sz as 64 | 20)}
                    className={`px-2 py-0.5 border text-[9px] uppercase transition-none ${
                      orbSize === sz
                        ? "bg-white text-black border-white"
                        : "bg-transparent text-[#888888] border-[#222222]"
                    }`}
                  >
                    {sz}px
                  </button>
                ))}
              </div>

              <button
                onClick={() => setOrbPaused(!orbPaused)}
                className="px-2 py-0.5 border border-[#222222] text-[#888888] hover:text-white uppercase flex items-center gap-1 transition-none text-[9px]"
              >
                {orbPaused ? <Play className="w-2.5 h-2.5" /> : <Pause className="w-2.5 h-2.5" />}
                <span>{orbPaused ? "RESUME" : "FREEZE"}</span>
              </button>
            </div>
          </div>
        </section>

        {/* 02 // BORDER_BEAM */}
        <section className="border border-[#222222] bg-[#0A0A0A] p-4 flex flex-col gap-3 rounded-none">
          <div className="flex items-center justify-between border-b border-[#222222] pb-2 font-mono text-xs">
            <span className="font-bold text-white uppercase tracking-wider">02 // BORDER_BEAM</span>
            <span className="text-[10px] text-[#888888]">npm i border-beam</span>
          </div>

          {/* Beam Wrapped Stage */}
          <div className="h-48 bg-[#000000] border border-[#222222] flex items-center justify-center p-3 relative overflow-hidden">
            <div className="relative w-full max-w-[300px]">
              <BorderBeam
                size={beamSize}
                colorVariant={beamColor}
                strength={beamStrength}
                active={beamActive}
                theme="dark"
              >
                <div className="p-4 bg-[#0E0E0E] border border-[#222222] font-mono text-xs text-center space-y-1">
                  <div className="font-bold text-white uppercase tracking-wider text-[11px]">
                    Border Beam Active
                  </div>
                  <p className="text-[9px] text-[#888888]">
                    Animated glowing border effect
                  </p>
                </div>
              </BorderBeam>
            </div>
          </div>

          {/* Controls */}
          <div className="space-y-2 font-mono text-[10px]">
            <div>
              <label className="text-[#888888] uppercase block mb-1">COLOR VARIANT:</label>
              <div className="grid grid-cols-4 gap-1">
                {(["mono", "colorful", "ocean", "sunset"] as const).map((clr) => (
                  <button
                    key={clr}
                    onClick={() => {
                      playMechanicalClick("mid");
                      setBeamColor(clr);
                    }}
                    className={`px-1.5 py-1 text-center border uppercase transition-none ${
                      beamColor === clr
                        ? "bg-white text-black border-white font-bold"
                        : "bg-transparent text-[#888888] border-[#222222] hover:text-white"
                    }`}
                  >
                    {clr}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-1.5">
                <span className="text-[#888888]">SIZE:</span>
                {(["md", "sm", "line"] as const).map((sz) => (
                  <button
                    key={sz}
                    onClick={() => setBeamSize(sz)}
                    className={`px-1.5 py-0.5 border text-[9px] uppercase transition-none ${
                      beamSize === sz
                        ? "bg-white text-black border-white"
                        : "bg-transparent text-[#888888] border-[#222222]"
                    }`}
                  >
                    {sz}
                  </button>
                ))}
              </div>

              <button
                onClick={() => setBeamActive(!beamActive)}
                className={`px-2 py-0.5 border text-[9px] uppercase transition-none ${
                  beamActive ? "bg-white text-black border-white font-bold" : "border-[#222222] text-[#888888]"
                }`}
              >
                {beamActive ? "ACTIVE" : "PAUSED"}
              </button>
            </div>
          </div>
        </section>

        {/* 03 // LIQUID_GOOEY */}
        <section className="border border-[#222222] bg-[#0A0A0A] p-4 flex flex-col gap-3 rounded-none">
          <div className="flex items-center justify-between border-b border-[#222222] pb-2 font-mono text-xs">
            <span className="font-bold text-white uppercase tracking-wider">03 // LIQUID_GOOEY</span>
            <span className="text-[10px] text-[#888888]">npm i liquid-gooey</span>
          </div>

          {/* Gooey Stage */}
          <div className="h-48 bg-[#000000] border border-[#222222] flex items-center justify-center p-3 relative overflow-hidden">
            <div className="flex flex-col items-center">
              <Liquid blur={gooeyBlur} contrast={gooeyContrast} fill="#FFFFFF">
                <div className="relative flex items-center justify-center h-20 w-48">
                  {/* Primary anchor item */}
                  <Liquid.Item x={0} y={0} transition="bouncy">
                    <button
                      onClick={() => {
                        playMechanicalClick("mid");
                        triggerHaptic("tap");
                        setGooeyOpen(!gooeyOpen);
                      }}
                      className="w-10 h-10 bg-white text-black font-mono font-bold text-xs flex items-center justify-center cursor-pointer shadow-none rounded-none"
                    >
                      {gooeyOpen ? "✕" : "✚"}
                    </button>
                  </Liquid.Item>

                  {/* Satellite item 1 */}
                  <Liquid.Item x={gooeyOpen ? -52 : 0} y={gooeyOpen ? -15 : 0} transition="bouncy">
                    <div className="w-8 h-8 bg-white text-black text-[9px] font-mono font-bold flex items-center justify-center cursor-pointer rounded-none">
                      A1
                    </div>
                  </Liquid.Item>

                  {/* Satellite item 2 */}
                  <Liquid.Item x={gooeyOpen ? 52 : 0} y={gooeyOpen ? -15 : 0} transition="bouncy">
                    <div className="w-8 h-8 bg-white text-black text-[9px] font-mono font-bold flex items-center justify-center cursor-pointer rounded-none">
                      A2
                    </div>
                  </Liquid.Item>
                </div>
              </Liquid>
              <span className="font-mono text-[9px] text-[#666666] uppercase mt-2">
                CLICK CENTER TO {gooeyOpen ? "MERGE" : "SEPARATE"} LIQUID NODES
              </span>
            </div>
          </div>

          {/* Controls */}
          <div className="flex items-center justify-between font-mono text-[10px]">
            <span className="text-[#888888]">BLUR: {gooeyBlur}px · CONTRAST: {gooeyContrast}</span>
            <button
              onClick={() => setGooeyOpen(!gooeyOpen)}
              className="px-2.5 py-1 border border-white bg-white text-black font-bold uppercase transition-none text-[9px]"
            >
              TOGGLE LIQUID MELT
            </button>
          </div>
        </section>

        {/* 04 // METAL_FX */}
        <section className="border border-[#222222] bg-[#0A0A0A] p-4 flex flex-col gap-3 rounded-none">
          <div className="flex items-center justify-between border-b border-[#222222] pb-2 font-mono text-xs">
            <span className="font-bold text-white uppercase tracking-wider">04 // METAL_FX</span>
            <span className="text-[10px] text-[#888888]">npm i metal-fx</span>
          </div>

          {/* Metal Stage */}
          <div className="h-48 bg-[#000000] border border-[#222222] flex flex-col items-center justify-center p-3 relative overflow-hidden gap-3">
            <div className="flex items-center gap-3">
              <MetalText font="700 16px Arial, sans-serif" color="#FFFFFF">
                Crux
              </MetalText>
              <MetalBadge>PRO</MetalBadge>
            </div>

            <MetalFx
              preset={metalPreset}
              variant="button"
              strength={metalStrength}
              innerShadow={metalInnerShadow}
              theme="dark"
            >
              <button
                ref={metalButtonRef}
                className="px-5 py-2.5 bg-transparent border border-white/20 text-white font-mono text-xs uppercase tracking-wider cursor-pointer rounded-none transition-none"
              >
                Click Me ↵
              </button>
            </MetalFx>

            <span className="font-mono text-[9px] text-[#666666] uppercase">
              Liquid Metal Shader Effect
            </span>
          </div>

          {/* Controls */}
          <div className="space-y-2 font-mono text-[10px]">
            <div>
              <label className="text-[#888888] uppercase block mb-1">PRESET MODE:</label>
              <div className="grid grid-cols-3 gap-1">
                {(["silver", "chromatic", "gold"] as const).map((pr) => (
                  <button
                    key={pr}
                    onClick={() => {
                      playMechanicalClick("mid");
                      setMetalPreset(pr);
                    }}
                    className={`px-1.5 py-1 text-center border uppercase transition-none ${
                      metalPreset === pr
                        ? "bg-white text-black border-white font-bold"
                        : "bg-transparent text-[#888888] border-[#222222] hover:text-white"
                    }`}
                  >
                    {pr}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-2">
                <span className="text-[#888888]">STRENGTH:</span>
                <input
                  type="range"
                  min="0.2"
                  max="1"
                  step="0.1"
                  value={metalStrength}
                  onChange={(e) => setMetalStrength(parseFloat(e.target.value))}
                  className="w-24 accent-white"
                />
                <span>{metalStrength}</span>
              </div>

              <button
                onClick={() => setMetalInnerShadow(!metalInnerShadow)}
                className={`px-2 py-0.5 border text-[9px] uppercase transition-none ${
                  metalInnerShadow
                    ? "bg-white text-black border-white"
                    : "border-[#222222] text-[#888888]"
                }`}
              >
                RIM {metalInnerShadow ? "ON" : "OFF"}
              </button>
            </div>
          </div>
        </section>
      </main>

      {/* 3. FOOTER */}
      <footer className="h-8 px-4 bg-[#050505] border-t border-[#222222] flex items-center justify-between font-mono text-[9px] text-[#444444] shrink-0">
        <div>Component Effects Demo</div>
        <div className="flex items-center gap-3">
          <span>THINKING-ORBS</span>
          <span>·</span>
          <span>BORDER-BEAM</span>
          <span>·</span>
          <span>LIQUID-GOOEY</span>
          <span>·</span>
          <span>METAL-FX</span>
        </div>
      </footer>
    </div>
  );
}
