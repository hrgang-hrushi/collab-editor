"use client";

import React, { useState, useRef, useEffect } from "react";
import { ThinkingOrb } from "thinking-orbs";
import { BorderBeam } from "border-beam";
import { Liquid } from "liquid-gooey";
import { MetalFx, MetalText, MetalBadge, useMetalBend } from "metal-fx";
import { X, Play, Pause, Sparkles, Layers, Sliders, ArrowUp, RefreshCw, Zap } from "lucide-react";
import { triggerHaptic } from "@/lib/haptics";
import { playMechanicalClick } from "@/lib/sound";

interface CruxLibrariesFxProps {
  isOpen: boolean;
  onClose: () => void;
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

export default function CruxLibrariesFx({ isOpen, onClose }: CruxLibrariesFxProps) {
  // Orb State
  const [orbState, setOrbState] = useState<OrbState>("searching");
  const [orbSize, setOrbSize] = useState<64 | 20>(64);
  const [orbSpeed, setOrbSpeed] = useState(1);
  const [orbPaused, setOrbPaused] = useState(false);

  // Beam State
  const [beamSize, setBeamSize] = useState<"md" | "sm" | "line" | "pulse-inner" | "pulse-outside">("md");
  const [beamColor, setBeamColor] = useState<"mono" | "colorful" | "ocean" | "sunset">("mono");
  const [beamStrength, setBeamStrength] = useState(0.85);
  const [beamActive, setBeamActive] = useState(true);

  // Gooey State
  const [gooeyOpen, setGooeyOpen] = useState(false);
  const [gooeyBlur, setGooeyBlur] = useState(6);
  const [gooeyContrast, setGooeyContrast] = useState(18);

  // Metal State
  const [metalPreset, setMetalPreset] = useState<"silver" | "chromatic" | "gold">("silver");
  const [metalStrength, setMetalStrength] = useState(1);
  const [metalInnerShadow, setMetalInnerShadow] = useState(true);
  const metalButtonRef = useRef<HTMLButtonElement>(null);

  // Hook for metal cursor bend
  useMetalBend(metalButtonRef);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-[#000000]/80 backdrop-blur-none flex items-center justify-center p-4 font-sans select-none">
      <div className="w-full max-w-4xl max-h-[90vh] bg-[#0A0A0A] border border-[#222222] flex flex-col rounded-none shadow-none overflow-hidden">
        {/* Header Strip */}
        <div className="h-10 px-4 bg-[#111111] border-b border-[#222222] flex items-center justify-between font-mono text-xs text-white">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-white animate-hard-blink" />
            <span className="font-bold uppercase tracking-wider">LIBRARIES.DEV // EFFECTS_ENGINE</span>
            <span className="text-[#444444]">|</span>
            <span className="text-[#888888] text-[10px]">ORB · BEAM · GOOEY · METAL</span>
          </div>
          <button
            onClick={() => {
              playMechanicalClick("low");
              onClose();
            }}
            className="text-[#666666] hover:text-white border border-[#222222] px-2 py-0.5 text-[10px] uppercase transition-none"
          >
            [ESC // CLOSE]
          </button>
        </div>

        {/* Content Body: 2x2 Matrix */}
        <div className="flex-1 p-4 overflow-y-auto grid grid-cols-1 md:grid-cols-2 gap-4 bg-[#000000]">
          {/* 1. THINKING ORBS */}
          <div className="border border-[#222222] bg-[#0A0A0A] p-4 flex flex-col gap-3 rounded-none">
            <div className="flex items-center justify-between border-b border-[#222222] pb-2 font-mono text-xs">
              <span className="font-bold text-white uppercase tracking-wider">01 // THINKING_ORB</span>
              <span className="text-[10px] text-[#888888]">npm i thinking-orbs</span>
            </div>

            {/* Orb Stage Canvas */}
            <div className="h-40 bg-[#000000] border border-[#222222] flex flex-col items-center justify-center relative p-2">
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
                <label className="text-[#888888] uppercase block mb-1">Select Animation State:</label>
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
          </div>

          {/* 2. BORDER BEAM */}
          <div className="border border-[#222222] bg-[#0A0A0A] p-4 flex flex-col gap-3 rounded-none">
            <div className="flex items-center justify-between border-b border-[#222222] pb-2 font-mono text-xs">
              <span className="font-bold text-white uppercase tracking-wider">02 // BORDER_BEAM</span>
              <span className="text-[10px] text-[#888888]">npm i border-beam</span>
            </div>

            {/* Beam Wrapped Stage */}
            <div className="h-40 bg-[#000000] border border-[#222222] flex items-center justify-center p-3 relative overflow-hidden">
              <div className="relative w-full max-w-[280px]">
                <BorderBeam
                  size={beamSize}
                  colorVariant={beamColor}
                  strength={beamStrength}
                  active={beamActive}
                  theme="dark"
                >
                  <div className="p-3 bg-[#0E0E0E] border border-[#222222] font-mono text-xs text-center space-y-1">
                    <div className="font-bold text-white uppercase tracking-wider text-[11px]">
                      [ENCLAVE_BEAM_ACTIVE]
                    </div>
                    <p className="text-[9px] text-[#888888]">
                      Animated border glow riding perimeter
                    </p>
                  </div>
                </BorderBeam>
              </div>
            </div>

            {/* Controls */}
            <div className="space-y-2 font-mono text-[10px]">
              <div>
                <label className="text-[#888888] uppercase block mb-1">Color Variant:</label>
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
                  className="px-2 py-0.5 border border-[#222222] text-[#888888] hover:text-white uppercase transition-none text-[9px]"
                >
                  {beamActive ? "ACTIVE" : "PAUSED"}
                </button>
              </div>
            </div>
          </div>

          {/* 3. LIQUID GOOEY */}
          <div className="border border-[#222222] bg-[#0A0A0A] p-4 flex flex-col gap-3 rounded-none">
            <div className="flex items-center justify-between border-b border-[#222222] pb-2 font-mono text-xs">
              <span className="font-bold text-white uppercase tracking-wider">03 // LIQUID_GOOEY</span>
              <span className="text-[10px] text-[#888888]">npm i liquid-gooey</span>
            </div>

            {/* Gooey Stage */}
            <div className="h-40 bg-[#000000] border border-[#222222] flex items-center justify-center p-3 relative overflow-hidden">
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
                className="px-2 py-1 border border-white bg-white text-black font-bold uppercase transition-none text-[9px]"
              >
                TOGGLE LIQUID MELT
              </button>
            </div>
          </div>

          {/* 4. METAL FX */}
          <div className="border border-[#222222] bg-[#0A0A0A] p-4 flex flex-col gap-3 rounded-none">
            <div className="flex items-center justify-between border-b border-[#222222] pb-2 font-mono text-xs">
              <span className="font-bold text-white uppercase tracking-wider">04 // METAL_FX</span>
              <span className="text-[10px] text-[#888888]">npm i metal-fx</span>
            </div>

            {/* Metal Stage */}
            <div className="h-40 bg-[#000000] border border-[#222222] flex flex-col items-center justify-center p-3 relative overflow-hidden gap-3">
              <div className="flex items-center gap-3">
                <MetalText font="700 16px Arial, sans-serif" color="#FFFFFF">
                  CRUX KERNEL
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
                  DISPATCH METAL CORE ↵
                </button>
              </MetalFx>

              <span className="font-mono text-[9px] text-[#666666] uppercase">
                WEBGL2 REAL-TIME LIQUID METAL SHADER
              </span>
            </div>

            {/* Controls */}
            <div className="space-y-2 font-mono text-[10px]">
              <div>
                <label className="text-[#888888] uppercase block mb-1">Preset Mode:</label>
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
          </div>
        </div>

        {/* Footer Stencil */}
        <div className="h-8 px-4 bg-[#050505] border-t border-[#222222] flex items-center justify-between font-mono text-[9px] text-[#444444]">
          <div>[LIBRARIES.DEV // HARDWARE_BRUTALISM_INTEGRATION_OK]</div>
          <div className="text-white">CRUX_OS v1.2</div>
        </div>
      </div>
    </div>
  );
}
