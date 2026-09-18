"use client";

import React, { useMemo } from "react";

export default function VoidCanvas({ children }: { children?: React.ReactNode }) {
  // Dense ASCII hardware matrix art representation of silicon dies & circuit traces
  const asciiMatrix = useMemo(() => {
    return `
+========================================================================================+
| [0x00] 01000011 01010010 01000101 01011000 :: CREX DOM BARE-METAL KERNEL ARCHITECTURE |
| [0x08] CPU.CORE.0: ACTIVE | MMU: VIRTUAL_FLUSH | IPC: 0.04ms | ENCLAVE: HARDWARE_LOCK |
+----------------------------------------------------------------------------------------+
  ::: ::::::::  :::::::::  :::::::::: :::    :::      :::     ::::::::::: :::    :::      
  :+: :+:    :+: :+:    :+: :+:        :+:    :+:    :+: :+:       :+:     :+:   :+:       
  +:+ +:+        +:+    +:+ +:+         +:+  +:+    +:+   +:+     +:+     +:+  +:+        
  +#+ +#+        +#++:++#:  +#++:++#     +#++:+    +#++:++#++:    +#+     +#++:++         
  +#+ +#+        +#+    +#+ +#+         +#+  +#+   +#+     +#+    +#+     +#+  +#+        
  #+# #+#    #+# #+#    #+# #+#        #+#    #+#  #+#     #+#    #+#     #+#   #+#       
  ###  ########  ###    ### ########## ###    ###  ###     ### ########### ###    ###      
+----------------------------------------------------------------------------------------+
| 01100011 01110010 01100101 01111000 00101101 01110110 01101111 01101001 01100100       |
| REGISTER_MAP: RAX=0x000000 RBX=0xFFFFFF RCX=0x111111 RDX=0x222222 RSI=0x444444         |
| INSTRUCTION_PIPELINE: STREAM_AST_FETCH -> CRDT_MERGE -> DOM_RENDER_RAW_HARDWARE         |
+========================================================================================+`;
  }, []);

  return (
    <div className="relative w-screen h-screen bg-[#000000] text-white overflow-hidden select-none flex flex-col font-sans">
      {/* Z-0: ASCII Hardware / Silicon Architecture Canvas */}
      <div className="absolute inset-0 pointer-events-none z-0 overflow-hidden flex items-center justify-center opacity-15">
        <pre className="font-mono text-[9px] leading-[10px] text-[#222222] whitespace-pre select-none text-center">
          {asciiMatrix}
          {asciiMatrix}
          {asciiMatrix}
        </pre>
      </div>

      {/* Z-10: The Crex Effect — High-Speed Spinny Motion Blur with Radial Void Mask */}
      <div className="absolute inset-0 pointer-events-none z-10 overflow-hidden flex items-center justify-center">
        <div className="w-[800px] h-[800px] crex-spinny-blur pointer-events-none opacity-30 select-none">
          <svg
            viewBox="0 0 400 400"
            className="w-full h-full stroke-[#444444]"
            fill="none"
            strokeWidth="0.75"
          >
            {/* Concentric silicon trace rings */}
            <circle cx="200" cy="200" r="180" strokeDasharray="4 6" />
            <circle cx="200" cy="200" r="140" strokeDasharray="8 4" />
            <circle cx="200" cy="200" r="100" strokeDasharray="2 8" />
            <circle cx="200" cy="200" r="60" strokeDasharray="12 6" />
            {/* Radial circuit tracks */}
            <line x1="20" y1="200" x2="380" y2="200" />
            <line x1="200" y1="20" x2="200" y2="380" />
            <line x1="72" y1="72" x2="328" y2="328" strokeDasharray="6 6" />
            <line x1="328" y1="72" x2="72" y2="328" strokeDasharray="6 6" />
          </svg>
        </div>
      </div>

      {/* 1px Center Reticle & Alignment Crosshair */}
      <div className="absolute inset-0 pointer-events-none z-10 flex items-center justify-center">
        <div className="absolute w-16 h-[1px] bg-[#222222]" />
        <div className="absolute h-16 w-[1px] bg-[#222222]" />
        <div className="w-8 h-8 border border-[#222222]" />
      </div>

      {/* Structural Corner Telemetry (No gaps, absolute boundaries) */}
      <div className="absolute top-2 left-2 pointer-events-none font-mono text-[10px] text-[#444444] z-20">
        [SYS.CORE // SILICON_BARE_METAL]
      </div>
      <div className="absolute top-2 right-2 pointer-events-none font-mono text-[10px] text-[#444444] z-20">
        [LATENCY: 0.04ms]
      </div>
      <div className="absolute bottom-2 left-2 pointer-events-none font-mono text-[10px] text-[#444444] z-20">
        [GRID: 1PX SOLID #222222]
      </div>
      <div className="absolute bottom-2 right-2 pointer-events-none font-mono text-[10px] text-[#444444] z-20">
        [ENCLAVE: HARDWARE_LOCK]
      </div>

      {/* Z-20 / Z-50 Slot */}
      {children}
    </div>
  );
}
