"use client";

import React, { Suspense } from "react";
import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";

const CruxEditorView = dynamic(() => import("@/components/crux/CruxEditorView"), {
  ssr: false,
  loading: () => (
    <div className="w-screen h-screen bg-[#000000] flex flex-col items-center justify-center font-mono text-xs text-[#71717a] gap-3">
      <div className="w-4 h-4 border border-[#333333] border-t-white animate-spin" />
      <span>[INITIALIZING CRUX BARE-METAL KERNEL...]</span>
    </div>
  ),
});

export default function IdePage() {
  const router = useRouter();

  return (
    <main className="w-screen h-screen overflow-hidden bg-[#000000] select-none">
      <Suspense
        fallback={
          <div className="w-screen h-screen bg-[#000000] flex flex-col items-center justify-center font-mono text-xs text-[#71717a] gap-3">
            <div className="w-4 h-4 border border-[#333333] border-t-white animate-spin" />
            <span>[INITIALIZING CRUX BARE-METAL KERNEL...]</span>
          </div>
        }
      >
        <CruxEditorView onBackToEffects={() => router.push("/")} />
      </Suspense>
    </main>
  );
}
