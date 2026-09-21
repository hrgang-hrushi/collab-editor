"use client";

import React, { Suspense, useState, useEffect } from "react";
import dynamic from "next/dynamic";
import CruxLandingPage from "@/components/crux/landing/CruxLandingPage";

const CruxEditorView = dynamic(() => import("@/components/crux/CruxEditorView"), {
  ssr: false,
  loading: () => <div className="w-full h-full bg-[#000000]" />,
});

function CruxPageContent() {
  const [view, setView] = useState<"landing" | "editor">("landing");
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);
    if (typeof window !== "undefined") {
      // If running inside native Tauri desktop app, immediately open editor
      const isTauri = Boolean((window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__);
      const searchParams = new URLSearchParams(window.location.search);
      const isEditorRequested =
        searchParams.get("app") === "true" ||
        searchParams.get("editor") === "true" ||
        searchParams.has("session") ||
        searchParams.has("room");

      if (isTauri || isEditorRequested) {
        setView("editor");
      }
    }
  }, []);

  if (!isClient) {
    return <div className="w-full min-h-screen bg-[#09090b]" />;
  }

  if (view === "editor") {
    return (
      <div className="w-screen h-screen overflow-hidden bg-black">
        <CruxEditorView onBackToEffects={() => setView("landing")} />
      </div>
    );
  }

  return <CruxLandingPage onLaunchWebEditor={() => setView("editor")} />;
}

export default function CruxPage() {
  return (
    <Suspense fallback={<div className="w-full min-h-screen bg-[#09090b]" />}>
      <CruxPageContent />
    </Suspense>
  );
}

