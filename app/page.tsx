"use client";

import React, { Suspense, useState, useEffect } from "react";
import dynamic from "next/dynamic";
const CruxLandingPage = dynamic(() => import("@/components/crux/landing/CruxLandingPage"), {
  ssr: false,
  loading: () => <div className="w-full min-h-screen bg-[#000000]" />,
});

import AeyeLandingPage from "@/components/aeye/AeyeLandingPage";

const CruxEditorView = dynamic(() => import("@/components/crux/CruxEditorView"), {
  ssr: false,
  loading: () => <div className="w-full h-full bg-[#000000]" />,
});

function PageContent() {
  const [view, setView] = useState<"aeye" | "crux" | "editor">("aeye");

  useEffect(() => {
    if (typeof window !== "undefined") {
      const isTauri = Boolean((window as any).__TAURI_INTERNALS__ || (window as any).__TAURI__);
      const searchParams = new URLSearchParams(window.location.search);

      if (searchParams.get("crux") === "true") {
        setView("crux");
        return;
      }

      if (searchParams.get("app") === "true" || searchParams.get("editor") === "true") {
        setView("editor");
      }
    }
  }, []);

  if (view === "editor") {
    return (
      <div className="w-screen h-screen overflow-hidden bg-black">
        <CruxEditorView onBackToEffects={() => setView("aeye")} />
      </div>
    );
  }

  if (view === "crux") {
    return <CruxLandingPage onLaunchWebEditor={() => setView("editor")} />;
  }

  return <AeyeLandingPage />;
}

export default function Page() {
  return (
    <Suspense fallback={<div className="w-full min-h-screen bg-[#0a0a0a]" />}>
      <PageContent />
    </Suspense>
  );
}
