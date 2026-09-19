"use client";

import React, { useState } from "react";
import dynamic from "next/dynamic";

const CruxLibrariesDirectView = dynamic(
  () => import("@/components/crux/effects/CruxLibrariesDirectView"),
  { ssr: false }
);

const CruxEditorView = dynamic(() => import("@/components/crux/CruxEditorView"), {
  ssr: false,
});

export default function CruxPage() {
  const [activeView, setActiveView] = useState<"effects" | "ide">("effects");

  if (activeView === "ide") {
    return <CruxEditorView onBackToEffects={() => setActiveView("effects")} />;
  }

  return <CruxLibrariesDirectView onLaunchIde={() => setActiveView("ide")} />;
}
