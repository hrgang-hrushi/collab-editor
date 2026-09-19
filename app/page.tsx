"use client";

import React from "react";
import dynamic from "next/dynamic";

const CruxEditorView = dynamic(() => import("@/components/crux/CruxEditorView"), {
  ssr: false,
});

export default function CruxPage() {
  return <CruxEditorView />;
}

