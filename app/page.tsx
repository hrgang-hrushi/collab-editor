"use client";

import React, { Suspense } from "react";
import dynamic from "next/dynamic";

const CruxEditorView = dynamic(() => import("@/components/crux/CruxEditorView"), {
  ssr: false,
  loading: () => <div className="w-full h-full bg-[#000000]" />,
});

export default function CruxPage() {
  return (
    <Suspense fallback={<div className="w-full h-full bg-[#000000]" />}>
      <CruxEditorView />
    </Suspense>
  );
}
