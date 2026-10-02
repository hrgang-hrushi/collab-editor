import React, { Suspense } from "react";
import type { Metadata } from "next";
import PageClient from "@/components/PageClient";

export const metadata: Metadata = {
  alternates: { canonical: "https://codecrux.us/" },
};

export default function Page() {
  return (
    <main className="min-h-screen bg-[#000000] text-white">
      <Suspense fallback={<div className="w-full min-h-screen bg-[#000000]" />}>
        <PageClient />
      </Suspense>
    </main>
  );
}
