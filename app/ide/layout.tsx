import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Crux Web IDE — Live Native Collaborative Code Editor",
  description:
    "Launch Crux IDE directly in your browser. Real-time AST-CRDT pair programming, native WebGPU rendering, multi-file code editing, and integrated AI coding agents.",
  alternates: {
    canonical: "https://codecrux.us/ide",
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://codecrux.us/ide",
    siteName: "Crux IDE",
    title: "Crux Web IDE — Live Collaborative Workstation",
    description:
      "Direct browser workstation powered by Rust & WebGPU. Real-time AST-CRDT collaborative editing with zero cloud latency.",
    images: [
      {
        url: "https://codecrux.us/og-image.png",
        width: 1200,
        height: 630,
        alt: "Crux IDE Online Collaborative Editor",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Crux Web IDE — Live Collaborative Workstation",
    description:
      "Direct browser workstation powered by Rust & WebGPU. Real-time AST-CRDT collaborative editing.",
    images: ["https://codecrux.us/og-image.png"],
  },
};

export default function IdeLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
