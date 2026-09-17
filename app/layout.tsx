import type { Metadata } from "next";
import { Hanken_Grotesk, Space_Grotesk } from "next/font/google";
import { GeistMono } from "geist/font/mono";
import "./globals.css";

const hankenGrotesk = Hanken_Grotesk({
  subsets: ["latin"],
  variable: "--font-hanken",
  display: "swap",
  weight: ["300", "400", "500", "600", "700", "800", "900"],
});

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space",
  display: "swap",
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "Crux Studio — Spatial Collaborative Architecture & Code Engine",
  description: "High-performance collaborative coding studio merging zero-latency local daemon memory with real-time CRDT buffers, spatial multi-file architecture, and inline AI co-pilots.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`dark h-full ${hankenGrotesk.variable} ${spaceGrotesk.variable} ${GeistMono.variable}`}
    >
      <body className="h-full bg-workbench-bg text-zinc-100 antialiased overflow-hidden font-sans selection:bg-brand-primary/30 selection:text-white">
        {children}
      </body>
    </html>
  );
}
