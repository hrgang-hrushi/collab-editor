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
  title: "Crux Editor — Collaborative IDE & Spatial Code Studio",
  description: "Modern collaborative coding IDE with real-time CRDT buffers, spatial multi-file architecture, and integrated terminal.",
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
      <body className="h-full bg-[#1e1e1e] text-[#cccccc] antialiased overflow-hidden font-sans selection:bg-[#264f78] selection:text-white">
        {children}
      </body>
    </html>
  );
}
