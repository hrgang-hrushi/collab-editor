import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Crux — Collaborative IDE & Spatial Code Studio",
  description: "Bare-metal collaborative coding IDE with real-time CRDT buffers, spatial multi-file architecture, and integrated terminal.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark h-full">
      <body className="h-full bg-[#000000] text-white antialiased overflow-hidden font-sans selection:bg-[#222222] selection:text-white">
        {children}
      </body>
    </html>
  );
}
