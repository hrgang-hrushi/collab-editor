import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Crux — Collaborative IDE & Spatial Code Studio",
  description: "Bare-metal collaborative coding IDE with real-time CRDT buffers, spatial multi-file architecture, and integrated terminal.",
  icons: {
    icon: "/crux-logo.svg",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark min-h-full" suppressHydrationWarning>
      <body className="min-h-full bg-[#09090b] text-white antialiased font-sans selection:bg-[#222222] selection:text-white">
        {children}
      </body>
    </html>
  );
}
