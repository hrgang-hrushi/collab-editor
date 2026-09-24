import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Crux — Bare-Metal Collaborative IDE",
  description:
    "Crux is the native collaborative IDE engineered for high-velocity engineering. Sub-15ms rendering latency, decentralized AST-CRDT real-time sync, and zero Chromium overhead.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="min-h-full" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700;800;900&family=Geist+Mono:wght@400;500;600;700&family=Fragment+Mono:ital@0;1&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-full bg-[#0a0a0a] text-white antialiased font-sans selection:bg-[#0055ff]/30 selection:text-white">
        {children}
      </body>
    </html>
  );
}
