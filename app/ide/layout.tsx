import type { Metadata } from "next";

export const metadata: Metadata = {
  title: { absolute: "Crux Browser IDE | Shared Code Editor" },
  description:
    "Open the Crux browser IDE to explore files on a spatial canvas, edit code with teammates, and use an integrated terminal.",
  alternates: {
    canonical: "https://codecrux.us/ide",
  },
  robots: { index: false, follow: true },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://codecrux.us/ide",
    siteName: "Crux IDE",
    title: "Crux Browser IDE | Shared Code Editor",
    description:
      "Open a shared coding workspace with a spatial code canvas, live editing, and an integrated terminal.",
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
    title: "Crux Browser IDE | Shared Code Editor",
    description:
      "Open a shared coding workspace with a spatial code canvas, live editing, and an integrated terminal.",
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
