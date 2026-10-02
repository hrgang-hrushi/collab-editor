import type { Metadata } from "next";
import "./globals.css";

const siteUrl = "https://codecrux.us";
const title = "Crux — Collaborative IDE with a Spatial Code Canvas";
const description =
  "Edit code together in real time, explore files on a spatial canvas, and work from an integrated terminal. Try Crux in the browser or join the waitlist.";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: title,
    template: "%s | Crux",
  },
  description,
  applicationName: "Crux IDE",
  icons: {
    icon: [
      { url: "/icon.svg", type: "image/svg+xml" },
      { url: "/crux-icon.png", sizes: "512x512", type: "image/png" },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" }],
  },
  manifest: "/manifest.json",
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, "max-image-preview": "large" },
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: siteUrl,
    siteName: "Crux IDE",
    title,
    description,
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "Crux IDE" }],
  },
  twitter: {
    card: "summary_large_image",
    title,
    description,
    images: ["/og-image.png"],
  },
  verification: {
    google: [
      process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION || "",
      process.env.GOOGLE_SITE_VERIFICATION || "",
    ].filter(Boolean),
    yandex: process.env.NEXT_PUBLIC_YANDEX_VERIFICATION || "",
    other: {
      "msvalidate.01": process.env.NEXT_PUBLIC_BING_VERIFICATION || "8E75C4196DCED84BCB7110C9EB5E502B",
    },
  },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": `${siteUrl}/#organization`,
      name: "Crux",
      url: siteUrl,
      logo: `${siteUrl}/crux-icon.png`,
    },
    {
      "@type": "WebSite",
      "@id": `${siteUrl}/#website`,
      name: "Crux IDE",
      url: siteUrl,
      publisher: { "@id": `${siteUrl}/#organization` },
    },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="min-h-full" suppressHydrationWarning>
      <head>
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      </head>
      <body className="min-h-full bg-[#0a0a0a] text-white antialiased font-sans selection:bg-[#0055ff]/30 selection:text-white">
        {children}
      </body>
    </html>
  );
}
