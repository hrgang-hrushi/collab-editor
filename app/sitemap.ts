import type { MetadataRoute } from "next";

const siteUrl = "https://codecrux.us";

// Add lastModified only when a real content update timestamp is available.
const pages = [
  "/",
  "/about",
  "/code-editor",
  "/pair-programming",
  "/docs",
  "/compare",
  "/vs-cursor",
  "/vs-vscode",
  "/vs-zed",
] as const;

export default function sitemap(): MetadataRoute.Sitemap {
  return pages.map((path) => ({ url: `${siteUrl}${path}` }));
}
