/** @type {import('next').NextConfig} */
const nextConfig = {
  distDir: process.env.VERCEL
    ? undefined
    : (process.env.NEXT_DIST_DIR || (process.env.NODE_ENV === "development" ? ".next-dev" : ".next")),
  reactStrictMode: false, // Prevents duplicate double-mount on WebRTC/Yjs provider in dev
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  output: process.env.TAURI_BUILD ? "export" : undefined,
  images: {
    unoptimized: true,
  },
  webpack: (config) => {
    // Enable WebAssembly if needed
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
      layers: true,
    };
    return config;
  },
};

export default nextConfig;
