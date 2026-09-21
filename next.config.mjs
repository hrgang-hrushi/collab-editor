/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false, // Prevents duplicate double-mount on WebRTC/Yjs provider in dev
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
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
  async rewrites() {
    return [
      {
        source: "/downloads/:path*",
        destination: "/api/download",
      },
      {
        source: "/download",
        destination: "/api/download",
      },
    ];
  },
};

export default nextConfig;
