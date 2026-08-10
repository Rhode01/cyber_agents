import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  // Produces .next/standalone, which the Dockerfile runs with `node server.js`.
  output: 'standalone',
  reactStrictMode: true,
  poweredByHeader: false,
}

export default nextConfig
