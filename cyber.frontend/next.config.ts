import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  // Produces .next/standalone, which the Dockerfile runs with `node server.js`.
  output: 'standalone',
  reactStrictMode: true,
  poweredByHeader: false,

  /* Build output directory, overridable.
     `next build` and `next dev` both write to `.next` by default, so verifying a production
     build while a dev server is running corrupts the dev server's own output and forces a
     restart. Setting NEXT_DIST_DIR lets a build land somewhere else and leave dev alone.
     Unset — which is every real build, including Docker — this is exactly the default. */
  distDir: process.env.NEXT_DIST_DIR || '.next',
}

export default nextConfig
