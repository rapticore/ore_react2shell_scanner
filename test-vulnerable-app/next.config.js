/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable experimental features that expose RSC endpoints
  experimental: {
    // Server Actions configuration for Next.js 14
    serverActions: true,
  },

  // Expose RSC in various ways for testing
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-RSC-Enabled', value: 'true' },
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET, POST, PUT, DELETE, OPTIONS' },
          { key: 'Access-Control-Allow-Headers', value: 'RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Url, Content-Type' },
        ],
      },
    ];
  },

  // Rewrites to create multiple RSC endpoint paths for testing
  async rewrites() {
    return [
      {
        source: '/_rsc/:path*',
        destination: '/:path*',
      },
      {
        source: '/api/rsc/:path*',
        destination: '/:path*',
      },
      {
        source: '/flight/:path*',
        destination: '/:path*',
      },
      {
        source: '/__flight/:path*',
        destination: '/:path*',
      },
    ];
  },

  // SECURITY WARNING: This configuration is intentionally insecure for testing
  poweredByHeader: true,
  reactStrictMode: false,
};

module.exports = nextConfig;
