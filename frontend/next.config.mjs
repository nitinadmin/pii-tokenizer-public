/** @type {import('next').NextConfig} */
const apiUrl = process.env.API_URL || "http://localhost:8000";

const nextConfig = {
  // Self-contained server bundle for the Docker image.
  output: "standalone",
  // Gzip buffers proxied responses, which would stall the SSE pipeline stream.
  compress: false,
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${apiUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
