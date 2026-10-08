/** @type {import('next').NextConfig} */
const apiUrl = process.env.API_URL || "http://localhost:8000";

const nextConfig = {
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
