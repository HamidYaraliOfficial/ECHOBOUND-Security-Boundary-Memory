/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  env: {
    NEXT_PUBLIC_ECHOBOUND_API_BASE: process.env.NEXT_PUBLIC_ECHOBOUND_API_BASE || "http://localhost:8088",
  },
};
module.exports = nextConfig;
