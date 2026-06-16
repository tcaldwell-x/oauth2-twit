/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Pin the workspace root to this project so a lockfile in a parent
  // directory doesn't get inferred as the root during builds.
  turbopack: {
    root: __dirname,
  },
};

module.exports = nextConfig;
