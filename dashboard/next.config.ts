import type { NextConfig } from "next";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const csp = [
  "default-src 'self'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "object-src 'none'",
  `script-src 'self' 'unsafe-inline'${process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "connect-src 'self'",
].join("; ");

const config: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  transpilePackages: ["aegis-latent-sdk"],
  turbopack: {root: repositoryRoot},
  async headers() {
    return [{
      source: "/(.*)",
      headers: [
        {key: "Content-Security-Policy", value: csp},
        {key: "Cache-Control", value: "no-store"},
        {key: "Referrer-Policy", value: "no-referrer"},
        {key: "X-Content-Type-Options", value: "nosniff"},
        {key: "X-Frame-Options", value: "DENY"},
        {key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()"},
      ],
    }];
  },
};

export default config;
