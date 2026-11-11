import type { NextConfig } from "next";

// Alamat backend yang sama dengan lib/api.ts; CSP hanya mengizinkan halaman
// terhubung ke sini (dan ke dirinya sendiri), jadi data tidak bisa dikirim
// ke tempat lain walau suatu saat ada celah XSS.
const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws";
const dev = process.env.NODE_ENV === "development";

const csp = [
  "default-src 'self'",
  // Next menyisipkan skrip bootstrap inline; mode dev butuh eval untuk Fast Refresh
  `script-src 'self' 'unsafe-inline'${dev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src 'self' ${API_URL} ${WS_URL}${dev ? " ws://localhost:*" : ""}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  // tombol Setujui/Blokir tidak boleh dibingkai situs lain (clickjacking)
  "frame-ancestors 'none'",
].join("; ");

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

export default nextConfig;
