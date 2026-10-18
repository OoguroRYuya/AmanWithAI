import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Dashboard NDR",
  description: "Deteksi dan mitigasi serangan jaringan kampus secara real-time",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="id">
      <body>{children}</body>
    </html>
  );
}
