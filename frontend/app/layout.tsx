import type { Metadata } from "next";
import { Atkinson_Hyperlegible_Mono, Host_Grotesk } from "next/font/google";

import "./globals.css";

// Di-self-host oleh next/font saat build (lolos CSP font-src 'self'):
// Host Grotesk untuk yang dibaca orang, Atkinson Hyperlegible Mono untuk
// yang diukur instrumen (IP, angka, waktu).
const sans = Host_Grotesk({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-host-grotesk",
  display: "swap",
});
const mono = Atkinson_Hyperlegible_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-atkinson-mono",
  display: "swap",
  // Next tidak punya metrik pengganti untuk font ini; tanpa metrik yang
  // dipublikasikan, fallback dibiarkan apa adanya
  adjustFontFallback: false,
});

export const metadata: Metadata = {
  title: "Dashboard NDR",
  description: "Deteksi dan mitigasi serangan jaringan kampus secara real-time",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="id" className={`${sans.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
