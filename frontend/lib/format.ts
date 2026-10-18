import type { Kelas, StatusInsiden } from "./tipe";

export const LABEL_KELAS: Record<Kelas, string> = {
  normal: "Normal",
  ddos_flood: "DDoS flood",
  port_scanning: "Port scan",
};

export const LABEL_STATUS: Record<StatusInsiden, string> = {
  blokir_otomatis: "Blokir otomatis",
  menunggu_persetujuan: "Menunggu persetujuan",
  disetujui: "Disetujui",
  ditolak: "Ditolak",
  dicatat: "Dicatat",
};

const angka = new Intl.NumberFormat("id-ID");

export const fAngka = (n: number | null | undefined) => (n == null ? "–" : angka.format(n));

export const fPersen = (n: number | null | undefined) =>
  n == null ? "–" : `${(n * 100).toLocaleString("id-ID", { maximumFractionDigits: 1 })}%`;

export const fDetik = (n: number | null | undefined) =>
  n == null ? "–" : `${n.toLocaleString("id-ID", { maximumFractionDigits: 3 })} dtk`;

// Stempel backend berupa ISO tanpa zona waktu (jam lokal backend); cukup
// diambil bagian jamnya tanpa konversi zona.
export const fJam = (iso: string | null | undefined, detik = false) =>
  iso ? iso.slice(11, detik ? 19 : 16) : "–";

export const fTanggalJam = (iso: string | null | undefined) =>
  iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)} ${iso.slice(11, 16)}` : "–";

export function fHitungMundur(detik: number) {
  if (detik <= 0) return "kedaluwarsa";
  const m = Math.floor(detik / 60);
  const s = detik % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

export const IPV4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export function urutIp(a: string, b: string) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
}
