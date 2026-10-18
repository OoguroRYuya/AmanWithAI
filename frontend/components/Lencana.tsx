import { LABEL_KELAS, LABEL_STATUS } from "@/lib/format";
import type { Kelas, StatusInsiden } from "@/lib/tipe";

// Warna kelas = warna seri grafik; teks tetap memakai tinta biasa,
// identitas dibawa oleh titik berwarna di sampingnya.
export function LencanaKelas({ kelas }: { kelas: Kelas }) {
  return (
    <span className="lencana">
      <span className={`titik seri-${kelas}`} aria-hidden />
      {LABEL_KELAS[kelas] ?? kelas}
    </span>
  );
}

const IKON_STATUS: Record<StatusInsiden, string> = {
  blokir_otomatis: "⛔",
  menunggu_persetujuan: "⏳",
  disetujui: "✓",
  ditolak: "✕",
  dicatat: "•",
};

// Status selalu ikon + label, warna hanya penegas
export function LencanaStatus({ status }: { status: StatusInsiden }) {
  return (
    <span className={`lencana status-${status}`}>
      <span aria-hidden>{IKON_STATUS[status] ?? "•"}</span>
      {LABEL_STATUS[status] ?? status}
    </span>
  );
}
