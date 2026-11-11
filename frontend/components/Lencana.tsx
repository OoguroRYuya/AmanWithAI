import { LABEL_KELAS, LABEL_STATUS } from "@/lib/format";
import type { Kelas, StatusInsiden } from "@/lib/tipe";

// Kelas dikenali dari kotak warna seri yang sama dengan grafik; teksnya
// tetap tinta biasa, warna tidak pernah dipakai pada kata.
export function LencanaKelas({ kelas }: { kelas: Kelas }) {
  return (
    <span className="kelas">
      <span className={`kunci-seri seri-${kelas}`} aria-hidden />
      {LABEL_KELAS[kelas] ?? kelas}
    </span>
  );
}

// Status dibawa oleh kata; warna hanya penegas: amber = perlu atau sudah
// diputuskan manusia, biru = dilakukan instrumen (blokir otomatis).
export function LencanaStatus({ status }: { status: StatusInsiden }) {
  return <span className={`lencana status-${status}`}>{LABEL_STATUS[status] ?? status}</span>;
}
