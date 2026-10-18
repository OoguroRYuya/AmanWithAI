// Bentuk data mengikuti backend/main.py, backend/pipeline.py (Insiden),
// dan backend/keputusan.py (KeputusanInsiden, EvaluasiSumber).

export type Kelas = "normal" | "ddos_flood" | "port_scanning";

export const KELAS: Kelas[] = ["normal", "ddos_flood", "port_scanning"];

export type StatusInsiden =
  | "blokir_otomatis"
  | "menunggu_persetujuan"
  | "disetujui"
  | "ditolak"
  | "dicatat";

export interface StatusReplay {
  aktif: boolean;
  total_window: number;
  terkirim: number;
  selesai: boolean;
}

// GET /api/status dan snapshot.status. Pesan WS `status` hanya membawa
// model_dimuat, dry_run, ip_terblokir, sehingga kolom lain opsional.
export interface StatusSistem {
  model_dimuat: boolean;
  dry_run: boolean;
  ip_terblokir: number;
  kelas?: string[] | null;
  router?: string;
  ambang_tinggi?: number;
  ambang_sedang?: number;
  min_flow_insiden?: number;
  ambang_rasio_serangan?: number;
  ambang_conf_blokir?: number;
  allowlist?: string[];
  sumber_data?: string;
  estimasi_paket_paksa?: boolean;
  replay?: StatusReplay | null;
  antrean?: number;
  menunggu_persetujuan?: number;
  total_deteksi?: number;
}

export interface Trafik {
  window: string;
  per_kelas: Record<string, number>;
  byte_total: number;
  jumlah_backscatter: number;
  jumlah_insiden: number;
  jumlah_diabaikan: number;
  sumber_data: string;
  t_window_end: string | null;
  t_diterima: string | null;
  t_klasifikasi: string | null;
}

export interface EvaluasiSumber {
  ip: string;
  rasio_serangan: number;
  conf_rata: number;
  lolos: boolean;
  alasan: string;
}

export interface Saran {
  kelas: string;
  judul: string;
  tingkat: string;
  narasi: string;
  saran_mitigasi: string | null;
  mitigasi_otomatis: boolean;
  confidence: number;
  durasi_blokir?: number;
}

export interface Insiden {
  id: number;
  jenis: "insiden";
  waktu: string;
  window: string;
  kelas: Kelas;
  kunci: string;
  jumlah_flow: number;
  sumber: string[];
  tujuan: string[];
  confidence: number;
  packet_total: number;
  byte_total: number;
  dst_port_maks: number;
  jumlah_sumber: number;
  status: StatusInsiden;
  alasan: string;
  ip_blokir: string[];
  ip_kandidat: string[];
  evaluasi_sumber: EvaluasiSumber[];
  saran: Saran;
  dimitigasi: boolean;
  sumber_data: string;
  nama_file: string | null;
  t_window_end: string | null;
  t_diterima: string | null;
  t_klasifikasi: string | null;
  t_mitigasi: string | null;
  latensi_detik: { deteksi: number | null; mitigasi: number | null };
}

export interface Terblokir {
  ip: string;
  kedaluwarsa: string;
  sisa_detik: number;
}

export type PesanWS =
  | {
      tipe: "snapshot";
      status: StatusSistem;
      insiden: Insiden[];
      terblokir: Terblokir[];
      trafik: Trafik[];
    }
  | ({ tipe: "trafik" } & Trafik)
  | ({ tipe: "insiden" } & Insiden)
  | {
      tipe: "mitigasi";
      aksi: "blokir" | "cabut";
      ip: string[];
      oleh: "otomatis" | "manual";
      dry_run: boolean;
    }
  | { tipe: "status"; model_dimuat: boolean; dry_run: boolean; ip_terblokir: number }
  | { tipe: "ping"; waktu: string };

export type KoneksiWS = "menyambung" | "tersambung" | "terputus";
