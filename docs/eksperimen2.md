# Eksperimen 2 — Randomisasi Trafik

*(Stub — isi detail saat eksperimen berjalan. Lihat Rencana_Eksperimen2.md & Panduan_Eksperimen2.md.)*

## Latar: kenapa Eksperimen 1 dapat 100%
Tiap kelas dibangkitkan dari satu perintah tetap, jadi fitur nyaris tanpa variasi
(zero-variance) dan model menghafal sidik jari ukuran paket tiap tool.

## Perubahan di Eksperimen 2
- Randomisasi parameter serangan (jenis scan/flood, port, laju, ukuran payload, timing).
- Multi-host via IP alias (banyak penyerang & klien) → `unique_src_ip_per_dst` tak lagi konstan.
- Trafik normal realistis berjalan bersamaan dengan serangan.
- Pelabelan per-window (karena kelas bercampur waktu) + split latih/uji per sesi.

## Hasil
*(tabel metrik, confusion matrix, feature importance — diisi)*
