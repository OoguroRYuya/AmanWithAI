# Eksperimen 1 — Baseline dan Analisis Akurasi 100%

Eksperimen pertama dilakukan untuk membangun *baseline*: mengumpulkan dataset
dari lab tersimulasi, melatih Random Forest dan XGBoost, lalu memeriksa apakah
kesepuluh fitur NetFlow cukup untuk membedakan tiga kelas serangan. Hasilnya
akurasi 100% — tetapi analisis menunjukkan angka itu **artefak realisme data**,
bukan keberhasilan model. Temuan inilah yang memotivasi Eksperimen 2.

## 1. Tujuan
- Memverifikasi pipeline ujung-ke-ujung: pembangkitan trafik → NetFlow → ekstraksi fitur → pelatihan.
- Mengukur performa awal Random Forest vs XGBoost pada tiga kelas: Normal, DDoS Flood, Port Scanning.

## 2. Lingkungan
- Simulator: GNS3 + Docker (Alpine), router **VyOS** rolling.
- Topologi: 1 Client (`192.168.10.10`), 1 Penyerang (`192.168.20.10`), 1 Target (`192.168.30.10`), 1 Collector (`192.168.100.10`).
- Telemetri: NetFlow (ipt_NETFLOW pada VyOS) → `nfcapd`/`nfdump` di Collector.
- Tool pembangkit trafik: `ping`/`wget` (Normal), `nmap` (Port Scanning), `hping3` (DDoS Flood).

## 3. Dataset v1
Dikumpulkan dalam 5 sesi, total **139.625 flow**:

| Kelas | Jumlah record |
|-------|---------------|
| Normal | 8.533 |
| Port Scanning | 67.861 |
| DDoS Flood | 63.231 |

Tiap kelas dibangkitkan dengan **satu perintah tetap**:
- Normal: `ping` + `wget` ke Target.
- Port Scanning: `nmap -sS -p 1-500 192.168.30.10`.
- DDoS Flood: `hping3 -S --flood -p 80 192.168.30.10`.

## 4. Metode
- **10 fitur** (Tabel 3.3): duration, packet_count, byte_count, dst_port_count,
  avg_packet_size, flow_rate, syn_flag_count, unique_src_ip_per_dst, protocol,
  inter_arrival_time.
- **Pelabelan per-file**: tiap CSV berisi satu kelas murni (`ekstraksi_fitur.py --label`).
- **Model**: Random Forest (100 pohon) dan XGBoost, split **70:30 stratified acak**, `random_state=42`.

## 5. Hasil
Kedua model mencapai **akurasi 100%** dengan confusion matrix tanpa kesalahan
(precision, recall, F1 = 1.000 untuk semua kelas).

Feature importance teratas:
- Random Forest: avg_packet_size 0.26, byte_count 0.24, dst_port_count 0.22
- XGBoost: avg_packet_size 0.44, dst_port_count 0.33, byte_count 0.23

## 6. Analisis — mengapa 100% adalah artefak

Akurasi sempurna di sini **bukan** tanda model yang baik, melainkan tanda data
yang terlalu mudah. Empat sebab:

1. **Sidik jari tiap tool.** Karena tiap kelas dibuat dari satu perintah identik,
   ukuran paket dan volume tiap kelas nyaris konstan. Model cukup menghafal
   "avg_packet_size sekian = nmap", bukan belajar pola perilaku serangan. Ini
   konsisten dengan dominasi `avg_packet_size` pada feature importance.
2. **Fitur zero-variance.** `unique_src_ip_per_dst` selalu bernilai 1 karena hanya
   ada satu penyerang — fitur ini tidak memberi informasi apa pun, dan secara
   teknis "DDoS" di sini sebenarnya hanya **DoS** (satu sumber).
3. **Tidak ada kasus batas.** Trafik normal dan serangan dikumpulkan di sesi
   terpisah, sehingga tidak pernah ada trafik normal bervolume tinggi yang
   menyerupai flood. Model tidak pernah dipaksa membedakan kasus yang ambigu.
4. **Keseragaman antar-flow.** Dalam satu kelas, hampir semua flow mirip, sehingga
   data latih dan data uji praktis berasal dari distribusi yang identik.

## 7. Keterbatasan teknis (dibahas di BAB IV)
- **packet_count diestimasi** dari byte_count (~84 byte/paket) karena exporter
  `ipt_NETFLOW` tidak mengisi field paket.
- Digunakan **NetFlow v5** karena v9 tidak terbaca oleh nfdump 1.7.6 pada lab ini.
- ARP spoofing tidak dijadikan kelas deteksi (Layer 2, tak terlihat NetFlow) —
  dicatat sebagai saran penelitian lanjutan.

## 8. Kesimpulan dan tindak lanjut
Pipeline terbukti berjalan, namun dataset v1 terlalu "bersih" untuk menguji
kemampuan model yang sebenarnya. **Eksperimen 2** memperbaiki realisme data:
mengacak parameter serangan, menambah banyak host (via IP alias) agar
`unique_src_ip_per_dst` bervariasi, dan menjalankan trafik normal bersamaan
dengan serangan. Lihat [eksperimen2.md](eksperimen2.md).
