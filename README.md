# NDR Dashboard — Random Forest & XGBoost untuk Deteksi & Mitigasi Serangan Jaringan Kampus

Sistem Network Detection & Response (NDR) tersimulasi: telemetri NetFlow/IPFIX
diolah menjadi 10 fitur, diklasifikasikan dengan **Random Forest** dan
**XGBoost** ke tiga kelas (**Normal / DDoS Flood / Port Scanning**), ditampilkan
di dashboard, dan dimitigasi otomatis via Netmiko/SSH ke router VyOS.
Lab dibangun di **GNS3 + Docker**.

> Skripsi Teknik Informatika, Universitas Padjadjaran — Muhammad Hafizh Fenaldi (140810230006).

## Arsitektur singkat
```
Client ─┐
Attacker┼─[ Router VyOS ]── NetFlow ──> Collector (nfcapd)
Target ─┘                                     │
                                              v
                      ekstraksi_fitur → label → latih (RF/XGB) → model
                                              │
                               dashboard + mitigasi (Netmiko → VyOS)
```

## Struktur repo
| Folder | Isi |
|--------|-----|
| `Dockerfile` | image lab (semua tool + skrip); build dari root repo |
| `lab/` | skrip trafik GNS3 + panduan build image & setup eksperimen |
| `ml/` | pipeline ML: `ekstraksi_fitur.py`, `label_per_window.py`, `latih_model.py`, `mitigasi.py`, `saran_tindakan.py` |
| `backend/` | API FastAPI dashboard |
| `data/` | sampel kecil + cara regenerasi; dataset penuh via Releases (lihat `data/README.md`) |
| `results/` | metrik & confusion matrix tiap eksperimen |
| `docs/` | metodologi & temuan Eksperimen 1 dan 2 |

## Cara mereproduksi
1. **Bangun image lab** (dari root repo): `docker build -t ndr-lab:exp2 .`
2. **Jalankan lab di GNS3**: daftarkan image sebagai template, start node, lihat `docs/eksperimen2.md`.
3. **Kumpulkan data**: jalankan skrip trafik (normal + serangan bersamaan), ekspor flow via `nfdump`.
4. **Label & latih**:
   ```
   python ml/label_per_window.py flows_sesi1.csv -o data/dataset_sesi1.csv
   python ml/latih_model.py --gabung data/dataset_sesi*.csv -o data/dataset_exp2.csv
   python ml/latih_model.py data/dataset_exp2.csv --uji-sesi 4
   ```

## Hasil (ringkas)
| Eksperimen | Akurasi | Catatan |
|------------|---------|---------|
| Eksperimen 1 | 1.000 | **artefak data** — model menghafal sidik jari ukuran paket tiap tool, bukan perilaku |
| Eksperimen 2 | (In Progress) | trafik diacak + multi-host → fitur punya variasi, hasil realistis |

## Keterbatasan
- `packet_count` diestimasi dari `byte_count` karena exporter `ipt_NETFLOW` tidak mengisi field paket.
- NetFlow v5 dipakai (v9 tidak terbaca nfdump 1.7.6 di lab ini).
- ARP spoofing tidak dijadikan kelas deteksi (Layer 2, tak terlihat NetFlow) — jadi saran penelitian lanjutan.

## ⚠️ Penggunaan
Skrip pada `lab/scripts/` membangkitkan trafik serangan (port scan, flood) dan
**hanya ditujukan untuk lab tersimulasi yang terisolasi** (GNS3, jaringan privat
RFC1918) untuk keperluan penelitian pertahanan jaringan. Jangan dijalankan pada
jaringan produksi atau sistem yang bukan milikmu.

## Sitasi
Jika mengacu pada karya ini, sitasi skripsi terkait (lihat `docs/`).
