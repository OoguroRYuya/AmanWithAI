# Pengujian Sistem — Black-Box & Unit Testing

Dokumen ini mendokumentasikan hasil pengujian sistem NDR dari dua sisi yang saling
melengkapi:

- **Black-box** (fungsional): menguji perilaku sistem dari luar — memberi masukan
  (trafik serangan) lalu memeriksa keluaran (deteksi, blokir di router), tanpa
  melihat kode. Dijalankan **live** di lab GNS3 dengan router VyOS nyata.
- **Unit (white-box)**: menguji tiap unit logika backend secara terisolasi dengan
  `pytest`, memastikan ekstraksi fitur, pipeline, gerbang keputusan, mitigasi, dan
  WebSocket berperilaku benar.

---

## 1. Pengujian Black-Box (Fungsional)

Enam skenario dijalankan pada sistem yang berjalan penuh (backend mode aktif
`DRY_RUN=false`, mitigasi nyata ke VyOS). Setiap hasil diverifikasi di router
dengan `show firewall group BLOKIR_NDR`.

| ID | Skenario | Masukan | Hasil Diharapkan | Hasil Aktual | Status |
|----|----------|---------|------------------|--------------|--------|
| SK-01 | Trafik normal | Ping/akses Client → Target | 0 insiden, 0 blokir | Hanya trafik normal, tidak ada blokir | ✅ Lulus |
| SK-02 | DDoS Flood | `hping3` flood ke `192.168.30.10` | Insiden `ddos_flood`; sumber penyerang diblokir otomatis | 7 insiden, confidence 72–86%; 215 IP `192.168.20.x` diblokir otomatis; klien tak tersentuh | ✅ Lulus |
| SK-03 | Port Scanning | `nmap` dari `192.168.20.11–30` | Insiden `port_scanning`, kunci = pemindai | 4 insiden, confidence 51–58% (band sedang) → masuk antrean persetujuan | ✅ Lulus |
| SK-04 | Campuran normal + flood | Trafik normal + `hping3` bersamaan | Kedua kelas naik; hanya penyerang diblokir | Normal + DDoS naik; 173 IP `192.168.20.x` diblokir; klien `192.168.10.x` aman | ✅ Lulus |
| SK-05 | Persetujuan mitigasi | Tombol Setujui / Tolak pada insiden antrean | Setujui → blokir di VyOS; Tolak → tidak | Setujui mendorong IP ke grup `BLOKIR_NDR`; Tolak tidak | ✅ Lulus |
| SK-06 | Cabut blokir | Tombol Cabut pada IP terblokir | IP hilang dari grup VyOS | IP terhapus dari `BLOKIR_NDR` | ✅ Lulus |

**Catatan SK-03.** Confidence Port Scanning jatuh di band sedang (0,50–0,70) karena
fitur pemindaian lebih ambigu dibanding flood yang bervolume ekstrem. Perilaku
"masuk antrean persetujuan" adalah **kerja gerbang keputusan 3-tingkat yang benar**
(≥0,70 blokir otomatis; 0,50–0,70 antrean; <0,50 dicatat), bukan kegagalan.

**Kesimpulan black-box.** Keenam skenario lulus. Sistem mendeteksi kedua jenis
serangan, hanya memblokir sumber serangan (klien kampus tetap aman berkat syarat
rasio serangan ≥ 0,80 dan *allowlist*), dan mitigasi end-to-end (dashboard →
backend → SSH → VyOS) terbukti pada router nyata.

---

## 2. Pengujian Unit (pytest)

Suite backend dijalankan pada branch `dev`: **51 pengujian lulus, 0 gagal.**

| Modul | Jml | Cakupan |
|-------|-----|---------|
| `test_ekstraksi.py` | 7 | Ekstraksi 10 fitur dari CSV NetFlow |
| `test_pipeline.py` | 9 | Jendela 60 detik, buang *backscatter*, pengelompokan insiden |
| `test_keputusan.py` | 14 | Gerbang keputusan 3-tingkat + *allowlist* |
| `test_mitigasi.py` | 7 | Blokir/cabut/kedaluwarsa + mode *dry-run* |
| `test_ws.py` | 6 | Siaran WebSocket |
| `test_api.py` | 8 | Endpoint ingest / status / setujui-tolak |
| **Total** | **51** | **Semua lulus** |

### 2.1 Ekstraksi fitur — `test_ekstraksi.py`
- `test_tanpa_sertakan_ip_identik_dengan_golden` — hasil 10 fitur cocok dengan data acuan.
- `test_sertakan_ip_menambah_kolom_tanpa_mengubah_fitur` — opsi sertakan IP hanya menambah kolom, nilai fitur tetap.
- `test_sertakan_ip_false_eksplisit_identik` — `sertakan_ip=False` identik dengan default.
- `test_sertakan_ip_urutan_baris_cocok_dengan_csv` — urutan baris hasil konsisten dengan CSV sumber.
- `test_label_tetap_kolom_terakhir[True]` / `[False]` — kolom label selalu di posisi terakhir.
- `test_estimasi_paksa_mengganti_packet_count` — mode estimasi paksa mengganti `packet_count`.

### 2.2 Pipeline per-jendela — `test_pipeline.py`
- `test_proses_csv_fixture` — satu CSV menghasilkan `HasilWindow` yang benar.
- `test_jendela_terpisah` — flow dipisah per jendela 60 detik.
- `test_potong_per_window_fitur_sama_dengan_file_utuh` — pemotongan per jendela menghasilkan fitur identik dengan file utuh.
- `test_potong_per_window_fixture_satu_jendela` — kasus satu jendela.
- `test_tandai_backscatter` — flow menuju subnet penyerang ditandai *backscatter*.
- `test_flow_normal_tidak_membentuk_insiden` — trafik normal tidak membentuk insiden.
- `test_ddos_dikelompokkan_per_korban` — insiden DDoS dikunci ke IP korban.
- `test_scan_dikelompokkan_per_sumber` — insiden pindai dikunci ke IP pemindai.
- `test_per_sumber_dan_confidence` — agregasi per sumber dan confidence benar.

### 2.3 Gerbang keputusan — `test_keputusan.py`
- `test_allowlist_tidak_pernah_diblokir` / `test_allowlist_tidak_masuk_kandidat_persetujuan` — anggota *allowlist* (gateway, collector) tidak pernah diblokir/diantrekan.
- `test_klien_kampus_tidak_pernah_diblokir` — klien normal aman.
- `test_klien_dengan_sedikit_salah_klasifikasi_tidak_diblokir` — salah klasifikasi kecil tidak memicu blokir (syarat rasio).
- `test_confidence_di_bawah_ambang_blokir_menunggu_persetujuan` — confidence < 0,70 masuk antrean.
- `test_confidence_sedang_bawah_menunggu_persetujuan` — batas bawah band sedang masuk antrean.
- `test_confidence_di_bawah_ambang_sedang_hanya_dicatat` — confidence < 0,50 hanya dicatat.
- `test_port_scan_confidence_sedang_diblokir_otomatis` — kasus scan confidence tinggi → blokir otomatis.
- `test_flood_tetap_diblokir_walau_rata_rata_insiden_rendah` — flood bervolume tinggi tetap diblokir.
- `test_min_flow_insiden_berlaku_untuk_insiden_utuh` — ambang minimum flow berlaku benar.
- `test_ip_blokir_digabung_antar_insiden` — IP blokir dari beberapa insiden digabung.
- `test_sumber_palsu_satu_flow_tetap_diblokir` — sumber palsu satu flow tetap ditangani.
- `test_sumber_ragu_dalam_insiden_yang_diblokir` — sumber ragu dalam insiden terblokir ditangani.
- `test_tanpa_sumber_lolos_rasio_hanya_dicatat` — tak ada sumber lolos rasio → hanya dicatat.

### 2.4 Mitigasi — `test_mitigasi.py`
- `test_blokir_banyak_satu_sesi` — banyak IP diblokir dalam satu sesi SSH.
- `test_blokir_banyak_kosong` — daftar kosong ditangani.
- `test_blokir_banyak_tidak_mengirim_ulang_ip_terblokir` — IP yang sudah terblokir tidak dikirim ulang.
- `test_blokir_banyak_semua_sudah_terblokir_tanpa_sesi` — tak membuka sesi bila semua sudah terblokir.
- `test_blokir_banyak_gagal_tidak_mencatat` — kegagalan tidak dicatat sebagai sukses.
- `test_cabut_banyak_dan_kedaluwarsa` — pencabutan manual dan **auto-expire** kedaluwarsa.
- `test_dry_run_tidak_membuka_koneksi` — mode *dry-run* tidak membuka koneksi SSH.

### 2.5 WebSocket — `test_ws.py`
- `test_snapshot_lalu_umpan_live` — klien baru menerima snapshot lalu umpan live.
- `test_snapshot_memuat_keadaan_terkini` — snapshot memuat keadaan terkini.
- `test_broadcast_buang_klien_mati_dan_tetap_kirim_ke_yang_hidup` — klien mati dibuang, klien hidup tetap menerima.
- `test_broadcast_tanpa_klien_tidak_galat` — siaran tanpa klien tidak galat.
- `test_klien_putus_dilepas` — klien terputus dilepas.
- `test_mitigasi_manual_disiarkan` — aksi mitigasi manual disiarkan ke dashboard.

### 2.6 API — `test_api.py`
- `test_status_dry_run` — endpoint status melaporkan mode `dry-run`.
- `test_ingest_menghasilkan_insiden_terkelompok` — ingest CSV menghasilkan insiden terkelompok.
- `test_ingest_kosong_ditolak` — CSV kosong ditolak (HTTP 400).
- `test_ingest_multipart` — ingest via `multipart/form-data`.
- `test_ingest_path_di_luar_folder_ditolak` — path di luar folder aman ditolak.
- `test_id_unik` — id insiden selalu unik (monoton).
- `test_setujui_dan_tolak` — endpoint setujui/tolak insiden antrean.
- `test_allowlist_tidak_diblokir` — permintaan blokir anggota *allowlist* ditolak.

### 2.7 Cara menjalankan
```bash
cd backend
python -m pytest -q          # ringkas: 51 passed
python -m pytest -v          # rinci per pengujian
```

---

## 3. Kesimpulan

| Jenis | Cakupan | Hasil |
|-------|---------|-------|
| Black-box (fungsional, live VyOS) | 6 skenario deteksi + mitigasi | 6/6 lulus & terverifikasi di router |
| Unit (white-box, pytest) | 51 pengujian lintas 6 modul | 51/51 lulus |

Pengujian black-box membuktikan sistem bekerja benar secara end-to-end pada router
nyata; pengujian unit memastikan tiap komponen logika backend benar dan menjaga
sistem dari regresi saat dikembangkan.

---
*Pengujian black-box dijalankan 23 Oktober 2026 di lab GNS3 + VyOS. Unit test pada branch `dev`.*
