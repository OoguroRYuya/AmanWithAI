# Eksperimen 2 — Randomisasi Trafik dan Validasi Model

Eksperimen kedua dirancang untuk memperbaiki temuan Eksperimen 1, yaitu akurasi
100% yang terbukti merupakan **artefak realisme data**. Perbaikan difokuskan pada
sisi data: mengacak parameter serangan, menambah banyak host sumber melalui IP
alias, serta menjalankan trafik normal bersamaan dengan serangan agar fitur tidak
lagi *zero-variance*. Hasilnya, model tetap berkinerja tinggi (akurasi 99,77%)
namun kini dengan karakteristik yang **dapat dipertahankan secara ilmiah**:
model membuat kesalahan pada kasus yang memang ambigu, mengandalkan banyak fitur,
dan lolos pengujian per-sesi tanpa kebocoran data (*data leakage*).

## 1. Tujuan
- Menghilangkan fitur *zero-variance* dan sidik jari tool yang menyebabkan akurasi 100% pada Eksperimen 1.
- Menguji kemampuan generalisasi model Random Forest dan XGBoost pada data yang lebih realistis.
- Memvalidasi hasil dengan skema pengujian per-sesi (*hold-out*) agar bebas kebocoran data.

## 2. Lingkungan
Identik dengan Eksperimen 1 (agar perbandingan adil):
- Simulator: GNS3 2.2.61 + Docker (Alpine 3.20), router **VyOS** rolling.
- Topologi: 1 Client (`192.168.10.10`), 1 Penyerang (`192.168.20.10`), 1 Target (`192.168.30.10`), 1 Collector (`192.168.100.10`).
- Telemetri: NetFlow (ipt_NETFLOW pada VyOS) → `nfcapd`/`nfdump` di Collector (NetFlow v5, port 9995).
- Tool pembangkit trafik: `wget`/`curl` paralel (Normal), `nmap` (Port Scanning), `hping3` (DDoS Flood).

## 3. Perubahan utama terhadap Eksperimen 1
Keempat sebab artefak pada Eksperimen 1 ditangani secara langsung:

1. **Randomisasi parameter serangan.** Tiap kelas tidak lagi satu perintah tetap,
   melainkan banyak variasi acak:
   - DDoS Flood: jenis flood diacak (SYN, ACK, SYN-ACK, UDP, ICMP), port tujuan,
     laju paket (`-i u800..8000`), ukuran payload (0–1200 byte), dan jumlah paket per flow.
   - Port Scanning: tipe scan, rentang port, dan timing diacak.
2. **Multi-host via IP alias.** IP sumber penyerang disebar acak pada rentang
   `192.168.20.10`–`192.168.20.250`, sehingga `unique_src_ip_per_dst` tidak lagi
   konstan 1. Dengan ini serangan menjadi **DDoS yang sesungguhnya** (banyak sumber),
   bukan DoS satu sumber seperti Eksperimen 1. Trafik normal juga memakai banyak
   "pengguna" paralel.
3. **Trafik bercampur waktu.** Trafik normal berjalan **bersamaan** dengan serangan,
   sehingga muncul kasus batas (mis. trafik normal bervolume tinggi yang menyerupai flood).
4. **Variasi antar-flow.** Payload, laju, dan timing acak membuat flow dalam satu
   kelas tidak lagi seragam.

### Konsekuensi metodologis
- **Pelabelan per-window**, bukan per-file: karena kelas bercampur dalam satu
  rentang waktu, label ditentukan per flow berdasarkan jendela waktu aktivitas
  (`label_per_window.py`), bukan dari asumsi "satu file = satu kelas".
- **Pembersihan backscatter**: balasan SYN-ACK dari Target ke IP penyerang yang
  dipalsukan (tujuan `192.168.20.0/24`) dibuang **sebelum** pelabelan agar tidak
  salah dilabeli sebagai trafik normal.
- **packet_count kini asli** dibaca dari field `%pkt` NetFlow, tidak lagi diestimasi
  dari byte_count seperti Eksperimen 1.

## 4. Dataset v2
Dikumpulkan dalam **4 sesi** independen. Tiap sesi dilabeli terpisah lalu digabung,
total **313.032 flow** (setelah pembuangan backscatter):

| Sesi | Normal | Port Scanning | DDoS Flood | Total |
|------|-------:|--------------:|-----------:|------:|
| Sesi 1 | 69.665 | 30.304 | 8.788 | 108.757 |
| Sesi 2 | 46.588 | 16.198 | 5.944 | 68.730 |
| Sesi 3 | 50.710 | 16.842 | 6.610 | 74.162 |
| Sesi 4 | 45.148 | 9.826 | 6.409 | 61.383 |
| **Total** | **212.111** | **73.170** | **27.751** | **313.032** |

Rasio kelas 7,6 : 1. Ketimpangan ini ditangani oleh `class_weight="balanced"` pada
Random Forest, sehingga seluruh data tetap dipakai tanpa *downsampling*.

## 5. Metode
- **10 fitur** sama seperti Eksperimen 1: duration, packet_count, byte_count,
  dst_port_count, avg_packet_size, flow_rate, syn_flag_count,
  unique_src_ip_per_dst, protocol, inter_arrival_time.
- **Model**: Random Forest (`class_weight="balanced"`) dan XGBoost.
- **Skema pengujian — pemisahan per-sesi (*hold-out*)**: model dilatih pada
  **Sesi 1–3** (251.649 flow) dan diuji pada **Sesi 4** (61.383 flow) yang tidak
  pernah dilihat saat pelatihan. Skema ini lebih ketat daripada split acak karena
  mencegah kebocoran data: flow dari satu sesi tidak bisa bocor dari data latih ke data uji.

## 6. Hasil

### 6.1 Metrik
| Model | Accuracy | Precision (macro) | Recall (macro) | F1 (macro) |
|-------|---------:|------------------:|---------------:|-----------:|
| **Random Forest** | **0,9977** | **0,9950** | **0,9965** | **0,9957** |
| XGBoost | 0,9971 | 0,9940 | 0,9957 | 0,9948 |

Model terbaik berdasarkan F1-score: **Random Forest**.

### 6.2 Confusion Matrix (Random Forest, uji = Sesi 4)
Baris = aktual, kolom = prediksi.

| aktual \ prediksi | ddos_flood | normal | port_scanning |
|---|---:|---:|---:|
| **ddos_flood** | 6.355 | 54 | 0 |
| **normal** | 89 | 45.059 | 0 |
| **port_scanning** | 0 | 1 | 9.825 |

Rincian per kelas:

| Kelas | Precision | Recall | F1 | Support |
|-------|----------:|-------:|---:|--------:|
| ddos_flood | 0,99 | 0,99 | 0,99 | 6.409 |
| normal | 1,00 | 1,00 | 1,00 | 45.148 |
| port_scanning | 1,00 | 1,00 | 1,00 | 9.826 |

### 6.3 Feature importance
| Fitur | Random Forest | XGBoost |
|-------|-------------:|--------:|
| dst_port_count | 0,3545 | 0,3191 |
| duration | 0,1770 | 0,4391 |
| byte_count | 0,1480 | 0,0065 |
| packet_count | 0,1260 | 0,1707 |
| unique_src_ip_per_dst | 0,0661 | 0,0211 |
| inter_arrival_time | 0,0598 | 0,0014 |
| syn_flag_count | 0,0222 | 0,0132 |
| flow_rate | 0,0221 | 0,0025 |
| avg_packet_size | 0,0207 | 0,0009 |
| protocol | 0,0035 | 0,0256 |

## 7. Analisis — mengapa 99,77% kali ini sahih

Berbeda dengan Eksperimen 1, akurasi tinggi di sini mencerminkan pembelajaran yang
sebenarnya, bukan artefak. Tiga bukti utama:

1. **Model kini membuat kesalahan di tempat yang masuk akal.** Confusion matrix
   Eksperimen 1 diagonal sempurna (tanpa error); kini terdapat 143 kesalahan nyata
   yang **terkonsentrasi di batas ddos_flood ↔ normal** (54 ddos diprediksi normal,
   89 normal diprediksi ddos). Ini justru diharapkan: *burst* flood berlaju rendah
   secara fisik memang menyerupai trafik normal yang padat. Port Scanning tetap
   hampir sempurna (1 salah dari 9.826) karena `dst_port_count` merupakan pembeda
   **alami** aktivitas pemindaian port — ini sinyal yang sah, bukan sidik jari tool.
2. **Feature importance menyebar.** Pada Eksperimen 1 satu fitur
   (`avg_packet_size`) mendominasi karena menghafal sidik jari ukuran paket tiap tool.
   Kini keputusan dibagi ke banyak fitur perilaku (dst_port_count, duration,
   byte_count, packet_count). Yang terpenting, `unique_src_ip_per_dst` yang
   sebelumnya konstan 1 (tak berguna) kini menyumbang 6,6% pada Random Forest —
   bukti langsung bahwa perbaikan multi-host berhasil.
3. **Pengujian bebas kebocoran data.** Angka 99,77% diperoleh pada Sesi 4 yang
   **belum pernah dilihat** model saat pelatihan. Artinya model benar-benar
   melakukan generalisasi lintas-waktu, bukan menghafal distribusi data latih.

Nilai akurasi 99%+ wajar dalam literatur NIDS pada dataset terkontrol
(mis. CICIDS2017, NSL-KDD kerap melaporkan angka setara). Yang membedakan hasil
sahih dari artefak adalah ketiga sifat di atas — ketiganya kini terpenuhi.

## 8. Perbandingan Eksperimen 1 vs Eksperimen 2

| Aspek | Eksperimen 1 | Eksperimen 2 |
|-------|--------------|--------------|
| Pembangkitan tiap kelas | Satu perintah tetap | Parameter diacak (jenis, port, laju, payload, timing) |
| Sumber serangan | 1 IP (DoS) | Banyak IP alias (DDoS sesungguhnya) |
| Trafik normal vs serangan | Sesi terpisah | Bercampur dalam waktu |
| `unique_src_ip_per_dst` | Konstan 1 (zero-variance) | Bervariasi (kontribusi 6,6%) |
| packet_count | Diestimasi dari byte | Asli dari NetFlow (`%pkt`) |
| Pelabelan | Per-file (1 file = 1 kelas) | Per-window (per flow) |
| Skema uji | Split 70:30 acak | Hold-out per-sesi (bebas leakage) |
| Akurasi RF | 100% | 99,77% |
| Confusion matrix | Diagonal sempurna (0 error) | 143 error, terkonsentrasi di batas ddos↔normal |
| Feature importance | Dominasi `avg_packet_size` | Menyebar ke fitur perilaku |
| Interpretasi | **Artefak** data terlalu mudah | **Sahih** — model belajar pola nyata |

## 9. Keterbatasan
- Lab tetap terkontrol dengan 3 kelas yang relatif terpisah; akurasi tinggi
  sebagian disebabkan oleh karakteristik lab, bukan kompleksitas trafik dunia nyata.
- ARP spoofing tetap tidak dijadikan kelas deteksi (Layer 2, tak terlihat NetFlow) —
  dicatat sebagai saran penelitian lanjutan.
- Tetap menggunakan NetFlow v5 karena v9 tidak terbaca oleh nfdump 1.7.6 pada lab ini.

## 10. Kesimpulan
Perbaikan realisme data pada Eksperimen 2 berhasil menghilangkan artefak akurasi
100% Eksperimen 1. Model Random Forest mencapai akurasi 99,77% dan F1-score 0,9957
pada pengujian per-sesi yang bebas kebocoran data, dengan kesalahan yang
terkonsentrasi pada kasus ambigu (ddos ↔ normal) dan feature importance yang
menyebar ke fitur perilaku. Hasil ini menunjukkan sistem deteksi mampu membedakan
ketiga kelas berdasarkan pola perilaku trafik yang sebenarnya, dan dapat
dipertahankan sebagai hasil akhir penelitian.
