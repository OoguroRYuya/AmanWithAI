# Rencana Eksperimen 2 — Membuat Trafik Lab Lebih Realistis

Tujuan: menghilangkan penyebab akurasi/presisi = 1.000 di Eksperimen 1. Saran
pembimbing benar — masalahnya ada di **data**, bukan di model. Dokumen ini
memetakan mengapa tiap fitur rusak, lalu menawarkan tiga tingkat perbaikan
dengan satu rekomendasi.

---

## 1. Mengapa Eksperimen 1 dapat 100%

Model tidak belajar *perilaku serangan*; model belajar **sidik jari tiap tool**.
Tiga penyebab, dari yang paling merusak:

1. **Satu perintah = satu nilai fitur.** Semua Port Scan dibuat dengan
   `nmap -sS -p 1-500` yang identik, semua Flood dengan `hping3 -S --flood -p 80`
   yang identik, semua Normal dengan `ping`/`wget` kecil. Jadi tiap kelas jadi
   satu titik yang nyaris tanpa sebaran (zero variance): `avg_packet_size`,
   `byte_count`, `dst_port_count` langsung memisah sempurna. Feature importance
   mengkonfirmasi ini (avg_packet_size 0.26/0.44).
2. **Satu penyerang.** `unique_src_ip_per_dst` selalu = 1 → fitur mati, dan
   "DDoS" sebenarnya hanya DoS.
3. **Trafik terpisah waktu.** Normal dan serangan dikumpulkan di sesi berbeda,
   jadi tidak ada kasus batas (burst normal yang mirip flood) yang memaksa model
   benar-benar belajar.

## 2. Fitur mana yang diperbaiki oleh randomisasi

| Fitur | Di Exp 1 | Setelah randomisasi |
|---|---|---|
| avg_packet_size | konstan per tool | payload hping3 acak (`-d`), ukuran file HTTP acak → menyebar, tumpang tindih antar kelas |
| byte_count / packet_count | konstan per tool | durasi, laju, jumlah paket diacak |
| dst_port_count | 500 (scan) / 1 (flood) persis | rentang & jumlah port scan diacak; flood kadang multi-port |
| unique_src_ip_per_dst | **selalu 1** | 20 IP penyerang + 30 IP klien → 1..20, DDoS jadi nyata |
| flow_rate / inter_arrival_time | 2 nilai | timing diacak (flood vs rate-limit; jeda eksponensial di normal) |
| syn_flag_count | SYN=scan/flood, kosong=normal | ditambah scan `-sT/-sF/-sA` dan flood `--udp/--icmp` → SYN bukan lagi penanda pasti |
| duration | pendek seragam | diacak lewat durasi & scan-delay |

Catatan jujur untuk sidang: `packet_count` tetap **estimasi** dari byte_count
(keterbatasan exporter, sudah dicatat di BAB IV). Randomisasi ukuran payload
membuat estimasi ini tidak lagi sempurna berkorelasi dengan kelas — itu
sebetulnya *bagus* untuk realisme, tapi sebutkan apa adanya.

## 3. Tiga pilihan

### Opsi A — Randomisasi parameter saja (paling ringan)
Tetap 1 penyerang, 1 klien, 1 target. Ganti perintah tetap dengan skrip yang
mengacak jenis/port/kecepatan/ukuran tiap serangan, dan normal dengan ukuran
file + timing acak.
- Memperbaiki: avg_packet_size, byte_count, dst_port_count, flow_rate, duration, syn_flag_count.
- **Tidak** memperbaiki: `unique_src_ip_per_dst` (tetap 1 → tetap zero variance, tetap "DoS").
- Usaha: ~1 sesi lab. Perubahan topologi: tidak ada.

### Opsi B — Randomisasi + banyak host via IP alias (REKOMENDASI)
Opsi A **plus** memberi banyak IP pada container penyerang dan klien yang sudah
ada (`ip addr add`, lihat `skrip/alias_ip.sh`) — 20 sumber serangan, 30 klien —
tanpa menambah node GNS3. Inilah yang memperbaiki `unique_src_ip_per_dst` dan
membuat DDoS benar-benar terdistribusi, dengan ongkos RAM nyaris nol.
- Memperbaiki: **semua 10 fitur**.
- Usaha: ~1 sesi lab, 2 baris perintah tambahan per container.
- Risiko: perlu sebut di BAB IV bahwa "banyak host" disimulasikan lewat IP alias
  pada satu container (lazim & sah untuk lab skala ini).

### Opsi C — Node terpisah sungguhan
Tambah beberapa container penyerang & klien betulan di GNS3.
- Hasil deteksi setara Opsi B, tapi RAM/CPU naik dan setup tiap sesi lebih lama
  di PC 64 GB. Manfaat ilmiah atas B: kecil.

## 4. Rekomendasi

**Opsi B.** Ia menutup satu-satunya fitur yang Opsi A tinggalkan
(`unique_src_ip_per_dst`), sekaligus menjawab pertanyaan sidang "kenapa disebut
DDoS kalau penyerangnya satu" — tanpa membebani lab seperti Opsi C. Hasil yang
diharapkan: akurasi turun dari 1.000 ke kisaran realistis (~0.90–0.98) dengan
sebagian error di batas Normal-vs-Flood — justru itu yang membuktikan model
belajar perilaku, bukan menghafal tool.

## 5. Yang sudah saya siapkan (folder `eksperimen2/skrip/`)

| File | Jalankan di | Fungsi |
|---|---|---|
| `setup_target.sh` | Target-1 | HTTP + SSH + iperf3 + 40 file ukuran acak |
| `alias_ip.sh` | Client-1 & Penyerang-1 | pasang banyak IP (Opsi B) |
| `trafik_normal.sh` | Client-1 | normal campuran (HTTP burst, ping, unduhan besar, SSH, port tertutup) dengan timing acak — biarkan menyala selama sesi serangan |
| `serang_scan.sh` | Penyerang-1 | Port Scan: jenis/port/kecepatan/sumber diacak |
| `serang_flood.sh` | Penyerang-1 | Flood: jenis/port/laju/payload/jumlah-sumber diacak |
| `label_per_window.py` | mesin ML | pelabelan Exp 2: label per flow dari IP sumber + perilaku (karena normal & serangan kini bercampur waktu) |

Semua skrip memakai tool yang sudah ada di lab (nmap, hping3, curl, ping, iperf3,
ssh); hanya iperf3/dropbear yang perlu `apk add` di Target. Pelabelan berubah
karena di Exp 2 trafik bercampur, jadi `--label` per-file tidak lagi cukup.

## 6. Satu perubahan kecil yang disarankan di `latih_model.py`
Saat ini split 70:30 acak per flow. Dengan satu sesi, flow dari serangan yang
sama bisa bocor ke train & test (membesarkan skor). Saran: split **per sesi**
(latih di sesi 1–3, uji di sesi 4) atau minimal `GroupShuffleSplit` berbasis
window. Ini membuat angka Exp 2 lebih jujur. Bisa saya terapkan kalau kamu mau —
saya biarkan kamu yang putuskan dulu.
