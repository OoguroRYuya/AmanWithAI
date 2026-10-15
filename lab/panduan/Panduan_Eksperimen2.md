# Panduan Menjalankan Eksperimen 2 di GNS3 (Langkah per Langkah)

Panduan ini melanjutkan setup GNS3 yang sudah kamu punya. **Topologi dan
konfigurasi VyOS TIDAK berubah** dari Eksperimen 1 — yang baru hanya: (a)
beberapa IP alias per container, dan (b) skrip trafik yang mengacak parameter.
Semua skrip ada di folder `eksperimen2/skrip/`.

## File setup GNS3 yang sudah ada (di folder `03_Catatan_dan_Panduan`)
- `panduan-setup-gns3.html` — panduan setup awal GNS3 (sekali saja).
- `Skrip_Startup_GNS3.md` — urutan start tiap sesi (VyOS → container → collector). **Ini yang dipakai.**
- `Topologi_dan_Konfigurasi_Router_GNS3.md` — ⚠️ isinya masih Cisco IOU (rencana lama). Routermu sekarang VyOS, jadi untuk router pakai yang di `Skrip_Startup_GNS3.md`.

Jadi kamu **tidak perlu** bikin topologi dari nol — cukup jalankan langkah di bawah tiap sesi.

---

## LANGKAH 0 — Nyalakan lab (sama seperti biasa)
1. Power On **GNS3 VM** di VMware, tunggu dapat IP.
2. Buka **GNS3**, pastikan Servers Summary hijau, buka project, **Start semua node**, tunggu VyOS boot penuh.
3. Di console **VyOS** (login `vyos`/`vyos`), pasang kait iptables (wajib tiap sesi):
   ```
   sudo iptables -I FORWARD -j NETFLOW
   show interfaces          # pastikan eth0-eth4 muncul dengan IP
   ```

## LANGKAH 1 — Salin skrip ke tiap node
Skrip ada di PC-mu (`eksperimen2/skrip/`). Masukkan ke container lewat salah satu cara:
- Cara cepat (copy-paste): buka console node, buat file dengan `cat > nama.sh` lalu tempel isinya, tutup dengan Ctrl-D.
- Atau taruh di folder yang sudah di-mount ke container kalau topologimu pakai volume.

Yang perlu dikirim:
- ke **Target-1**: `setup_target.sh`
- ke **Client-1**: `alias_ip.sh`, `trafik_normal.sh`
- ke **Penyerang-1**: `alias_ip.sh`, `serang_scan.sh`, `serang_flood.sh`

## LANGKAH 2 — Target-1 (192.168.30.10)
Siapkan layanan + file ukuran acak (ini yang bikin trafik normal tak lagi seragam):
```
ip addr add 192.168.30.10/24 dev eth0 2>/dev/null; ip link set eth0 up; ip route add default via 192.168.30.1 2>/dev/null; echo "nameserver 8.8.8.8" > /etc/resolv.conf
sh setup_target.sh
```
Harus muncul: `TARGET SIAP: HTTP:80, SSH:22, iperf3:5201, 40 file acak`.

## LANGKAH 3 — Client-1 (banyak IP klien)
```
ip addr add 192.168.10.10/24 dev eth0 2>/dev/null; ip link set eth0 up; ip route add default via 192.168.10.1 2>/dev/null; echo "nameserver 8.8.8.8" > /etc/resolv.conf
apk add curl iputils openssh-client iperf3
sh alias_ip.sh 192.168.10 11 40          # 30 klien: .11 - .40
```

## LANGKAH 4 — Penyerang-1 (banyak IP penyerang)
```
ip addr add 192.168.20.10/24 dev eth0 2>/dev/null; ip link set eth0 up; ip route add default via 192.168.20.1 2>/dev/null; echo "nameserver 8.8.8.8" > /etc/resolv.conf
apk update && apk add nmap && apk add hping3 --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing
sh alias_ip.sh 192.168.20 11 30          # 20 penyerang: .11 - .30
```

## LANGKAH 5 — Collector-1 (sama seperti biasa)
```
ip addr add 192.168.100.10/24 dev eth0 2>/dev/null; ip link set eth0 up; ip route add default via 192.168.100.1 2>/dev/null; echo "nameserver 8.8.8.8" > /etc/resolv.conf
apk update && apk add nfdump && mkdir -p /data/nfcapd && nfcapd -D -p 9995 -w /data/nfcapd
```

---

## LANGKAH 6 — Jalankan SATU SESI (ini inti Eksperimen 2)

**Kunci:** trafik normal dan serangan jalan BERSAMAAN, tiap sesi berdurasi
sama (mis. 1800 detik = 30 menit). Kumpulkan **4–6 sesi** di waktu berbeda
supaya split per-sesi di `latih_model.py` sehat.

1. Di **Client-1** — nyalakan trafik normal dulu, biarkan jalan sepanjang sesi:
   ```
   nohup sh trafik_normal.sh 1800 > /tmp/normal.log 2>&1 &
   ```
2. Di **Penyerang-1** — jalankan scan dan flood (boleh bersamaan):
   ```
   nohup sh serang_scan.sh  1800 > /tmp/scan.log  2>&1 &
   nohup sh serang_flood.sh 1800 > /tmp/flood.log 2>&1 &
   ```
3. Tunggu sampai durasi selesai (cek `tail -f /tmp/scan.log`).

## LANGKAH 7 — Ekspor & beri label (per sesi)
Di **Collector-1**, flush lalu ekspor:
```
kill $(pgrep nfcapd)                              # paksa tulis
nfdump -R /data/nfcapd -o "fmt:%ts,%td,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt" > /data/flows_sesi1.csv
```
> Pakai format kustom ini (bukan `-o csv`) supaya kolom TCP flags ikut terekspor.

Salin `flows_sesi1.csv` ke mesin ML, lalu label (karena normal & serangan bercampur, pakai skrip label baru):
```
python label_per_window.py flows_sesi1.csv -o dataset_sesi1.csv
```
Ulangi Langkah 6–7 untuk sesi 2, 3, 4 (ganti nama file jadi `_sesi2`, dst).

## LANGKAH 8 — Gabung & latih (split per-sesi)
```
python latih_model.py --gabung dataset_sesi1.csv dataset_sesi2.csv dataset_sesi3.csv dataset_sesi4.csv -o dataset_exp2.csv
python latih_model.py dataset_exp2.csv --uji-sesi 4
```
`--gabung` otomatis menandai tiap file sebagai satu sesi; `--uji-sesi 4` melatih di sesi 1–3 dan menguji di sesi 4 (tanpa kebocoran data).

---

## Cara membaca hasil
- Kalau akurasi **turun dari 1.000 ke ~0.90–0.98** dengan sedikit salah di batas Normal↔Flood → **berhasil**: model belajar perilaku, bukan menghafal tool.
- Cek feature importance: idealnya tidak lagi didominasi `avg_packet_size` saja; `dst_port_count`, `unique_src_ip_per_dst`, `flow_rate` ikut berperan.
- `unique_src_ip_per_dst` sekarang harus **bervariasi** (bukan konstan 1) — bukti DDoS terdistribusi.

## Kalau muncul masalah
- `apk add` gagal DNS → ganti nameserver ke `192.168.42.1` (gateway NAT).
- `nfcapd Address in use` → `killall nfcapd` → `rm` isi folder → start ulang.
- Skrip serangan error "cannot find -S source" → pastikan IP alias sudah terpasang (Langkah 4) dan pakai `-e eth0`.
