# Membuat Docker Image Permanen untuk Lab (biar tidak reset tiap sesi)

Masalah: container GNS3 me-reset filesystem tiap VM di-restart, jadi skrip yang
dibuat di console hilang dan tool harus di-`apk add` lagi. Solusinya: bangun
**satu image** yang sudah berisi semua tool + skrip. Sekali build, dipakai
semua node, tidak perlu setup ulang.

## Langkah build (di dalam GNS3 VM, yang sudah punya Docker)

1. Salin folder `eksperimen2/` (berisi `Dockerfile` dan subfolder `skrip/`) ke
   GNS3 VM. Cara mudah: aktifkan SSH di GNS3 VM (menu biru GNS3 VM → opsi shell),
   lalu dari PC:
   ```
   scp -r "D:\punya Piji\Source Code\eksperimen2" gns3@<IP_GNS3_VM>:/tmp/
   ```
   (atau pakai WinSCP ke IP GNS3 VM, user `gns3`).

2. Di shell GNS3 VM, build image:
   ```
   cd /tmp/eksperimen2
   sudo docker build -t ndr-lab:exp2 .
   ```
   Tunggu sampai selesai (`Successfully tagged ndr-lab:exp2`).

## Daftarkan image ke GNS3

3. GNS3 GUI → **Edit → Preferences → Docker containers → New**.
4. Pilih **existing image** → pilih `ndr-lab:exp2`.
5. Beri nama template (mis. `NDR-Lab`), set **Adapters = 1**, Start command
   biarkan `/bin/sh`. Simpan.

## Pakai di topologi

6. Ganti 4 node lama (Client, Penyerang, Target, Collector) dengan node dari
   template `NDR-Lab` **atau** ubah template tiap node ke image ini.
7. Sekarang tiap node sudah punya semua tool + skrip di `/root/skrip/` dan bisa
   dipanggil langsung dari mana saja, mis. `setup_target.sh`, `trafik_normal.sh`.

## Yang masih perlu tiap sesi (jauh lebih ringkas)

Image membuat **tool & skrip permanen**. Dua hal ini tetap diset tiap sesi
karena sifat jaringan GNS3 — tapi ini singkat:

- **IP tiap node.** Bisa dibuat permanen juga: GNS3 node → klik kanan →
  **Edit config** / **Network configuration**, isi `/etc/network/interfaces`
  (contoh Target):
  ```
  auto eth0
  iface eth0 inet static
      address 192.168.30.10
      netmask 255.255.255.0
      gateway 192.168.30.1
  ```
  GNS3 menyimpan file ini dalam project, jadi IP ikut permanen. Ulangi untuk
  tiap node dengan IP masing-masing.
- **Kait iptables di VyOS**: `sudo iptables -I FORWARD -j NETFLOW` (ini di
  router, bukan container — memang harus tiap sesi).

Setelah image + network config permanen, alur tiap sesi tinggal:
1. Start semua node + kait iptables VyOS.
2. Target: `setup_target.sh`
3. Client: `alias_ip.sh 192.168.10 11 40` lalu `trafik_normal.sh 1800 &`
4. Penyerang: `alias_ip.sh 192.168.20 11 30` lalu `serang_scan.sh 1800 &` dan `serang_flood.sh 1800 &`
5. Collector: jalankan nfcapd, lalu ekspor.

## Kalau tidak mau build image

Dua alternatif lebih ringan (tanpa Docker build):
- **Persistent directory GNS3**: di template Docker node → tab Advanced →
  "Additional directories", tambah `/root`. Taruh skrip di `/root` sekali, nanti
  bertahan antar-restart. Tapi **tool** (nmap/hping3) tetap perlu di-`apk add`
  tiap sesi karena terpasang di `/usr`.
- **Satu paste besar per node**: gabung set-IP + tulis skrip + install tool jadi
  satu blok, tempel sekali di tiap console tiap sesi. Paling cepat kalau cuma
  mau segera jalan, tapi tetap diulang tiap sesi.
