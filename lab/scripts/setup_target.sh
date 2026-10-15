#!/bin/sh
# setup_target.sh — jalankan di Target-1 (192.168.30.10) tiap sesi.
# Menyiapkan beberapa layanan dan file berukuran acak supaya trafik normal
# tidak lagi berukuran seragam (sebelumnya hanya directory listing kecil).

apk add python3 iperf3 dropbear >/dev/null 2>&1

mkdir -p /srv/www && cd /srv/www || exit 1
# 40 file dengan ukuran acak 1 KB - 5 MB (skala log, jadi banyak file kecil)
i=1
while [ $i -le 40 ]; do
  kb=$(awk -v s=$i 'BEGIN{srand(s*7919); printf "%d", exp(rand()*log(5000))}')
  head -c $((kb * 1024)) /dev/urandom > "file_$i.bin"
  i=$((i + 1))
done
echo "<html><body>Portal Akademik</body></html>" > index.html

python3 -m http.server 80 >/dev/null 2>&1 &      # HTTP
iperf3 -s -D                                      # unduhan besar sah (port 5201)
dropbear -R -p 22 2>/dev/null                     # SSH (cukup handshake)
echo "TARGET SIAP: HTTP:80, SSH:22, iperf3:5201, $(ls file_*.bin | wc -l) file acak"
