#!/bin/sh
# trafik_normal.sh — jalankan di Client-1, biarkan menyala SEPANJANG sesi
# (juga saat sesi serangan berlangsung).
#   apk add curl iputils openssh-client iperf3
#   sh alias_ip.sh 192.168.10 11 40
#   nohup sh trafik_normal.sh 3600 10 > /tmp/normal.log 2>&1 &
# Arg 1: lama berjalan (detik, default 1800).
# Arg 2: jumlah pengguna paralel (default 8).
#
# CATATAN VOLUME (Eksperimen 2 revisi): versi lama satu loop berurutan dengan
# jeda rata-rata 2 dtk -> trafik normal cuma ~1.500 flow/sesi, kalah telak
# dari serangan. Versi ini menjalankan BEBERAPA "pengguna" paralel (tiap
# pengguna satu alias IP) dengan jeda lebih rapat, jadi normal jadi puluhan
# ribu flow/sesi -> cukup untuk diseimbangkan dengan kelas serangan.

TARGET=192.168.30.10
LAMA=${1:-1800}
PENGGUNA=${2:-8}
SELESAI=$(( $(date +%s) + LAMA ))

rnd() { shuf -i "$1-$2" -n 1; }
# jeda acak berdistribusi eksponensial (rata-rata $1 detik), meniru
# kedatangan pengguna yang tidak teratur
jeda() { awk -v m="$1" -v s="$(rnd 1 99999)" 'BEGIN{srand(s); printf "%.2f", -m*log(1-rand())}'; }

# satu pengguna = satu alias IP yang terus beraktivitas sepanjang sesi
satu_pengguna() {
  SRC="192.168.10.$1"
  while [ "$(date +%s)" -lt "$SELESAI" ]; do
    pilih=$(rnd 1 100)
    if   [ $pilih -le 40 ]; then          # 40%: buka satu halaman/file
      curl -s -o /dev/null --interface "$SRC" "http://$TARGET/file_$(rnd 1 40).bin"
    elif [ $pilih -le 55 ]; then          # 15%: browser memuat banyak objek sekaligus (mirip burst)
      n=$(rnd 5 25); j=0
      while [ $j -lt $n ]; do
        curl -s -o /dev/null --interface "$SRC" "http://$TARGET/file_$(rnd 1 40).bin" &
        j=$((j + 1))
      done; wait
    elif [ $pilih -le 70 ]; then          # 15%: ping dengan jumlah, ukuran, interval acak
      ping -I "$SRC" -c "$(rnd 1 20)" -s "$(rnd 32 1400)" -i "0.$(rnd 2 9)" "$TARGET" >/dev/null
    elif [ $pilih -le 80 ]; then          # 10%: unduhan besar sah (mirip flood dari sisi volume)
      iperf3 -c "$TARGET" -B "$SRC" -t "$(rnd 2 10)" -b "$(rnd 1 50)M" -R >/dev/null 2>&1
    elif [ $pilih -le 90 ]; then          # 10%: login SSH (handshake lalu putus)
      timeout 3 ssh -b "$SRC" -o StrictHostKeyChecking=no -o BatchMode=yes "user@$TARGET" true >/dev/null 2>&1
    elif [ $pilih -le 96 ]; then          # 6%: akses port yang tertutup (aplikasi salah konfigurasi)
      curl -s -m 2 -o /dev/null --interface "$SRC" "http://$TARGET:$(rnd 8000 8100)/"
    else                                  # 4%: DNS/UDP kecil ke target (tidak dijawab, tetap tercatat)
      echo "q" | nc -u -w1 -s "$SRC" "$TARGET" 53 >/dev/null 2>&1
    fi
    sleep "$(jeda 0.5)"                    # jeda lebih rapat (rata-rata 0.5 dtk) -> volume naik
  done
}

# sebar pengguna ke alias 192.168.10.11, .12, ... (sesuai alias_ip.sh), paralel
u=0
while [ $u -lt $PENGGUNA ]; do
  satu_pengguna $((11 + u)) &
  u=$((u + 1))
done
wait
echo "Trafik normal selesai ($PENGGUNA pengguna paralel)"
