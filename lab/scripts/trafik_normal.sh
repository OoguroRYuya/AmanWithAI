#!/bin/sh
# trafik_normal.sh — jalankan di Client-1, biarkan menyala SEPANJANG sesi
# (juga saat sesi serangan berlangsung).
#   apk add curl iputils openssh-client iperf3
#   sh alias_ip.sh 192.168.10 11 40
#   SEED=20261124 nohup sh trafik_normal.sh 1800 8 > /tmp/normal_sesi5.log 2>&1 &
# Arg 1: lama berjalan (detik, default 1800).
# Arg 2: jumlah pengguna paralel (default 8).
#
# Beberapa "pengguna" paralel (tiap pengguna satu alias IP) dengan jeda rapat,
# supaya trafik normal puluhan ribu flow per sesi.
# REVISI 2026-11-24 (butir 11): bilangan acak dari pembangkit ber-SEED. Tiap
# pengguna memakai aliran sendiri (seed + nomor pengguna). Setiap aksi ditulis
# ke log. Distribusi aksi dan jeda SAMA dengan sesi 1-4.

TARGET=192.168.30.10
LAMA=${1:-1800}
PENGGUNA=${2:-8}
SEED=${SEED:-$(date +%s)}
SELESAI=$(( $(date +%s) + LAMA ))

# r A B -> R acak bulat di [A, B]; keadaan generator di X (per pengguna)
r() {
  R=$(awk -v x="$X" -v a="$1" -v b="$2" \
      'BEGIN{x = (x * 48271) % 2147483647; print x, int(a + x / 2147483647 * (b - a + 1))}')
  X=${R% *}; R=${R#* }
}
# jeda acak berdistribusi eksponensial (rata-rata $1 detik) -> JEDA
jeda() {
  JEDA=$(awk -v x="$X" -v m="$1" \
      'BEGIN{x = (x * 48271) % 2147483647; printf "%d %.2f", x, -m * log(1 - x / 2147483647)}')
  X=${JEDA% *}; JEDA=${JEDA#* }
}

# satu pengguna = satu alias IP yang terus beraktivitas sepanjang sesi
satu_pengguna() {
  SRC="192.168.10.$1"
  X=$(( (SEED * 100 + $1) % 2147483646 + 1 ))   # aliran acak per pengguna
  while [ "$(date +%s)" -lt "$SELESAI" ]; do
    r 1 100; pilih=$R
    if   [ $pilih -le 40 ]; then          # 40%: buka satu halaman/file
      r 1 40; echo "$(date +%s) $SRC http file_$R"
      curl -s -o /dev/null --interface "$SRC" "http://$TARGET/file_$R.bin"
    elif [ $pilih -le 55 ]; then          # 15%: browser memuat banyak objek sekaligus
      r 5 25; n=$R; j=0; echo "$(date +%s) $SRC http_burst n=$n"
      while [ $j -lt $n ]; do
        r 1 40
        curl -s -o /dev/null --interface "$SRC" "http://$TARGET/file_$R.bin" &
        j=$((j + 1))
      done; wait
    elif [ $pilih -le 70 ]; then          # 15%: ping dengan jumlah, ukuran, interval acak
      r 1 20; c=$R; r 32 1400; s=$R; r 2 9; i=$R
      echo "$(date +%s) $SRC ping c=$c s=$s i=0.$i"
      ping -I "$SRC" -c "$c" -s "$s" -i "0.$i" "$TARGET" >/dev/null
    elif [ $pilih -le 80 ]; then          # 10%: unduhan besar sah
      r 2 10; t=$R; r 1 50; b=$R
      echo "$(date +%s) $SRC iperf3 t=$t b=${b}M"
      iperf3 -c "$TARGET" -B "$SRC" -t "$t" -b "${b}M" -R >/dev/null 2>&1
    elif [ $pilih -le 90 ]; then          # 10%: login SSH (handshake lalu putus)
      echo "$(date +%s) $SRC ssh"
      timeout 3 ssh -b "$SRC" -o StrictHostKeyChecking=no -o BatchMode=yes "user@$TARGET" true >/dev/null 2>&1
    elif [ $pilih -le 96 ]; then          # 6%: akses port yang tertutup
      r 8000 8100; echo "$(date +%s) $SRC http_tertutup port=$R"
      curl -s -m 2 -o /dev/null --interface "$SRC" "http://$TARGET:$R/"
    else                                  # 4%: DNS/UDP kecil ke target
      echo "$(date +%s) $SRC udp53"
      echo "q" | nc -u -w1 -s "$SRC" "$TARGET" 53 >/dev/null 2>&1
    fi
    jeda 0.5; sleep "$JEDA"
  done
}

echo "$(date +%s) normal MULAI dur=${LAMA}s seed=$SEED pengguna=$PENGGUNA"
u=0
while [ $u -lt $PENGGUNA ]; do
  satu_pengguna $((11 + u)) &
  u=$((u + 1))
done
wait
echo "$(date +%s) normal SELESAI seed=$SEED ($PENGGUNA pengguna paralel)"
