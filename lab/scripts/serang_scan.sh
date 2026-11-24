#!/bin/sh
# serang_scan.sh — jalankan di Penyerang-1. Satu sesi = banyak pemindaian
# dengan parameter acak: jenis scan, rentang port, kecepatan, sumber IP.
# REVISI 2026-11-24 (butir 11): bilangan acak dari pembangkit ber-SEED dan
# seed ditulis ke log. Distribusi parameter SAMA dengan sesi 1-4.
#   sh alias_ip.sh 192.168.20 11 30
#   SEED=20261124 nohup sh serang_scan.sh 1800 > /tmp/scan_sesi5.log 2>&1 &

TARGET=192.168.30.10
LAMA=${1:-1800}
SEED=${SEED:-$(date +%s)}
SELESAI=$(( $(date +%s) + LAMA ))
X=$(( SEED % 2147483646 + 1 ))   # keadaan generator, tidak boleh 0
r() {
  R=$(awk -v x="$X" -v a="$1" -v b="$2" \
      'BEGIN{x = (x * 48271) % 2147483647; print x, int(a + x / 2147483647 * (b - a + 1))}')
  X=${R% *}; R=${R#* }
}
# daftar K port unik acak dari 1-10000 (pengganti shuf -n), dipisah koma
daftar_port() {
  PORTLIST=$(awk -v x="$X" -v k="$1" 'BEGIN{c = 0
    while (c < k) { x = (x * 48271) % 2147483647; p = int(1 + x / 2147483647 * 10000)
      if (!(p in a)) { a[p] = 1; o = o (c ? "," : "") p; c++ } }
    print x, o}')
  X=${PORTLIST% *}; PORTLIST=${PORTLIST#* }
}

echo "$(date +%s) scan MULAI dur=${LAMA}s seed=$SEED src=192.168.20.11-30 target=${TARGET}"

while [ "$(date +%s)" -lt "$SELESAI" ]; do
  r 11 30; SRC="192.168.20.$R"
  r 1 5
  case $R in                              # jenis scan
    1|2) JENIS=-sS ;; 3) JENIS=-sT ;; 4) JENIS=-sF ;; 5) JENIS=-sA ;;
  esac
  r 1 4
  case $R in                              # cakupan port
    1) r 1 60000; awal=$R; r 20 1500; PORT="-p $awal-$((awal + R))" ;;
    2) r 10 1000; PORT="--top-ports $R" ;;
    3) r 100 3000; PORT="-p 1-$R" ;;
    4) r 5 40; daftar_port "$R"; PORT="-p $PORTLIST" ;;
  esac
  r 1 4
  case $R in                              # kecepatan
    1) r 3 5; LAJU="-T$R" ;;
    2) r 5 500; LAJU="--max-rate $R" ;;
    3) r 10 300; LAJU="--scan-delay ${R}ms" ;;
    4) LAJU="-T2" ;;
  esac
  r 30 180; BATAS=$R
  echo "$(date +%s) nmap $JENIS $PORT $LAJU -S $SRC timeout=$BATAS"
  timeout "$BATAS" nmap -Pn -n $JENIS $PORT $LAJU -S "$SRC" -e eth0 "$TARGET" >/dev/null 2>&1
  r 2 30; sleep "$R"
done

echo "$(date +%s) scan SELESAI seed=$SEED"
