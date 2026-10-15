#!/bin/sh
# serang_scan.sh — jalankan di Penyerang-1. Satu sesi = banyak pemindaian
# dengan parameter acak: jenis scan, rentang port, kecepatan, sumber IP.
#   sh alias_ip.sh 192.168.20 11 30
#   nohup sh serang_scan.sh 1800 > /tmp/scan.log 2>&1 &

TARGET=192.168.30.10
LAMA=${1:-1800}
SELESAI=$(( $(date +%s) + LAMA ))
rnd() { shuf -i "$1-$2" -n 1; }

while [ "$(date +%s)" -lt "$SELESAI" ]; do
  SRC="192.168.20.$(rnd 10 30)"
  case $(rnd 1 5) in                      # jenis scan
    1|2) JENIS=-sS ;; 3) JENIS=-sT ;; 4) JENIS=-sF ;; 5) JENIS=-sA ;;
  esac
  case $(rnd 1 4) in                      # cakupan port
    1) awal=$(rnd 1 60000); PORT="-p $awal-$((awal + $(rnd 20 1500)))" ;;
    2) PORT="--top-ports $(rnd 10 1000)" ;;
    3) PORT="-p 1-$(rnd 100 3000)" ;;
    4) PORT="-p $(shuf -i 1-10000 -n $(rnd 5 40) | tr '\n' ',' | sed 's/,$//')" ;;
  esac
  case $(rnd 1 4) in                      # kecepatan: dari pelan-diam-diam sampai agresif
    1) LAJU="-T$(rnd 3 5)" ;;
    2) LAJU="--max-rate $(rnd 5 500)" ;;
    3) LAJU="--scan-delay $(rnd 10 300)ms" ;;
    4) LAJU="-T2" ;;
  esac
  echo "$(date +%s) nmap $JENIS $PORT $LAJU -S $SRC"
  # batas waktu supaya scan yang sangat pelan tidak memakan seluruh sesi
  timeout "$(rnd 30 180)" nmap -Pn -n $JENIS $PORT $LAJU -S "$SRC" -e eth0 "$TARGET" >/dev/null 2>&1
  sleep "$(rnd 2 30)"
done
