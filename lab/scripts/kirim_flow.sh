#!/bin/sh
# kirim_flow.sh — jalankan di HOST VM GNS3 (bukan di dalam container Collector).
# Mengirim setiap file nfcapd yang SUDAH DITUTUP ke backend NDR (D1, push):
#   docker exec <collector> nfdump -r <file> -o fmt:... | curl POST /api/ingest
#
# Prasyarat di Collector: nfcapd -D -p 9995 -t 60 -w /data/nfcapd
#   (-t 60 -> satu file = satu jendela 60 detik, sama dengan jendela fitur)
#
# Pakai:
#   COLLECTOR=$(docker ps --format '{{.Names}}' | grep -i collector) \
#     nohup sh kirim_flow.sh > /tmp/kirim_flow.log 2>&1 &
#
# Variabel (opsional):
#   COLLECTOR   nama/ID container Collector (wajib bila tidak bisa ditebak)
#   DIR_NFCAPD  folder nfcapd di dalam container   (default /data/nfcapd)
#   BACKEND     URL endpoint ingest                (default http://192.168.172.1:8000/api/ingest)
#   JEDA        detik antar pemeriksaan            (default 10)
#   STATE       daftar file yang sudah terkirim    (default /tmp/kirim_flow.terkirim)
#   KIRIM_LAMA  1 = saat STATE belum ada, kirim juga file sesi lama (default 0)
#   TZ_NFDUMP   zona waktu untuk nfdump            (default WIB-7 = UTC+7)
#
# Format ekspor sengaja SAMA dengan data latih (tanpa -N), ditambah -q agar
# baris header dan ringkasan nfdump tidak ikut terkirim.
#
# CATATAN ZONA WAKTU: nfdump mencetak kolom %ts dalam zona waktu container.
# Image Collector (Alpine) tidak memasang tzdata, sehingga tanpa variabel TZ
# waktu dicetak sebagai UTC dan latensi di backend meleset +7 jam (lokal WIB).
# Variabel TZ POSIX 'WIB-7' berarti UTC+7, memaksa %ts tercetak waktu WIB.

COLLECTOR=${COLLECTOR:-$(docker ps --format '{{.Names}}' | grep -i collector | head -n 1)}
DIR_NFCAPD=${DIR_NFCAPD:-/data/nfcapd}
BACKEND=${BACKEND:-http://192.168.172.1:8000/api/ingest}
JEDA=${JEDA:-10}
STATE=${STATE:-/tmp/kirim_flow.terkirim}
TZ_NFDUMP=${TZ_NFDUMP:-WIB-7}
FORMAT='fmt:%ts,%td,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt'

if [ -z "$COLLECTOR" ]; then
  echo "COLLECTOR tidak ditemukan. Set COLLECTOR=<nama container>." >&2
  exit 1
fi

daftar_file() {
  docker exec "$COLLECTOR" find "$DIR_NFCAPD" -type f -name 'nfcapd.[0-9]*' 2>/dev/null | sort
}

# Jalankan pertama kali: file dari sesi sebelumnya dianggap sudah terkirim,
# supaya backend tidak dibanjiri data lama. KIRIM_LAMA=1 untuk mengirim semua.
if [ ! -f "$STATE" ]; then
  if [ "${KIRIM_LAMA:-0}" = 1 ]; then
    touch "$STATE"
  else
    daftar_file > "$STATE"
    echo "$(date '+%F %T') $(wc -l < "$STATE") file lama dilewati (KIRIM_LAMA=1 untuk mengirim)"
  fi
fi
echo "$(date '+%F %T') mulai: collector=$COLLECTOR dir=$DIR_NFCAPD tz=$TZ_NFDUMP -> $BACKEND"

while true; do
  # Hanya file yang sudah ditutup: nfcapd.YYYYMMDDhhmm, BUKAN nfcapd.current.*
  daftar_file | while read -r f; do
      grep -qxF "$f" "$STATE" && continue

      kode=$(docker exec -e TZ="$TZ_NFDUMP" "$COLLECTOR" nfdump -q -r "$f" -o "$FORMAT" \
        | curl -s -o /dev/null -w '%{http_code}' -X POST \
            -H 'Content-Type: text/csv' -H "X-Nama-File: $(basename "$f")" \
            --data-binary @- "$BACKEND")

      case "$kode" in
        202)
          echo "$f" >> "$STATE"
          echo "$(date '+%F %T') terkirim $(basename "$f")" ;;
        400)
          # 400 = CSV kosong (tidak ada flow di jendela ini); jangan dikirim ulang
          echo "$f" >> "$STATE"
          echo "$(date '+%F %T') kosong   $(basename "$f")" ;;
        *)
          # gagal (backend mati/jaringan): tidak dicatat, dicoba lagi berikutnya
          echo "$(date '+%F %T') GAGAL    $(basename "$f") (HTTP $kode)" >&2 ;;
      esac
    done
  sleep "$JEDA"
done
