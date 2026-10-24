#!/bin/sh
# bringup_lab.sh — jalankan di HOST VM GNS3 setelah node GNS3 di-Start.
# Menyiapkan lab Eksperimen 2 tiap kali boot: set IP tiap container, pasang
# IP alias (multi-host), jalankan layanan Target, dan mulai nfcapd di Collector.
#
# Semua yang diatur di sini bersifat NON-PERSISTEN (reset tiap container
# dibuat ulang / VM reboot). Konfigurasi VyOS (interface, NAT, NetFlow, SSH)
# bersifat permanen dan TIDAK disentuh skrip ini.
#
# PENTING (VyOS, lakukan manual di konsol VyOS tiap boot — bukan di sini):
#   sudo iptables -I FORWARD -j NETFLOW
#   sudo sysctl -w net.netflow.protocol=5
#   lalu dari backend:  curl -X POST http://<vyos>:8000/api/setup-firewall  (sekali)
#
# CATATAN: skrip ini direkonstruksi dari catatan pengembangan. Kalau di VM
# kamu masih ada ~/bringup_lab.sh yang sudah teruji, PAKAI yang itu dan commit
# versi tersebut. Bandingkan dulu (diff) sebelum menimpa.

set -u

# Pola nama node di GNS3 (docker ps). Sesuaikan bila nama node berbeda.
CLI=$(docker ps --format '{{.Names}}' | grep -i client     | head -n 1)
PEN=$(docker ps --format '{{.Names}}' | grep -i penyerang  | head -n 1)
TGT=$(docker ps --format '{{.Names}}' | grep -i target     | head -n 1)
COL=$(docker ps --format '{{.Names}}' | grep -i collector  | head -n 1)

IFACE=${IFACE:-eth0}
DNS=${DNS:-8.8.8.8}

cek() { [ -n "$1" ] || { echo "GAGAL: container '$2' tidak ditemukan (sudah Start node di GNS3?)" >&2; exit 1; }; }
cek "$CLI" Client; cek "$PEN" Penyerang; cek "$TGT" Target; cek "$COL" Collector
echo "Container: client=$CLI penyerang=$PEN target=$TGT collector=$COL"

# set_ip <container> <ip/prefix> <gateway>
set_ip() {
  c=$1; ipp=$2; gw=$3
  docker exec "$c" ip addr flush dev "$IFACE" 2>/dev/null
  docker exec "$c" ip addr add "$ipp" dev "$IFACE"
  docker exec "$c" ip link set "$IFACE" up
  docker exec "$c" ip route replace default via "$gw" 2>/dev/null
  docker exec "$c" sh -c "echo nameserver $DNS > /etc/resolv.conf" 2>/dev/null
  echo "  $c -> $ipp (gw $gw)"
}

echo "== Set IP dasar =="
set_ip "$CLI" 192.168.10.10/24 192.168.10.1
set_ip "$PEN" 192.168.20.10/24 192.168.20.1
set_ip "$TGT" 192.168.30.10/24 192.168.30.1
set_ip "$COL" 192.168.100.10/24 192.168.100.1

# alias_range <container> <prefix> <start> <end> : pasang prefix.start..end/24
alias_range() {
  c=$1; pre=$2; a=$3; b=$4
  i=$a
  while [ "$i" -le "$b" ]; do
    docker exec "$c" ip addr add "$pre.$i/24" dev "$IFACE" 2>/dev/null
    i=$((i + 1))
  done
}

echo "== Pasang IP alias (multi-host) =="
alias_range "$CLI" 192.168.10 11 40   # Client: .10 + .11..40  -> total 31 inet
alias_range "$PEN" 192.168.20 11 30   # Penyerang: .10 + .11..30 -> total 21 inet

# Verifikasi jumlah alias (langkah ini pernah gagal diam-diam; harus dicek).
n_pen=$(docker exec "$PEN" sh -c "ip addr show $IFACE | grep -c 'inet '")
n_cli=$(docker exec "$CLI" sh -c "ip addr show $IFACE | grep -c 'inet '")
echo "  Penyerang inet=$n_pen (harus 21), Client inet=$n_cli (harus 31)"
[ "$n_pen" = 21 ] || echo "  PERINGATAN: alias Penyerang tidak 21 — ulangi alias_range Penyerang." >&2
[ "$n_cli" = 31 ] || echo "  PERINGATAN: alias Client tidak 31 — ulangi alias_range Client." >&2

echo "== Siapkan layanan Target (http/iperf3/ssh + file dummy) =="
# setup_target.sh ada di dalam image (/root/skrip) atau lab/scripts; sesuaikan path.
docker exec "$TGT" sh -c '[ -x /root/skrip/setup_target.sh ] && /root/skrip/setup_target.sh' \
  || echo "  (lewati: setup_target.sh tidak ada di /root/skrip — jalankan manual bila perlu)"

echo "== Mulai nfcapd di Collector (window 60 detik) =="
docker exec "$COL" sh -c 'pkill nfcapd 2>/dev/null; mkdir -p /data/nfcapd; \
  nfcapd -D -p 9995 -t 60 -w /data/nfcapd'
echo "  nfcapd jalan (port 9995, -t 60, /data/nfcapd)"

# == Routing di HOST VM agar backend bisa SSH ke VyOS mgmt (opsional) ==
# Sesuaikan subnet mgmt VyOS (contoh 192.168.42.0/24) dengan jaringanmu.
# Baris ini dikomentari karena bergantung topologi VM-mu; aktifkan bila perlu.
# sudo sysctl -w net.ipv4.ip_forward=1
# sudo iptables -t nat -C POSTROUTING -s 192.168.42.0/24 -j MASQUERADE 2>/dev/null \
#   || sudo iptables -t nat -A POSTROUTING -s 192.168.42.0/24 -j MASQUERADE
# sudo iptables -C FORWARD -d 192.168.42.0/24 -j ACCEPT 2>/dev/null \
#   || sudo iptables -I FORWARD -d 192.168.42.0/24 -j ACCEPT

echo "== Selesai. Jangan lupa hook NetFlow di VyOS (lihat header skrip). =="
