#!/bin/sh
# alias_ip.sh — menambah banyak IP pada satu container supaya tampak seperti
# banyak host. Contoh:
#   Client-1    : sh alias_ip.sh 192.168.10 11 40   (30 klien: .11-.40)
#   Penyerang-1 : sh alias_ip.sh 192.168.20 11 30   (20 penyerang: .11-.30)
prefix=$1; awal=$2; akhir=$3
i=$awal
while [ $i -le $akhir ]; do
  ip addr add "$prefix.$i/24" dev eth0 2>/dev/null
  i=$((i + 1))
done
echo "Alias $prefix.$awal - $prefix.$akhir terpasang"
