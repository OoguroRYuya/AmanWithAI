"""
Ekspor arsip riwayat backend (DIR_STATUS/riwayat.jsonl) ke CSV latensi.

Arsip ditulis backend setiap insiden final (blokir otomatis, menunggu,
disetujui, ditolak). Satu insiden bisa muncul lebih dari sekali; yang dipakai
baris terakhirnya (keadaan final). Nomor id mulai lagi dari 1 setiap backend
di-restart, jadi kunci insiden = (id, nama_file), bukan id saja.

Pakai (dari akar repo):
  python ml/ekspor_riwayat.py                         # semua insiden
  python ml/ekspor_riwayat.py --sejak 2026-11-15T13:00 --sampai 2026-11-15T14:00 \
      --keluar hasil/latensi_sk02.csv
  python ml/ekspor_riwayat.py --trafik --sejak ...    # ringkasan per jendela

Ringkasan min/rata-rata/maks latensi dicetak ke layar (bahan Tabel 4.9).
"""
import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

KOLOM_INSIDEN = ["id", "waktu", "nama_file", "kelas", "kunci", "jumlah_flow", "confidence",
                 "jumlah_sumber", "status", "dimitigasi", "deteksi_detik", "mitigasi_detik"]


def baca(berkas):
    for baris in Path(berkas).read_text(encoding="utf-8").splitlines():
        if baris.strip():
            yield json.loads(baris)


def dalam_rentang(waktu, sejak, sampai):
    w = (waktu or "")[:19]
    return (not sejak or w >= sejak) and (not sampai or w <= sampai)


def ringkas(nama, nilai):
    nilai = [v for v in nilai if v is not None]
    if not nilai:
        print(f"  {nama}: (tidak ada data)", file=sys.stderr)
        return
    print(f"  {nama}: n={len(nilai)} min={min(nilai):.1f} rata={statistics.mean(nilai):.1f} "
          f"maks={max(nilai):.1f} detik", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default="backend/.state", help="DIR_STATUS backend")
    ap.add_argument("--sejak", help="waktu awal ISO, mis. 2026-11-15T13:00")
    ap.add_argument("--sampai", help="waktu akhir ISO")
    ap.add_argument("--kelas", help="ddos_flood / port_scanning")
    ap.add_argument("--trafik", action="store_true", help="ekspor ringkasan per jendela")
    ap.add_argument("--keluar", help="berkas CSV (default: stdout)")
    a = ap.parse_args()

    if a.trafik:
        data = [t for t in baca(Path(a.dir) / "trafik.jsonl")
                if dalam_rentang(t.get("t_window_end"), a.sejak, a.sampai)]
        kelas = sorted({k for t in data for k in t.get("per_kelas", {})})
        kolom = ["window", "t_window_end", "jumlah_insiden", "jumlah_backscatter"] + kelas
        baris = [{**{k: t.get(k) for k in kolom[:4]}, **t.get("per_kelas", {})} for t in data]
    else:
        final = {}
        for e in baca(Path(a.dir) / "riwayat.jsonl"):
            final[(e["id"], e.get("nama_file"))] = e
        data = [e for e in final.values()
                if dalam_rentang(e.get("waktu"), a.sejak, a.sampai)
                and (not a.kelas or e.get("kelas") == a.kelas)]
        data.sort(key=lambda e: e.get("waktu") or "")
        kolom = KOLOM_INSIDEN
        baris = [{**{k: e.get(k) for k in kolom},
                  "deteksi_detik": e.get("latensi_detik", {}).get("deteksi"),
                  "mitigasi_detik": e.get("latensi_detik", {}).get("mitigasi")} for e in data]

    keluar = open(a.keluar, "w", newline="", encoding="utf-8") if a.keluar else sys.stdout
    w = csv.DictWriter(keluar, fieldnames=kolom, extrasaction="ignore")
    w.writeheader()
    w.writerows(baris)
    if a.keluar:
        keluar.close()

    print(f"\n{len(baris)} baris", file=sys.stderr)
    if not a.trafik:
        print("Latensi:", file=sys.stderr)
        ringkas("deteksi", [b["deteksi_detik"] for b in baris])
        ringkas("mitigasi (otomatis)", [b["mitigasi_detik"] for b in baris if b["status"] == "blokir_otomatis"])
        ringkas("mitigasi (disetujui, termasuk tunggu admin)",
                [b["mitigasi_detik"] for b in baris if b["status"] == "disetujui"])


if __name__ == "__main__":
    main()
