"""
label_per_window.py — REVISI ANTI-KEBOCORAN (2026-11-10)
========================================================
Menjawab koreksi Pak Deni (butir 20, 31, 32, 33, 34, 35, 58 = "target
leakage"): label TIDAK BOLEH ditentukan dari fitur model. Versi lama memberi
label port_scanning bila `dst_port_count > 20`, padahal dst_port_count adalah
salah satu fitur -> model jadi "menghafal" aturan label (kebocoran).

Versi ini menentukan label dari IDENTITAS GENERATOR (siapa yang mengirim flow),
yang sepenuhnya lepas dari nilai fitur:

  - Sumber subnet Client 192.168.10.0/24           -> normal
  - Sumber rentang SCANNER  (mis. 192.168.20.11-30) -> port_scanning
  - Sumber rentang FLOODER  (mis. 192.168.20.31-250)-> ddos_flood
  - Tujuan ke subnet penyerang 192.168.20.0/24      -> DIBUANG (backscatter)
  - Sumber penyerang di luar rentang di atas        -> DIBUANG (ambigu)

Dua metode:

  --metode rentang  (DEFAULT, untuk DATA REKAM ULANG)
      Scanner dan flooder memakai rentang IP sumber yang DIPISAH tanpa tumpang
      tindih (lihat serang_scan.sh / serang_flood.sh revisi). Label murni dari
      rentang IP -> bebas kebocoran, tidak butuh log.

  --metode log  (untuk DATA LAMA sesi 1-4 yang rentangnya tumpang tindih)
      Butuh --scan-log (keluaran serang_scan.sh: baris 'EPOCH nmap ... -S <ip>').
      port_scanning = flow yang IP sumber + waktunya cocok dengan entri scan-log;
      ddos_flood    = sumber penyerang DI LUAR rentang scanner (pasti flood,
                      karena scanner tak pernah pakai IP itu);
      flow di rentang scanner yang TIDAK ada di log -> DIBUANG (ambigu, bisa
      jadi flood yang kebetulan memalsukan IP scanner). Konsekuensi: sebagian
      flow flood yang menyamar di rentang scanner ikut terbuang, tapi label
      yang tersisa bersih dan bisa dipertanggungjawabkan.

Pakai:
    # data rekam ulang (rentang dipisah):
    python label_per_window.py flows_sesi1.csv -o dataset_sesi1.csv

    # data lama (pakai log scan):
    python label_per_window.py flows_sesi1.csv -o dataset_sesi1.csv \
        --metode log --scan-log scan_sesi1.log

    # seimbangkan kelas (opsional):
    python label_per_window.py flows.csv -o dataset.csv --downsample
"""
import argparse
import ipaddress
import re

import pandas as pd

import ekstraksi_fitur as ef

# --- rentang generator (SESUAIKAN bila lab berbeda) ------------------------
CLIENT_PREFIX = "192.168.10."       # trafik normal
ATTACKER_PREFIX = "192.168.20."     # subnet penyerang
NOISE_DST_PREFIX = "192.168.20."    # tujuan ke subnet penyerang = backscatter
# Oktet terakhir untuk tiap generator serangan (INKLUSIF).
SCANNER_RANGE = (11, 30)            # serang_scan.sh : alias .11-.30
FLOODER_RANGE = (31, 250)           # serang_flood.sh REVISI : .31-.250 (dipisah)
# Perkiraan durasi satu nmap (detik) untuk metode log; nmap dibungkus
# `timeout rnd(30,180)` di serang_scan.sh, jadi 180 dipakai sebagai batas atas.
SCAN_MAX_DURASI = 180
SEED = 42


def _oktet_terakhir(ip_series):
    return ip_series.astype(str).str.rsplit(".", n=1).str[-1]


def _dalam_rentang(oktet, lo, hi):
    n = pd.to_numeric(oktet, errors="coerce")
    return n.between(lo, hi)


def _muat_scan_log(path):
    """Parse keluaran serang_scan.sh: 'EPOCH nmap ... -S <ip>' -> daftar (ip, t0, t1)."""
    entri = []
    pat_ip = re.compile(r"-S\s+(\d+\.\d+\.\d+\.\d+)")
    with open(path) as f:
        for baris in f:
            bagian = baris.split(None, 1)
            if not bagian or not bagian[0].isdigit():
                continue
            t0 = int(bagian[0])
            m = pat_ip.search(baris)
            if not m:
                continue
            entri.append((m.group(1), t0, t0 + SCAN_MAX_DURASI))
    return entri


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default="dataset_exp2.csv")
    ap.add_argument("--window", type=int, default=ef.WINDOW_SECONDS)
    ap.add_argument("--metode", choices=["rentang", "log"], default="rentang")
    ap.add_argument("--scan-log", help="wajib untuk --metode log")
    ap.add_argument("--downsample", nargs="?", type=int, const=-1, default=None)
    args = ap.parse_args()
    ef.set_window(args.window)

    if args.metode == "log" and not args.scan_log:
        ap.error("--metode log membutuhkan --scan-log")

    # ekstrak fitur TANPA label, bawa sa/da/ts untuk melabeli
    mentah = ef.baca_nfdump_csv(args.input)
    df = ef.normalisasi_kolom(mentah)
    df["ts_dt"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df[df["ts_dt"].notna()].reset_index(drop=True)
    df["ts_epoch"] = ((df["ts_dt"] - pd.Timestamp("1970-01-01"))
                      // pd.Timedelta(seconds=1)).astype("int64")

    fitur = ef.ekstrak(args.input)
    fitur["sa"] = df["sa"].values
    fitur["da"] = df["da"].values
    fitur["ts_epoch"] = df["ts_epoch"].values
    fitur["label"] = pd.NA          # NA = belum dilabeli / ambigu -> dibuang

    # 1. buang backscatter (tujuan ke subnet penyerang)
    dst = fitur["da"].astype(str)
    is_backscatter = dst.str.startswith(NOISE_DST_PREFIX)
    n_backscatter = int(is_backscatter.sum())
    fitur = fitur[~is_backscatter].reset_index(drop=True)

    src = fitur["sa"].astype(str)
    is_attacker = src.str.startswith(ATTACKER_PREFIX)
    oktet = _oktet_terakhir(fitur["sa"])

    # 2. normal = SEMUA sumber BUKAN penyerang (client .10.x, balasan server
    #    .30.x ke client, dll). Kebocoran yang dikoreksi Pak Deni hanya soal
    #    scan vs flood; kelas normal tetap "apa pun yang bukan dari penyerang"
    #    (setelah backscatter dibuang), sama seperti versi lama.
    fitur.loc[~is_attacker, "label"] = "normal"

    if args.metode == "rentang":
        in_scan = is_attacker & _dalam_rentang(oktet, *SCANNER_RANGE)
        in_flood = is_attacker & _dalam_rentang(oktet, *FLOODER_RANGE)
        fitur.loc[in_scan, "label"] = "port_scanning"
        fitur.loc[in_flood, "label"] = "ddos_flood"
    else:  # metode log
        # flood PASTI = sumber penyerang di luar rentang scanner
        in_flood = is_attacker & ~_dalam_rentang(oktet, *SCANNER_RANGE)
        fitur.loc[in_flood, "label"] = "ddos_flood"
        # scan = cocok dengan entri scan-log (ip + jendela waktu)
        entri = _muat_scan_log(args.scan_log)
        cocok = pd.Series(False, index=fitur.index)
        for ip, t0, t1 in entri:
            cocok |= (src == ip) & fitur["ts_epoch"].between(t0, t1)
        fitur.loc[is_attacker & cocok, "label"] = "port_scanning"
        # sisanya (penyerang di rentang scanner, tak ada di log) tetap NA -> dibuang

    n_ambigu = int(fitur["label"].isna().sum())
    out = fitur.dropna(subset=["label"])[ef.FEATURE_COLUMNS + ["label"]].reset_index(drop=True)

    print(f"Backscatter dibuang (tujuan {NOISE_DST_PREFIX}0/24): {n_backscatter:,} baris")
    print(f"Ambigu/di luar rentang dibuang: {n_ambigu:,} baris")
    print("\nSebelum penyeimbangan:")
    print(out["label"].value_counts().to_string())

    if args.downsample is not None:
        counts = out["label"].value_counts()
        n_min = int(counts.min())
        target = n_min if args.downsample == -1 else min(args.downsample, n_min)
        bagian = [g.sample(n=min(target, len(g)), random_state=SEED)
                  for _, g in out.groupby("label")]
        out = (pd.concat(bagian).sample(frac=1, random_state=SEED)
                 .reset_index(drop=True))
        print(f"\nSetelah penyeimbangan (target {target:,}/kelas):")
        print(out["label"].value_counts().to_string())

    out.to_csv(args.output, index=False)
    print(f"\nTersimpan: {args.output}  ({len(out):,} baris)")


if __name__ == "__main__":
    main()
