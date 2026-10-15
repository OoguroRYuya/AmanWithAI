"""
label_per_window.py
===================
Pelabelan Eksperimen 2. Di Eksperimen 1 tiap file CSV berisi satu kelas murni,
jadi `--label` cukup. Di Eksperimen 2 trafik normal dan serangan berjalan
BERSAMAAN, maka label ditentukan per flow dari IP sumber + perilaku, bukan
per file.

Pakai:
    python label_per_window.py flows.csv -o dataset_exp2.csv
    python label_per_window.py flows.csv -o dataset_exp2.csv --downsample
    python label_per_window.py flows.csv -o dataset_exp2.csv --downsample 3000

Aturan (sesuaikan bila rentang IP berbeda):
    - tujuan 192.168.20.0/24 (subnet penyerang)  -> DIBUANG
        Tidak ada trafik sah menuju subnet penyerang. Baris ini adalah
        "backscatter": balasan SYN-ACK dari Target (src 192.168.30.x) ke
        alamat penyerang yang dipalsukan oleh hping3 flood. Di Eksperimen 2
        sebelumnya baris ini salah terlabel 'normal' dan membengkakkan
        kelas normal sampai jutaan. Dibuang sebelum pelabelan.
    - sumber 192.168.20.0/24  -> kandidat serangan
        * banyak port tujuan unik dalam jendela  -> port_scanning
        * selain itu (volume tinggi ke sedikit port) -> ddos_flood
    - sumber lain -> normal
Ambang dibuat eksplisit supaya bisa dipertanggungjawabkan saat sidang.

--downsample menyeimbangkan jumlah tiap kelas (flood cenderung mendominasi).
Tanpa angka: setiap kelas dipangkas ke ukuran kelas TERKECIL. Dengan angka N:
setiap kelas maksimal N baris (tetap seimbang; N dibatasi oleh kelas terkecil).
"""
import argparse
import pandas as pd
import ekstraksi_fitur as ef

ATTACKER_PREFIX = "192.168.20."   # subnet penyerang (sumber serangan)
NOISE_DST_PREFIX = "192.168.20."  # tujuan ke subnet penyerang = backscatter, buang
SCAN_PORT_THRESHOLD = 20          # >20 port tujuan unik / jendela dari satu sumber = scan
SEED = 42

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default="dataset_exp2.csv")
    ap.add_argument("--window", type=int, default=ef.WINDOW_SECONDS)
    ap.add_argument("--downsample", nargs="?", type=int, const=-1, default=None,
                    help="Seimbangkan kelas. Tanpa angka: ke kelas terkecil. "
                         "Dengan angka N: maksimal N/kelas.")
    args = ap.parse_args()
    ef.set_window(args.window)

    # ekstrak fitur TANPA label, lalu kembalikan kolom sa/da/window untuk melabeli
    mentah = ef.baca_nfdump_csv(args.input)
    df = ef.normalisasi_kolom(mentah)
    df["ts_dt"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df[df["ts_dt"].notna()].reset_index(drop=True)
    df["ts_epoch"] = ((df["ts_dt"] - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)).astype("int64")
    df["window"] = (df["ts_epoch"] // ef.WINDOW_SECONDS).astype("int64")

    fitur = ef.ekstrak(args.input)           # 10 fitur per flow (urutan sama)
    fitur["sa"] = df["sa"].values
    fitur["da"] = df["da"].values
    fitur["label"] = "normal"

    # buang backscatter: apa pun yang menuju subnet penyerang
    dst_str = fitur["da"].astype(str)
    is_backscatter = dst_str.str.startswith(NOISE_DST_PREFIX)
    n_backscatter = int(is_backscatter.sum())
    fitur = fitur[~is_backscatter].reset_index(drop=True)

    is_attacker = fitur["sa"].astype(str).str.startswith(ATTACKER_PREFIX)
    is_scan = fitur["dst_port_count"] > SCAN_PORT_THRESHOLD
    fitur.loc[is_attacker & is_scan, "label"] = "port_scanning"
    fitur.loc[is_attacker & ~is_scan, "label"] = "ddos_flood"

    out = fitur[ef.FEATURE_COLUMNS + ["label"]]

    print(f"Backscatter dibuang (tujuan {NOISE_DST_PREFIX}0/24): {n_backscatter:,} baris")
    print("\nSebelum penyeimbangan:")
    print(out["label"].value_counts().to_string())

    if args.downsample is not None:
        counts = out["label"].value_counts()
        n_min = int(counts.min())
        target = n_min if args.downsample == -1 else min(args.downsample, n_min)
        bagian = [g.sample(n=min(target, len(g)), random_state=SEED)
                  for _, g in out.groupby("label")]
        out = (pd.concat(bagian)
                 .sample(frac=1, random_state=SEED)        # acak urutan
                 .reset_index(drop=True))
        print(f"\nSetelah penyeimbangan (target {target:,}/kelas):")
        print(out["label"].value_counts().to_string())

    out.to_csv(args.output, index=False)
    print(f"\nTersimpan: {args.output}  ({len(out):,} baris)")

if __name__ == "__main__":
    main()
