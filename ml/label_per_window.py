"""
label_per_window.py
===================
Pelabelan Eksperimen 2. Di Eksperimen 1 tiap file CSV berisi satu kelas murni,
jadi `--label` cukup. Di Eksperimen 2 trafik normal dan serangan berjalan
BERSAMAAN, maka label ditentukan per flow dari IP sumber + perilaku, bukan
per file.

Pakai:
    python label_per_window.py flows.csv -o dataset_exp2.csv

Aturan (sesuaikan bila rentang IP berbeda):
    - sumber 192.168.20.0/24  -> kandidat serangan
        * banyak port tujuan unik dalam jendela  -> port_scanning
        * selain itu (volume tinggi ke sedikit port) -> ddos_flood
    - sumber lain -> normal
Ambang dibuat eksplisit supaya bisa dipertanggungjawabkan saat sidang.
"""
import argparse
import pandas as pd
import ekstraksi_fitur as ef

ATTACKER_PREFIX = "192.168.20."
SCAN_PORT_THRESHOLD = 20   # >20 port tujuan unik / jendela dari satu sumber = scan

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default="dataset_exp2.csv")
    ap.add_argument("--window", type=int, default=ef.WINDOW_SECONDS)
    args = ap.parse_args()
    ef.set_window(args.window)

    # ekstrak fitur TANPA label, lalu kembalikan kolom sa/dp/window untuk melabeli
    mentah = ef.baca_nfdump_csv(args.input)
    df = ef.normalisasi_kolom(mentah)
    df["ts_dt"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df[df["ts_dt"].notna()].reset_index(drop=True)
    df["ts_epoch"] = ((df["ts_dt"] - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)).astype("int64")
    df["window"] = (df["ts_epoch"] // ef.WINDOW_SECONDS).astype("int64")

    fitur = ef.ekstrak(args.input)           # 10 fitur per flow (urutan sama)
    fitur["sa"] = df["sa"].values
    fitur["label"] = "normal"

    is_attacker = fitur["sa"].astype(str).str.startswith(ATTACKER_PREFIX)
    is_scan = fitur["dst_port_count"] > SCAN_PORT_THRESHOLD
    fitur.loc[is_attacker & is_scan, "label"] = "port_scanning"
    fitur.loc[is_attacker & ~is_scan, "label"] = "ddos_flood"

    out = fitur[ef.FEATURE_COLUMNS + ["label"]]
    out.to_csv(args.output, index=False)
    print(out["label"].value_counts().to_string())
    print(f"\nTersimpan: {args.output}")

if __name__ == "__main__":
    main()
