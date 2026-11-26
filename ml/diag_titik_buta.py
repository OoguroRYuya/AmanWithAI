"""
diag_titik_buta.py
==================
Diagnosis "titik buta" model pada scan tanpa SYN / rentang lebar (sesi 4-5),
lanjutan banding_sesi.py. Butuh banding_sesi.py di folder yang sama.

BAGIAN 1 (baca saja, model beku):
  Dugaan: flow scan -sA/-sF (tanpa SYN, 1 paket, dst_port_count ratusan-ribuan)
  mirip flow BALASAN SERVER 192.168.30.10 ke klien (label normal: tanpa SYN,
  paket kecil, dst_port_count tinggi karena port efemeral klien banyak).
  Bagian ini membandingkan nilai fitur kedua kelompok, dan untuk tiap
  perintah nmap yang gagal (recall < 0,5, >= 100 flow) menghitung berapa flow
  normal di data latih (sesi 1-2) yang "mirip" dan dari mana asalnya.

BAGIAN 2 (EKSPLORASI, data pengembangan; BUKAN uji final, model beku TIDAK diganti):
  Melatih ulang RF dan XGB (parameter sama dengan latih_model.py) di sesi 1-2
  dengan 9 fitur + kandidat fitur yang hanya bergantung pada perilaku sumber:
    - sp_layanan  : 1 bila port sumber < 1024 (balasan layanan: 80/443/22/53, ICMP 0)
    - dst_ip_count: jumlah IP tujuan unik dari sumber itu dalam satu jendela
  lalu melaporkan F1 sesi 3, 4, 5 dan recall perintah yang gagal. Hasil ini
  hanya dasar memilih perbaikan; uji final tetap harus di sesi baru (sesi 6).

    cd ~/AmanWithAI/ml
    python3 diag_titik_buta.py \
      --sesi 1 ~/dataset_retrain/flows_sesi1.csv ~/dataset_retrain/scan_sesi1.log \
      ... (sama dengan banding_sesi.py) ... \
      --keluar ~/hasil_revisi/titik_buta 2>&1 | tee ~/hasil_revisi/titik_buta.txt
"""
import argparse
import tempfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

import banding_sesi as b
import ekstraksi_fitur as ef

KELAS = sorted(["ddos_flood", "normal", "port_scanning"])
FITUR9 = list(ef.FEATURE_COLUMNS)
SEED = 42


def baca_flow_sp(path):
    """Sama dengan banding_sesi.baca_flow, ditambah kolom sp dan dst_ip_count."""
    path = Path(path).expanduser()
    with open(path, errors="replace") as f:
        baris = [x for x in f if x.count(",") == 9]
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as t:
        t.writelines(baris)
    df = ef.ekstrak(t.name, sertakan_ip=True)
    n = ef.normalisasi_kolom(ef.baca_nfdump_csv(t.name))
    Path(t.name).unlink()
    ts = pd.to_datetime(n["ts"], errors="coerce")
    sp = pd.to_numeric(n.loc[ts.notna(), "sp"], errors="coerce").fillna(0).astype(int)
    assert len(sp) == len(df), "baris sp tidak sejajar dengan hasil ekstrak"
    df["sp"] = sp.to_numpy()
    df["sp_layanan"] = (df["sp"] < 1024).astype(int)
    df["dst_ip_count"] = df.groupby(["window", "sa"])["da"].transform("nunique")
    df = df[~df["da"].astype(str).str.startswith(b.PREFIX_PENYERANG)].reset_index(drop=True)
    okt = pd.to_numeric(df["sa"].str.rsplit(".", n=1).str[-1], errors="coerce")
    pyr = df["sa"].str.startswith(b.PREFIX_PENYERANG)
    df["label"] = "normal"
    df.loc[pyr & okt.between(*b.RENTANG_SCAN), "label"] = "port_scanning"
    df.loc[pyr & okt.between(*b.RENTANG_FLOOD), "label"] = "ddos_flood"
    return df


def kelompok(df):
    g = np.full(len(df), "lain", dtype=object)
    tcp_tanpa_syn = (df["protocol"] == 6) & (df["syn_flag_count"] == 0)
    g[(df["label"] == "normal") & df["sa"].str.startswith("192.168.30.")] = "normal_server"
    g[(df["label"] == "normal") & df["sa"].str.startswith("192.168.10.")] = "normal_klien"
    g[(df["label"] == "port_scanning")] = "scan"
    g[(df["label"] == "ddos_flood")] = "ddos"
    return pd.Series(g, index=df.index) + np.where(tcp_tanpa_syn, "_tanpaSYN", "_lain")


def latih(X, y, jenis):
    if jenis == "RF":
        m = RandomForestClassifier(n_estimators=100, max_depth=None, min_samples_split=2,
                                   random_state=SEED, n_jobs=-1, class_weight="balanced")
        return m.fit(X, y)
    from xgboost import XGBClassifier
    peta = {k: i for i, k in enumerate(KELAS)}
    m = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.3, random_state=SEED,
                      n_jobs=-1, eval_metric="mlogloss")
    m.fit(X, y.map(peta))
    return m


def prediksi(m, X):
    p = np.asarray(m.predict(X))
    if p.dtype.kind in "iu":
        p = np.array(KELAS)[p]
    return p.astype(str)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sesi", nargs=3, action="append", metavar=("N", "FLOW", "LOG"), required=True)
    ap.add_argument("--model", default="model/model_terbaik.pkl")
    ap.add_argument("--keluar", default="hasil_revisi/titik_buta")
    ap.add_argument("--lewati-eksplorasi", action="store_true")
    a = ap.parse_args()
    keluar = Path(a.keluar).expanduser()
    keluar.mkdir(parents=True, exist_ok=True)
    beku = joblib.load(a.model)

    data, logs = {}, {}
    for n, p_flow, p_log in a.sesi:
        n = int(n)
        df = baca_flow_sp(p_flow)
        log = b.baca_log(p_log)
        scan = df[df["label"] == "port_scanning"]
        geser, frac = b.cari_geser(scan, log)
        df["run"] = -1
        df.loc[scan.index, "run"] = b.kaitkan(scan, log, geser)
        df["kel"] = kelompok(df)
        df["pred_beku"] = prediksi(beku, df[FITUR9])
        data[n], logs[n] = df, log
        print(f"Sesi {n}: {len(df)} flow, terkait log {frac:.1%}")

    # ---------------- BAGIAN 1
    print("\n== 1a. Nilai fitur per kelompok (median [p10-p90]); jumlah flow")
    rows = []
    for n, df in data.items():
        for kel, g in df.groupby("kel"):
            r = {"sesi": n, "kelompok": kel, "flow": len(g),
                 "pred_normal_beku": round((g["pred_beku"] == "normal").mean(), 3),
                 "sp_layanan": round(g["sp_layanan"].mean(), 3)}
            for f in ("dst_port_count", "packet_count", "byte_count", "duration", "dst_ip_count"):
                q = g[f].quantile([0.1, 0.5, 0.9]).round(1).tolist()
                r[f] = f"{q[1]} [{q[0]}-{q[2]}]"
            rows.append(r)
    t1 = pd.DataFrame(rows)
    t1.to_csv(keluar / "1a_fitur_per_kelompok.csv", index=False)
    with pd.option_context("display.width", 250, "display.max_columns", 20):
        print(t1[t1["kelompok"].str.match(r"(normal_server|normal_klien|scan)_tanpaSYN")]
              .to_string(index=False))

    print("\n== 1b. Perintah nmap yang gagal (recall model beku < 0,5, >= 100 flow) "
          "dan flow normal mirip di data latih (sesi 1-2)")
    latih_df = pd.concat([data[s] for s in (1, 2) if s in data])
    ln = latih_df[(latih_df["label"] == "normal") & (latih_df["protocol"] == 6)
                  & (latih_df["syn_flag_count"] == 0)]
    gagal = []
    for n, df in data.items():
        for r, g in df[df["run"] >= 0].groupby("run"):
            rec = (g["pred_beku"] == "port_scanning").mean()
            if len(g) < 100 or rec >= 0.5:
                continue
            med = g[FITUR9].median()
            dpc = med["dst_port_count"]
            mirip = ln[(ln["dst_port_count"].between(0.85 * dpc, 1.15 * dpc))
                       & (ln["packet_count"] <= max(2, med["packet_count"]))]
            gagal.append({"sesi": n, "run": r, "perintah": logs[n].loc[r, "perintah"][:60],
                          "flow": len(g), "recall_beku": round(rec, 3),
                          "dst_port_count_med": dpc, "pkt_med": med["packet_count"],
                          "byte_med": med["byte_count"], "sp_layanan": round(g["sp_layanan"].mean(), 2),
                          "normal_latih_mirip": len(mirip),
                          "porsi_dari_server": round(mirip["sa"].str.startswith("192.168.30.").mean(), 3)
                          if len(mirip) else None})
    tg = pd.DataFrame(gagal)
    tg.to_csv(keluar / "1b_perintah_gagal.csv", index=False)
    with pd.option_context("display.width", 250, "display.max_columns", 20):
        print(tg.to_string(index=False))

    if a.lewati_eksplorasi:
        return

    # ---------------- BAGIAN 2
    print("\n== 2. EKSPLORASI (data pengembangan, bukan uji final): latih sesi 1-2, kandidat fitur")
    varian = {"9 fitur (ulang)": FITUR9,
              "+sp_layanan": FITUR9 + ["sp_layanan"],
              "+dst_ip_count": FITUR9 + ["dst_ip_count"],
              "+keduanya": FITUR9 + ["sp_layanan", "dst_ip_count"]}
    hasil, run_hasil = [], []
    for nama, fit in varian.items():
        for jenis in ("XGB", "RF"):
            m = latih(latih_df[fit], latih_df["label"], jenis)
            for n, df in data.items():
                p = prediksi(m, df[fit])
                hasil.append({"varian": nama, "model": jenis, "sesi": n,
                              "f1_makro": round(f1_score(df["label"], p, labels=KELAS, average="macro"), 4),
                              "recall_scan": round((p[df["label"].to_numpy() == "port_scanning"]
                                                    == "port_scanning").mean(), 4)})
                if not tg.empty:
                    for g in tg[tg["sesi"] == n].itertuples():
                        idx = (df["run"] == g.run).to_numpy()
                        run_hasil.append({"varian": nama, "model": jenis, "sesi": n, "run": g.run,
                                          "recall": round((p[idx] == "port_scanning").mean(), 3)})
            print(f"  selesai: {nama} {jenis}")
    th = pd.DataFrame(hasil)
    th.to_csv(keluar / "2_f1_varian.csv", index=False)
    print("\n[F1 makro per sesi; sesi 1-2 = latih, 3 = validasi, 4-5 = data pengembangan]")
    print(th.pivot_table(index=["varian", "model"], columns="sesi", values="f1_makro").to_string())
    print("\n[recall scan per sesi]")
    print(th.pivot_table(index=["varian", "model"], columns="sesi", values="recall_scan").to_string())
    if run_hasil:
        tr = pd.DataFrame(run_hasil)
        tr.to_csv(keluar / "2_recall_perintah_gagal.csv", index=False)
        print("\n[recall perintah yang gagal pada model beku]")
        print(tr.pivot_table(index=["varian", "model"], columns=["sesi", "run"],
                             values="recall").to_string())
    print(f"\nTersimpan di {keluar}")


if __name__ == "__main__":
    main()
