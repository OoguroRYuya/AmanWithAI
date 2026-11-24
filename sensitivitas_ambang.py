"""Analisis sensitivitas ambang gerbang keputusan (koreksi Pak Deni butir 22).

Pipeline backend (proses_csv) dan gerbang keputusan (putuskan + pemutus
darurat) yang SAMA dengan backend dijalankan pada data VALIDASI sesi 3, untuk
setiap kombinasi:
    AMBANG_RASIO_SERANGAN, AMBANG_CONF_BLOKIR, MIN_FLOW_INSIDEN.
AMBANG_SEDANG tetap (nilai .env), dibatasi tidak melebihi ambang blokir.

Kebenaran dasar per IP dari rentang generator (sama dengan pelabelan):
    192.168.20.11-30  = pemindai, 192.168.20.31-250 = sumber flood palsu,
    sumber lain       = sah (klien .10.x, server .30.x, dst.).

Taruh di ROOT repo (sejajar backend/ dan ml/), jalankan dengan venv backend:
  .\\backend\\.venv\\Scripts\\python.exe sensitivitas_ambang.py <flows_sesi3.csv> --keluar hasil_sensitivitas
Data sesi 4 dan sesi 5 TIDAK boleh dipakai di sini.
"""
import argparse
import ipaddress
import itertools
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "ml"))

import joblib  # noqa: E402
import pandas as pd  # noqa: E402

import keputusan as kp  # noqa: E402
import konfigurasi as cfg  # noqa: E402
import pipeline  # noqa: E402

GRID_RASIO = [0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]
GRID_CONF = [0.50, 0.60, 0.70, 0.80, 0.90]
GRID_MIN_FLOW = [5, 10, 15, 20, 25, 30, 40, 50]


def bersihkan(path):
    fd, tmp = tempfile.mkstemp(suffix=".csv", prefix="flows_clean_")
    with open(path, "r", errors="replace") as f, os.fdopen(fd, "w") as out:
        for baris in f:
            if baris.rstrip("\r\n").count(",") == 9:
                out.write(baris)
    return tmp


def peran(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "sah"
    if a in ipaddress.ip_network("192.168.20.0/24"):
        o = int(str(a).rsplit(".", 1)[1])
        if 11 <= o <= 30:
            return "pemindai"
        if 31 <= o <= 250:
            return "flood"
    return "sah"


def jalankan(hasil_list, rasio, conf, min_flow):
    terblokir, antre = set(), set()
    pemutus = 0
    status = {"blokir_otomatis": 0, "menunggu_persetujuan": 0, "dicatat": 0}
    diabaikan = 0
    pasangan_scan = set()  # (jendela, ip pemindai) yang diblokir atau diantrekan
    for hw in hasil_list:
        kep = kp.putuskan(hw, min_flow=min_flow, ambang_rasio=rasio,
                          ambang_conf_blokir=conf,
                          ambang_sedang=min(cfg.AMBANG_SEDANG, conf))
        if kp.pemutus_darurat(kep, set(terblokir), cfg.MAKS_BLOKIR_BARU_PER_JENDELA):
            pemutus += 1
        diabaikan += kep.jumlah_diabaikan
        for k in kep.keputusan:
            status[k.status] += 1
            antre |= set(k.ip_kandidat)
            for ip in k.ip_blokir + k.ip_kandidat:
                if peran(ip) == "pemindai":
                    pasangan_scan.add((hw.window, ip))
        terblokir |= set(kep.ip_blokir)
    return terblokir, antre, pemutus, status, diabaikan, pasangan_scan


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", help="CSV nfdump mentah sesi 3 (validasi)")
    ap.add_argument("--keluar", default="hasil_sensitivitas")
    a = ap.parse_args()
    keluar = Path(a.keluar)
    keluar.mkdir(parents=True, exist_ok=True)

    model = joblib.load(cfg.MODEL_PATH)
    tmp = bersihkan(a.csv)
    try:
        hasil_list = pipeline.proses_csv(tmp, model)
    finally:
        os.remove(tmp)

    # kebenaran dasar dari per_sumber tiap jendela
    ip_ada = {"pemindai": set(), "flood": set(), "sah": set()}
    pasangan_scan_ada, pasangan_scan_20 = set(), set()
    for hw in hasil_list:
        for ip, st in hw.per_sumber.items():
            p = peran(ip)
            ip_ada[p].add(ip)
            if p == "pemindai":
                pasangan_scan_ada.add((hw.window, ip))
                if st["total"] >= 20:
                    pasangan_scan_20.add((hw.window, ip))
    print(f"Berkas {a.csv}: {len(hasil_list)} jendela")
    print(f"IP unik: pemindai {len(ip_ada['pemindai'])}, flood {len(ip_ada['flood'])}, "
          f"sah {len(ip_ada['sah'])}")
    print(f"Pasangan jendela-pemindai: {len(pasangan_scan_ada)} "
          f"({len(pasangan_scan_20)} dengan >= 20 flow)")
    print(f"Nilai sekarang: rasio {cfg.AMBANG_RASIO_SERANGAN}, conf {cfg.AMBANG_CONF_BLOKIR}, "
          f"min_flow {cfg.MIN_FLOW_INSIDEN}, sedang {cfg.AMBANG_SEDANG}, "
          f"batas pemutus {cfg.MAKS_BLOKIR_BARU_PER_JENDELA}")

    baris = []
    t = time.time()
    for rasio, conf, mf in itertools.product(GRID_RASIO, GRID_CONF, GRID_MIN_FLOW):
        blok, antre, pemutus, status, diabaikan, ps = jalankan(hasil_list, rasio, conf, mf)
        per = {p: {ip for ip in blok if peran(ip) == p} for p in ip_ada}
        antre_sah = {ip for ip in antre if peran(ip) == "sah"}
        baris.append({
            "rasio": rasio, "conf": conf, "min_flow": mf,
            "sekarang": (rasio == cfg.AMBANG_RASIO_SERANGAN and conf == cfg.AMBANG_CONF_BLOKIR
                         and mf == cfg.MIN_FLOW_INSIDEN),
            "blokir_pemindai": len(per["pemindai"]),
            "blokir_flood": len(per["flood"]),
            "blokir_sah": len(per["sah"]),
            "antrean_sah": len(antre_sah),
            "antrean_total": len(antre),
            "pemindai_tertangani_pasangan": len(ps),
            "cakupan_pasangan_20": round(len(ps & pasangan_scan_20) / len(pasangan_scan_20), 4)
            if pasangan_scan_20 else None,
            "keputusan_blokir": status["blokir_otomatis"],
            "keputusan_antrean": status["menunggu_persetujuan"],
            "keputusan_dicatat": status["dicatat"],
            "diabaikan": diabaikan,
            "pemutus_darurat": pemutus,
        })
    print(f"{len(baris)} kombinasi selesai dalam {time.time() - t:.0f} s")
    df = pd.DataFrame(baris)
    df.to_csv(keluar / "b22_sensitivitas_grid.csv", index=False)

    kol = ["rasio", "conf", "min_flow", "blokir_pemindai", "blokir_flood", "blokir_sah",
           "antrean_sah", "pemindai_tertangani_pasangan", "cakupan_pasangan_20", "pemutus_darurat"]
    with open(keluar / "b22_ringkasan.txt", "w", encoding="utf-8") as f:
        def tulis(s=""):
            print(s)
            f.write(s + "\n")
        sek = df[df["sekarang"]]
        tulis("\nNilai sekarang:")
        tulis(sek[kol].to_string(index=False))
        for nama, sumbu, tetap in (
            ("rasio", "rasio", {"conf": cfg.AMBANG_CONF_BLOKIR, "min_flow": cfg.MIN_FLOW_INSIDEN}),
            ("confidence", "conf", {"rasio": cfg.AMBANG_RASIO_SERANGAN, "min_flow": cfg.MIN_FLOW_INSIDEN}),
            ("jumlah flow minimum", "min_flow", {"rasio": cfg.AMBANG_RASIO_SERANGAN,
                                                 "conf": cfg.AMBANG_CONF_BLOKIR}),
        ):
            m = pd.Series(True, index=df.index)
            for k, v in tetap.items():
                m &= df[k] == v
            tulis(f"\nVariasi {nama} (ambang lain tetap pada nilai sekarang):")
            tulis(df[m].sort_values(sumbu)[kol].to_string(index=False))
        aman = df[df["blokir_sah"] == 0]
        tulis(f"\nKombinasi tanpa IP sah terblokir: {len(aman)} dari {len(df)}")
        if len(aman):
            terbaik = aman["pemindai_tertangani_pasangan"].max()
            tulis(f"Cakupan pemindai tertinggi tanpa salah blokir: {terbaik} pasangan; "
                  f"dicapai {int((aman['pemindai_tertangani_pasangan'] == terbaik).sum())} kombinasi")
    print(f"\nTersimpan di {keluar}")


if __name__ == "__main__":
    main()
