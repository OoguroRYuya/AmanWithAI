"""Replay offline 4.4.3: jalankan pipeline backend (proses_csv) + gerbang
keputusan (putuskan + pemutus_darurat, himpunan terblokir berjalan antar
jendela) pada satu CSV nfdump mentah, lalu kumpulkan tally insiden level-sistem
persis seperti backend saat mode replay.

Taruh file ini di ROOT repo (folder yang berisi backend/ dan ml/), jalankan:
  .\backend\.venv\Scripts\python.exe replay_tally.py <path-ke-flows_sesi4.csv>
"""
import sys, os, ipaddress, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "ml"))

import joblib
import konfigurasi as cfg
import pipeline, keputusan as kp
import ekstraksi_fitur as ef

if len(sys.argv) < 2:
    sys.exit("pakai: python replay_tally.py <path-ke-flows_sesi4.csv>")
CSV_RAW = sys.argv[1]
model = joblib.load(cfg.MODEL_PATH)


def bersihkan(path):
    """Buang baris header/footer nfdump; simpan hanya baris 10-kolom (9 koma),
    seperti `awk -F, 'NF==10'` saat pelabelan. Mengembalikan path temp bersih."""
    fd, tmp = tempfile.mkstemp(suffix=".csv", prefix="flows_clean_")
    n_in = n_out = 0
    with open(path, "r", errors="replace") as f, os.fdopen(fd, "w") as out:
        for line in f:
            n_in += 1
            if line.rstrip("\r\n").count(",") == 9:
                out.write(line); n_out += 1
    print(f"Bersih-kan nfdump: {n_in} baris -> {n_out} baris data (buang {n_in - n_out})")
    return tmp


CSV = bersihkan(CSV_RAW)


def in_net(ip, nets):
    for n in nets:
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(n):
                return True
        except ValueError:
            pass
    return False


hasil_list = pipeline.proses_csv(CSV, model)

terblokir = set()
tot_ins = auto_ins = antre_ins = dicatat_ins = diabaikan = 0
ip_blokir_all = set(); ip_antre_all = set(); n_pemutus = 0
for hw in hasil_list:
    kep = kp.putuskan(hw)
    if kp.pemutus_darurat(kep, set(terblokir), cfg.MAKS_BLOKIR_BARU_PER_JENDELA):
        n_pemutus += 1
    diabaikan += kep.jumlah_diabaikan
    for k in kep.keputusan:
        tot_ins += 1
        if k.status == kp.BLOKIR_OTOMATIS:
            auto_ins += 1; ip_blokir_all |= set(k.ip_blokir)
        elif k.status == kp.MENUNGGU_PERSETUJUAN:
            antre_ins += 1; ip_antre_all |= set(k.ip_kandidat)
        else:
            dicatat_ins += 1
    terblokir |= set(kep.ip_blokir)

client_blok = sorted(ip for ip in ip_blokir_all if in_net(ip, cfg.SUBNET_TERLINDUNG))

df = ef.ekstrak(CSV, sertakan_ip=True)
bs = pipeline.tandai_backscatter(df["da"])
df = df[~bs].reset_index(drop=True)
df = pipeline.prediksi(df, model)
df["sa"] = df["sa"].astype(str)
klien = df[df["sa"].apply(lambda ip: in_net(ip, ["192.168.10.0/24"]))]
klien_ddos = int((klien["kelas"] == "ddos_flood").sum())
klien_scan = int((klien["kelas"] == "port_scanning").sum())

print(f"CSV                     : {CSV}")
print(f"Jumlah jendela          : {len(hasil_list)}")
print(f"Flow setelah buang backscatter : {len(df)}")
print(f"Prediksi per kelas      : {df['kelas'].value_counts().to_dict()}")
print("-" * 52)
print(f"Total insiden (>= {cfg.MIN_FLOW_INSIDEN} flow) : {tot_ins}")
print(f"  diblokir otomatis     : {auto_ins}")
print(f"  menunggu persetujuan  : {antre_ins}")
print(f"  hanya dicatat         : {dicatat_ins}")
print(f"  diabaikan (<min_flow) : {diabaikan}")
print(f"Jendela kena pemutus darurat : {n_pemutus}")
print("-" * 52)
print(f"IP sumber diblokir otomatis (unik) : {len(ip_blokir_all)}")
print(f"IP Client (10.0/24) terblokir      : {len(client_blok)}  {client_blok}")
print(f"IP masuk antrean (unik)            : {len(ip_antre_all)}")
print("-" * 52)
print(f"Flow sumber Client 10.x -> serangan : {klien_ddos + klien_scan}"
      f"  (ddos {klien_ddos}, scan {klien_scan})")
print(f"Total flow sumber Client 10.x       : {len(klien)}")
