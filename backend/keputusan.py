"""
keputusan.py
============
Gerbang keputusan mitigasi per insiden (D3). Model hanya mengklasifikasi;
modul ini yang menentukan apakah suatu insiden diblokir otomatis, menunggu
persetujuan administrator, atau sekadar dicatat.

Aturan untuk setiap insiden dalam satu jendela:
    - insiden dengan jumlah_flow < MIN_FLOW_INSIDEN diabaikan
    - setiap sumber dinilai dari per_sumber jendela tersebut:
        rasio_serangan = flow serangan sumber / seluruh flow sumber
        conf_rata      = rata-rata confidence flow serangan sumber
      sumber LOLOS bila rasio >= AMBANG_RASIO_SERANGAN, conf_rata >=
      AMBANG_TINGGI, dan tidak ada di ALLOWLIST
    - status insiden:
        confidence >= AMBANG_TINGGI dan ada sumber lolos -> blokir_otomatis
        confidence >= AMBANG_SEDANG dan ada kandidat     -> menunggu_persetujuan
        selain itu                                        -> dicatat
      kandidat persetujuan = sumber dengan rasio >= AMBANG_RASIO_SERANGAN
      yang tidak ada di ALLOWLIST (ambang confidence diserahkan ke admin)

Gerbang rasio inilah yang mencegah klien sah terblokir: klien normal
mengirim banyak flow normal, sehingga beberapa salah klasifikasi tetap
membuat rasionya jauh di bawah ambang. Sumber flood palsu hanya mengirim
flow serangan sehingga rasionya 1.0.
"""

import sys
from dataclasses import asdict, dataclass, field
from typing import List

import konfigurasi as cfg
from pipeline import HasilWindow, Insiden, KELAS_SERANGAN

sys.path.insert(0, str(cfg.DIR_REPO / "ml"))

import ekstraksi_fitur as ef  # noqa: E402
from saran_tindakan import susun_saran  # noqa: E402

BLOKIR_OTOMATIS = "blokir_otomatis"
MENUNGGU_PERSETUJUAN = "menunggu_persetujuan"
DICATAT = "dicatat"


@dataclass
class EvaluasiSumber:
    ip: str
    rasio_serangan: float
    conf_rata: float
    lolos: bool
    alasan: str


@dataclass
class KeputusanInsiden:
    insiden: Insiden
    status: str
    alasan: str
    ip_blokir: List[str]
    ip_kandidat: List[str]
    evaluasi_sumber: List[EvaluasiSumber]
    saran: dict

    def ke_dict(self):
        return asdict(self)


@dataclass
class HasilKeputusan:
    window: str
    keputusan: List[KeputusanInsiden] = field(default_factory=list)
    jumlah_diabaikan: int = 0

    @property
    def ip_blokir(self):
        """Gabungan IP yang diblokir otomatis dari seluruh insiden jendela ini."""
        return sorted({ip for k in self.keputusan for ip in k.ip_blokir})

    @property
    def menunggu(self):
        return [k for k in self.keputusan if k.status == MENUNGGU_PERSETUJUAN]


def evaluasi_sumber(ip, per_sumber, ambang_rasio, ambang_tinggi, allowlist):
    stat = per_sumber.get(ip, {})
    total = stat.get("total", 0)
    serangan = sum(stat.get(k, 0) for k in KELAS_SERANGAN)
    rasio = serangan / total if total else 0.0
    conf = stat.get("conf_serangan", 0.0) / serangan if serangan else 0.0

    if ip in allowlist:
        alasan = "ada di allowlist"
    elif rasio < ambang_rasio:
        alasan = f"rasio serangan {rasio:.2f} < {ambang_rasio:.2f}"
    elif conf < ambang_tinggi:
        alasan = f"confidence rata-rata {conf:.2f} < {ambang_tinggi:.2f}"
    else:
        alasan = "lolos semua gerbang"

    lolos = alasan == "lolos semua gerbang"
    return EvaluasiSumber(ip, round(rasio, 4), round(conf, 4), lolos, alasan)


def _ringkas_ip(daftar):
    if len(daftar) == 1:
        return daftar[0]
    return f"{daftar[0]} dan {len(daftar) - 1} alamat lain"


def _saran(ins, status, ip_utama, ambang_tinggi, ambang_sedang, durasi_blokir):
    # Narasi menyebut IP yang diblokir/diusulkan, bukan sumber pertama
    # menurut urutan string (yang bisa saja klien salah klasifikasi)
    waktu = ins.window.replace("T", " ")
    saran = susun_saran(
        kelas=ins.kelas,
        src_ip=_ringkas_ip(ip_utama or ins.sumber),
        dst_ip=_ringkas_ip(ins.tujuan),
        confidence=ins.confidence,
        packet_count=ins.packet_total,
        byte_count=ins.byte_total,
        # laju rata-rata insiden sepanjang satu jendela
        flow_rate=ins.packet_total / ef.WINDOW_SECONDS,
        dst_port_count=ins.dst_port_maks,
        waktu=waktu,
        durasi_blokir=durasi_blokir,
        ambang_tinggi=ambang_tinggi,
        ambang_sedang=ambang_sedang,
    )
    otomatis = status == BLOKIR_OTOMATIS
    if saran.get("mitigasi_otomatis") and not otomatis:
        catatan = (
            "Catatan: pemblokiran otomatis tidak dijalankan karena tidak ada "
            "sumber yang lolos gerbang rasio serangan, confidence, dan allowlist."
        )
        saran["saran_mitigasi"] = f"{saran['saran_mitigasi']} {catatan}"
        saran["narasi"] = f"{saran['narasi']}\n\n{catatan}"
    saran["mitigasi_otomatis"] = otomatis
    return saran


def putuskan(
    hasil: HasilWindow,
    min_flow=None,
    ambang_rasio=None,
    ambang_tinggi=None,
    ambang_sedang=None,
    allowlist=None,
    durasi_blokir=None,
):
    """Menerapkan gerbang D3 pada seluruh insiden satu jendela."""
    min_flow = cfg.MIN_FLOW_INSIDEN if min_flow is None else min_flow
    ambang_rasio = cfg.AMBANG_RASIO_SERANGAN if ambang_rasio is None else ambang_rasio
    ambang_tinggi = cfg.AMBANG_TINGGI if ambang_tinggi is None else ambang_tinggi
    ambang_sedang = cfg.AMBANG_SEDANG if ambang_sedang is None else ambang_sedang
    allowlist = cfg.ALLOWLIST if allowlist is None else set(allowlist)
    durasi_blokir = cfg.DURASI_BLOKIR_MENIT if durasi_blokir is None else durasi_blokir

    keluaran = HasilKeputusan(window=hasil.window)

    for ins in hasil.insiden:
        if ins.jumlah_flow < min_flow:
            keluaran.jumlah_diabaikan += 1
            continue

        evals = [
            evaluasi_sumber(ip, hasil.per_sumber, ambang_rasio, ambang_tinggi, allowlist)
            for ip in ins.sumber
        ]
        lolos = [e.ip for e in evals if e.lolos]
        kandidat = [
            e.ip for e in evals
            if e.rasio_serangan >= ambang_rasio and e.ip not in allowlist
        ]

        if ins.confidence >= ambang_tinggi and lolos:
            status = BLOKIR_OTOMATIS
            alasan = f"{len(lolos)} dari {len(evals)} sumber lolos gerbang"
            ip_blokir, ip_kandidat = lolos, []
        elif ins.confidence >= ambang_sedang and kandidat:
            status = MENUNGGU_PERSETUJUAN
            if ins.confidence >= ambang_tinggi:
                alasan = "confidence tinggi, tetapi tidak ada sumber yang lolos semua gerbang"
            else:
                alasan = (
                    f"confidence {ins.confidence:.2f} di antara "
                    f"{ambang_sedang:.2f} dan {ambang_tinggi:.2f}"
                )
            ip_blokir, ip_kandidat = [], kandidat
        else:
            status = DICATAT
            if ins.confidence < ambang_sedang:
                alasan = f"confidence {ins.confidence:.2f} < {ambang_sedang:.2f}"
            else:
                alasan = "tidak ada sumber yang layak diblokir"
            ip_blokir, ip_kandidat = [], []

        keluaran.keputusan.append(KeputusanInsiden(
            insiden=ins,
            status=status,
            alasan=alasan,
            ip_blokir=ip_blokir,
            ip_kandidat=ip_kandidat,
            evaluasi_sumber=evals,
            saran=_saran(ins, status, ip_blokir or ip_kandidat,
                         ambang_tinggi, ambang_sedang, durasi_blokir),
        ))

    return keluaran
