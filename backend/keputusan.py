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
      AMBANG_CONF_BLOKIR, dan tidak ada di ALLOWLIST
    - status insiden:
        ada sumber lolos  -> blokir_otomatis
        ada kandidat      -> menunggu_persetujuan
        selain itu        -> dicatat
      kandidat persetujuan = sumber dengan rasio >= AMBANG_RASIO_SERANGAN
      yang tidak ada di ALLOWLIST dan AMBANG_SEDANG <= conf_rata <
      AMBANG_CONF_BLOKIR; di bawah AMBANG_SEDANG sumber hanya dicatat

Pemicu blokir sengaja per sumber, bukan rata-rata confidence insiden:
rata-rata insiden flood dihitung atas ratusan sumber palsu sehingga hampir
tidak pernah mencapai AMBANG_TINGGI, padahal tiap sumbernya jelas serangan.

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


def evaluasi_sumber(ip, per_sumber, ambang_rasio, ambang_conf, allowlist):
    stat = per_sumber.get(ip, {})
    total = stat.get("total", 0)
    serangan = sum(stat.get(k, 0) for k in KELAS_SERANGAN)
    rasio = serangan / total if total else 0.0
    conf = stat.get("conf_serangan", 0.0) / serangan if serangan else 0.0

    if ip in allowlist:
        alasan = "ada di allowlist"
    elif rasio < ambang_rasio:
        alasan = f"rasio serangan {rasio:.2f} < {ambang_rasio:.2f}"
    elif conf < ambang_conf:
        alasan = f"confidence rata-rata {conf:.2f} < {ambang_conf:.2f}"
    else:
        alasan = "lolos semua gerbang"

    lolos = alasan == "lolos semua gerbang"
    return EvaluasiSumber(ip, round(rasio, 4), round(conf, 4), lolos, alasan)


def _ringkas_ip(daftar):
    if len(daftar) == 1:
        return daftar[0]
    return f"{daftar[0]} dan {len(daftar) - 1} alamat lain"


def _saran(ins, status, evals_utama, ambang_conf, ambang_sedang, durasi_blokir):
    # Narasi menyebut IP yang diblokir/diusulkan, bukan sumber pertama
    # menurut urutan string (yang bisa saja klien salah klasifikasi).
    # Tingkat tindakan mengikuti confidence sumber tersebut dan ambang
    # blokir, sejalan dengan gerbang per sumber.
    waktu = ins.window.replace("T", " ")
    ip_utama = [e.ip for e in evals_utama]
    confidence = (sum(e.conf_rata for e in evals_utama) / len(evals_utama)
                  if evals_utama else ins.confidence)
    saran = susun_saran(
        kelas=ins.kelas,
        src_ip=_ringkas_ip(ip_utama or ins.sumber),
        dst_ip=_ringkas_ip(ins.tujuan),
        confidence=confidence,
        packet_count=ins.packet_total,
        byte_count=ins.byte_total,
        # laju rata-rata insiden sepanjang satu jendela
        flow_rate=ins.packet_total / ef.WINDOW_SECONDS,
        dst_port_count=ins.dst_port_maks,
        waktu=waktu,
        durasi_blokir=durasi_blokir,
        ambang_tinggi=ambang_conf,
        ambang_sedang=min(ambang_sedang, ambang_conf),
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
    ambang_conf_blokir=None,
    ambang_sedang=None,
    allowlist=None,
    durasi_blokir=None,
):
    """Menerapkan gerbang D3 pada seluruh insiden satu jendela."""
    min_flow = cfg.MIN_FLOW_INSIDEN if min_flow is None else min_flow
    ambang_rasio = cfg.AMBANG_RASIO_SERANGAN if ambang_rasio is None else ambang_rasio
    ambang_conf = cfg.AMBANG_CONF_BLOKIR if ambang_conf_blokir is None else ambang_conf_blokir
    ambang_sedang = cfg.AMBANG_SEDANG if ambang_sedang is None else ambang_sedang
    allowlist = cfg.ALLOWLIST if allowlist is None else set(allowlist)
    durasi_blokir = cfg.DURASI_BLOKIR_MENIT if durasi_blokir is None else durasi_blokir

    keluaran = HasilKeputusan(window=hasil.window)

    for ins in hasil.insiden:
        if ins.jumlah_flow < min_flow:
            keluaran.jumlah_diabaikan += 1
            continue

        evals = [
            evaluasi_sumber(ip, hasil.per_sumber, ambang_rasio, ambang_conf, allowlist)
            for ip in ins.sumber
        ]
        lolos = [e for e in evals if e.lolos]
        kandidat = [
            e for e in evals
            if e.rasio_serangan >= ambang_rasio and e.ip not in allowlist
            and ambang_sedang <= e.conf_rata < ambang_conf
        ]

        if lolos:
            status = BLOKIR_OTOMATIS
            alasan = f"{len(lolos)} dari {len(evals)} sumber lolos gerbang"
            utama = lolos
            ip_blokir, ip_kandidat = [e.ip for e in lolos], []
        elif kandidat:
            status = MENUNGGU_PERSETUJUAN
            alasan = (
                f"{len(kandidat)} sumber lolos gerbang rasio dengan confidence "
                f"rata-rata di antara {ambang_sedang:.2f} dan {ambang_conf:.2f}"
            )
            utama = kandidat
            ip_blokir, ip_kandidat = [], [e.ip for e in kandidat]
        else:
            status = DICATAT
            alasan = "tidak ada sumber yang layak diblokir"
            utama = []
            ip_blokir, ip_kandidat = [], []

        keluaran.keputusan.append(KeputusanInsiden(
            insiden=ins,
            status=status,
            alasan=alasan,
            ip_blokir=ip_blokir,
            ip_kandidat=ip_kandidat,
            evaluasi_sumber=evals,
            saran=_saran(ins, status, utama, ambang_conf, ambang_sedang, durasi_blokir),
        ))

    return keluaran
