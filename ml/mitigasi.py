"""
mitigasi.py
===========
Modul mitigasi otomatis: memblokir alamat IP sumber serangan pada router
melalui koneksi SSH menggunakan library Netmiko.

Modul ini bersifat deterministik dan berbasis aturan. Model machine learning
hanya bertugas melakukan klasifikasi; keputusan pemblokiran dieksekusi oleh
modul ini berdasarkan hasil klasifikasi tersebut. Pemisahan ini disengaja
agar tindakan yang berdampak langsung pada jaringan dapat diaudit.

Catatan platform:
    Implementasi ini menargetkan VyOS (device_type 'vyos'). Bila penelitian
    kembali menggunakan Cisco IOS, ubah DEVICE_TYPE menjadi 'cisco_ios' dan
    gunakan kumpulan perintah pada CISCO_COMMANDS.
"""

import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mitigasi")

DEVICE_TYPE = "vyos"

# Nama firewall group pada VyOS yang menampung daftar IP terblokir
FIREWALL_GROUP = "BLOKIR_NDR"

# Batas lama satu pemblokiran (menit)
MAKS_DURASI_MENIT = 1440

# Keluaran VyOS yang menandakan perintah atau commit gagal
POLA_GAGAL = re.compile(r"(?i)(commit failed|failed|error|invalid|not valid|is not a valid)")
# Baris konfigurasi anggota address-group pada `show configuration commands`
POLA_ANGGOTA = re.compile(
    r"address-group\s+" + FIREWALL_GROUP + r"\s+address\s+'?(\d{1,3}(?:\.\d{1,3}){3})'?"
)


def keluaran_gagal(teks):
    """True bila keluaran router memuat tanda kegagalan."""
    return bool(teks) and bool(POLA_GAGAL.search(str(teks)))


def anggota_grup(teks):
    """Himpunan IP anggota BLOKIR_NDR dari keluaran `show configuration commands`."""
    return set(POLA_ANGGOTA.findall(str(teks or "")))


def ip_aman(ip):
    """
    Mengembalikan IP dalam bentuk baku bila ia SATU alamat IPv4 host yang
    wajar diblokir; selain itu ValueError.

    Setiap IP divalidasi di sini, tepat sebelum dirangkai menjadi perintah
    router, sehingga teks seperti "1.2.3.4\\ndelete firewall ..." (injeksi
    perintah) atau rentang "0.0.0.0-255.255.255.255" tidak pernah sampai
    ke VyOS, dari mana pun asalnya (API, pipeline, berkas status).
    """
    if not isinstance(ip, str):
        raise ValueError("IP harus berupa teks")
    alamat = ipaddress.IPv4Address(ip.strip())
    if (alamat.is_unspecified or alamat.is_loopback or alamat.is_multicast
            or alamat.is_link_local or alamat.is_reserved
            or alamat == ipaddress.IPv4Address("255.255.255.255")):
        raise ValueError(f"{alamat} bukan alamat host yang dapat diblokir")
    return str(alamat)


def durasi_aman(durasi_menit):
    durasi = int(durasi_menit)
    if not 1 <= durasi <= MAKS_DURASI_MENIT:
        raise ValueError(f"durasi harus 1 sampai {MAKS_DURASI_MENIT} menit")
    return durasi


class ModulMitigasi:
    """
    Mengelola koneksi ke router dan penerapan aturan pemblokiran.

    Daftar IP yang sedang diblokir disimpan beserta waktu kedaluwarsanya,
    sehingga pencabutan otomatis dapat dilakukan. Bila `berkas_status`
    diberikan, daftar itu juga ditulis ke disk dan dimuat ulang saat
    modul dibuat, agar blokir di router tidak tertinggal selamanya setelah
    backend dijalankan ulang.
    """

    def __init__(self, host, username, password, port=22, dry_run=False, berkas_status=None,
                 key_file=None):
        """
        Parameter
        ---------
        dry_run : bool
            Bila True, perintah hanya dicatat di log tanpa benar-benar
            dikirim ke router. Berguna untuk pengujian tanpa risiko.
        berkas_status : str | Path | None
            Berkas JSON penyimpan daftar IP terblokir. Gunakan berkas
            berbeda untuk dry run dan router sungguhan.
        key_file : str | Path | None
            Kunci privat SSH untuk login ke router. Bila diisi, login memakai
            kunci ini (password tidak dipakai).
        """
        self.host = host
        self.username = username
        self.password = password
        self.key_file = str(key_file) if key_file else None
        self.port = port
        self.dry_run = dry_run
        self.berkas_status = berkas_status
        self.terblokir = {}  # {ip: waktu_kedaluwarsa}
        # Rincian eksekusi router terakhir (koreksi Pak Deni butir 27):
        # tahap = "dikirim" (perintah terkirim tetapi commit gagal),
        # "commit_ok" (commit berhasil, belum/tidak terverifikasi), atau
        # "terverifikasi" (aturan terbaca aktif di konfigurasi router)
        self.hasil_terakhir = None
        self._muat_status()

    # -------------------------------------------------------------- status

    def _muat_status(self):
        if not self.berkas_status or not os.path.exists(self.berkas_status):
            return
        try:
            with open(self.berkas_status, encoding="utf-8") as f:
                data = json.load(f)
            for ip, waktu in data.items():
                self.terblokir[ip_aman(ip)] = datetime.fromisoformat(waktu)
            log.info(f"{len(self.terblokir)} blokir dimuat dari {self.berkas_status}")
        except Exception as e:
            log.error(f"Berkas status {self.berkas_status} tidak dapat dibaca: {e}")

    def _simpan_status(self):
        if not self.berkas_status:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.berkas_status)), exist_ok=True)
            sementara = f"{self.berkas_status}.tmp"
            with open(sementara, "w", encoding="utf-8") as f:
                json.dump({ip: w.isoformat() for ip, w in self.terblokir.items()}, f, indent=1)
            os.replace(sementara, self.berkas_status)
        except Exception as e:
            log.error(f"Berkas status {self.berkas_status} gagal ditulis: {e}")

    def _saring_ip(self, ips):
        """IP valid dalam bentuk baku; yang tidak valid dicatat lalu dibuang."""
        hasil = []
        for ip in ips:
            try:
                hasil.append(ip_aman(ip))
            except ValueError as e:
                log.error(f"IP ditolak, tidak dikirim ke router: {ip!r} ({e})")
        return sorted(set(hasil))

    # ------------------------------------------------------------- koneksi

    def _koneksi(self):
        """Membuka koneksi SSH ke router."""
        if self.dry_run:
            return None

        try:
            from netmiko import ConnectHandler
        except ImportError:
            raise RuntimeError("Netmiko belum terpasang. Jalankan: pip install netmiko")

        if self.key_file:
            # Login dengan kunci SSH; tanpa agent dan tanpa fallback password
            kredensial = dict(use_keys=True, key_file=self.key_file, allow_agent=False)
        else:
            kredensial = dict(password=self.password)
        return ConnectHandler(
            device_type=DEVICE_TYPE,
            host=self.host,
            username=self.username,
            port=self.port,
            timeout=20,
            **kredensial,
        )

    def _baca_grup(self, koneksi, mode_konfigurasi=True):
        """Membaca anggota BLOKIR_NDR yang sedang aktif di konfigurasi router."""
        perintah = f"show configuration commands | match {FIREWALL_GROUP}"
        if mode_konfigurasi:
            perintah = "run " + perintah
        return anggota_grup(koneksi.send_command(perintah, expect_string=r"[$#]"))

    def _jalankan(self, perintah_list, deskripsi, periksa=None, harus_ada=True):
        """
        Mengirim sekumpulan perintah konfigurasi ke router.

        Mengembalikan True hanya bila commit berhasil. Keluaran commit dan
        save diperiksa, bukan dianggap berhasil begitu terkirim. Bila
        `periksa` berisi daftar IP, konfigurasi router dibaca ulang setelah
        commit untuk memastikan IP tersebut benar-benar ada (harus_ada=True)
        atau sudah hilang (harus_ada=False) dari BLOKIR_NDR. Rinciannya
        disimpan di self.hasil_terakhir. Kegagalan dicatat di log tetapi
        tidak menghentikan program, karena sistem deteksi harus tetap
        berjalan meski mitigasi gagal.
        """
        if self.dry_run:
            log.info(f"[DRY RUN] {deskripsi}")
            for p in perintah_list:
                log.info(f"[DRY RUN]   {p}")
            self.hasil_terakhir = {"tahap": "dry_run", "tersimpan": False,
                                   "terverifikasi": list(periksa) if periksa is not None else None}
            return True

        koneksi = None
        hasil = {"tahap": "dikirim", "tersimpan": False, "terverifikasi": None}
        self.hasil_terakhir = hasil
        try:
            koneksi = self._koneksi()
            keluaran = koneksi.send_config_set(perintah_list, exit_config_mode=False)
            log.debug(keluaran)
            if keluaran_gagal(keluaran):
                raise RuntimeError(f"perintah ditolak router: {keluaran.strip()[-200:]}")

            out_commit = koneksi.send_command("commit", expect_string=r"#")
            if keluaran_gagal(out_commit):
                # Perubahan yang gagal di-commit dibuang agar tidak tertinggal
                # di sesi konfigurasi berikutnya
                koneksi.send_command("exit discard", expect_string=r"[$#]")
                raise RuntimeError(f"commit gagal: {out_commit.strip()[-200:]}")
            hasil["tahap"] = "commit_ok"

            out_save = koneksi.send_command("save", expect_string=r"#")
            hasil["tersimpan"] = not keluaran_gagal(out_save)
            if not hasil["tersimpan"]:
                log.warning(f"Commit berhasil tetapi save gagal: {out_save.strip()[-200:]}")

            if periksa is not None:
                grup = self._baca_grup(koneksi)
                cocok = [ip for ip in periksa if (ip in grup) == harus_ada]
                hasil["terverifikasi"] = cocok
                if len(cocok) == len(periksa):
                    hasil["tahap"] = "terverifikasi"
                else:
                    log.error(f"{len(periksa) - len(cocok)} IP tidak terverifikasi setelah commit")

            koneksi.send_command("exit", expect_string=r"[$#]")
            log.info(f"Berhasil ({hasil['tahap']}): {deskripsi}")
            return True

        except Exception as e:
            log.error(f"Gagal {deskripsi} (tahap {hasil['tahap']}): {e}")
            return hasil["tahap"] != "dikirim"

        finally:
            if koneksi:
                try:
                    koneksi.disconnect()
                except Exception:
                    pass

    # ------------------------------------------------------------ persiapan

    def siapkan_firewall(self, interface="eth1"):
        """
        Menyiapkan struktur firewall di router.

        Perlu dijalankan sekali saja sebelum sistem mulai beroperasi.
        Membuat address-group kosong dan aturan yang menolak trafik dari
        anggota group tersebut.
        """
        perintah = [
            f"set firewall group address-group {FIREWALL_GROUP} description 'IP diblokir sistem NDR'",
            f"set firewall ipv4 input filter rule 10 action drop",
            f"set firewall ipv4 input filter rule 10 source group address-group {FIREWALL_GROUP}",
            f"set firewall ipv4 forward filter rule 10 action drop",
            f"set firewall ipv4 forward filter rule 10 source group address-group {FIREWALL_GROUP}",
        ]
        return self._jalankan(perintah, "menyiapkan struktur firewall")

    # ------------------------------------------------------------- mitigasi

    def blokir(self, ip, durasi_menit=15, alasan=""):
        """
        Memblokir satu alamat IP selama durasi tertentu.

        Pemblokiran bersifat sementara. Waktu kedaluwarsa dicatat agar
        modul dapat mencabutnya secara otomatis melalui cabut_kedaluwarsa().
        IP atau durasi yang tidak valid ditolak (False) tanpa menghubungi router.
        """
        try:
            ip = ip_aman(ip)
            durasi_menit = durasi_aman(durasi_menit)
        except ValueError as e:
            log.error(f"Blokir ditolak: {e}")
            return False

        if ip in self.terblokir:
            log.info(f"{ip} sudah dalam daftar blokir, memperpanjang durasi")

        perintah = [
            f"set firewall group address-group {FIREWALL_GROUP} address {ip}",
        ]

        deskripsi = f"memblokir {ip} selama {durasi_menit} menit"
        if alasan:
            deskripsi += f" ({alasan})"

        self.hasil_terakhir = None
        berhasil = self._jalankan(perintah, deskripsi, periksa=[ip])
        berhasil = berhasil and ip in self._terverifikasi([ip])

        if berhasil:
            self.terblokir[ip] = datetime.now() + timedelta(minutes=durasi_menit)
            self._simpan_status()

        return berhasil

    def cabut(self, ip):
        """Mencabut pemblokiran satu alamat IP."""
        try:
            ip = ip_aman(ip)
        except ValueError as e:
            log.error(f"Cabut ditolak: {e}")
            return False

        perintah = [
            f"delete firewall group address-group {FIREWALL_GROUP} address {ip}",
        ]

        self.hasil_terakhir = None
        berhasil = self._jalankan(perintah, f"mencabut blokir {ip}", periksa=[ip], harus_ada=False)
        berhasil = berhasil and ip in self._terverifikasi([ip])

        if berhasil:
            self.terblokir.pop(ip, None)
            self._simpan_status()

        return berhasil

    def blokir_banyak(self, ips, durasi_menit=15, alasan=""):
        """
        Memblokir banyak alamat IP dalam SATU sesi SSH dan satu commit.

        Dipakai untuk flood dengan sumber palsu (bisa ratusan IP) agar tidak
        membuka satu sesi per IP. IP yang sudah terblokir tidak dikirim ulang
        ke router; waktu kedaluwarsanya cukup diperpanjang.

        Mengembalikan daftar IP yang kini terblokir (kosong bila gagal).
        IP yang tidak valid dibuang (dicatat di log), sisanya tetap diproses.
        """
        try:
            durasi_menit = durasi_aman(durasi_menit)
        except ValueError as e:
            log.error(f"Blokir ditolak: {e}")
            return []
        ips = self._saring_ip(ips)
        if not ips:
            return []

        kedaluwarsa = datetime.now() + timedelta(minutes=durasi_menit)
        baru = [ip for ip in ips if ip not in self.terblokir]

        if baru:
            perintah = [
                f"set firewall group address-group {FIREWALL_GROUP} address {ip}"
                for ip in baru
            ]
            deskripsi = f"memblokir {len(baru)} IP dalam satu sesi selama {durasi_menit} menit"
            if alasan:
                deskripsi += f" ({alasan})"
            self.hasil_terakhir = None
            if not self._jalankan(perintah, deskripsi, periksa=baru):
                return []
            # IP yang tidak terbaca di router setelah commit tidak dianggap
            # terblokir (butir 27)
            gagal = set(baru) - self._terverifikasi(baru)
            if gagal:
                log.error(f"{len(gagal)} IP tidak terverifikasi aktif di router: {sorted(gagal)}")
                ips = [ip for ip in ips if ip not in gagal]

        diperpanjang = len(ips) - len(baru)
        if diperpanjang > 0:
            log.info(f"{diperpanjang} IP sudah terblokir, durasi diperpanjang")

        for ip in ips:
            self.terblokir[ip] = kedaluwarsa
        self._simpan_status()
        return ips

    def cabut_banyak(self, ips):
        """
        Mencabut pemblokiran banyak alamat IP dalam satu sesi SSH.
        Mengembalikan daftar IP yang berhasil dicabut (kosong bila gagal).
        """
        ips = self._saring_ip(ips)
        if not ips:
            return []

        perintah = [
            f"delete firewall group address-group {FIREWALL_GROUP} address {ip}"
            for ip in ips
        ]
        self.hasil_terakhir = None
        if not self._jalankan(perintah, f"mencabut blokir {len(ips)} IP dalam satu sesi",
                              periksa=ips, harus_ada=False):
            return []
        ips = sorted(self._terverifikasi(ips))

        for ip in ips:
            self.terblokir.pop(ip, None)
        self._simpan_status()
        return ips

    def cabut_kedaluwarsa(self):
        """
        Mencabut seluruh pemblokiran yang sudah melewati waktu kedaluwarsa.

        Dipanggil secara berkala oleh backend, misalnya setiap satu menit.
        Seluruh IP kedaluwarsa dicabut dalam satu sesi. Mengembalikan daftar
        IP yang berhasil dicabut.
        """
        sekarang = datetime.now()
        kedaluwarsa = [ip for ip, waktu in self.terblokir.items() if waktu <= sekarang]

        dicabut = self.cabut_banyak(kedaluwarsa)
        if dicabut:
            log.info(f"{len(dicabut)} blokir dicabut otomatis karena kedaluwarsa")

        return dicabut

    def _terverifikasi(self, ips):
        """
        IP yang dinyatakan berhasil oleh eksekusi terakhir. Bila router tidak
        dibaca ulang (dry run atau _jalankan diganti pada pengujian), seluruh
        IP dianggap berhasil.
        """
        h = self.hasil_terakhir
        if not h or h.get("terverifikasi") is None:
            return set(ips)
        return set(h["terverifikasi"]) & set(ips)

    def sinkronkan_router(self, durasi_menit=15):
        """
        Menyamakan daftar blokir backend dengan BLOKIR_NDR di router (butir 28).
        Dipanggil saat backend dijalankan ulang tanpa me-restart VyOS:
            - IP yang ada di router tetapi tidak di daftar backend ditambahkan
              dengan kedaluwarsa baru (durasi_menit), sehingga tetap dicabut
              otomatis dan tidak tertinggal selamanya
            - IP yang ada di daftar backend tetapi sudah tidak ada di router
              dihapus dari daftar
        Mengembalikan ringkasan {"ditambah", "dihapus", "router"}; bila router
        tidak terbaca, None dan daftar backend tidak diubah.
        """
        if self.dry_run:
            log.info("[DRY RUN] Sinkronisasi router dilewati")
            return {"ditambah": [], "dihapus": [], "router": sorted(self.terblokir), "dry_run": True}
        koneksi = None
        try:
            koneksi = self._koneksi()
            grup = self._baca_grup(koneksi, mode_konfigurasi=False)
        except Exception as e:
            log.error(f"Sinkronisasi router gagal, daftar backend tidak diubah: {e}")
            return None
        finally:
            if koneksi:
                try:
                    koneksi.disconnect()
                except Exception:
                    pass

        ditambah, dihapus = [], []
        kedaluwarsa = datetime.now() + timedelta(minutes=durasi_aman(durasi_menit))
        for ip in sorted(grup):
            try:
                ip = ip_aman(ip)
            except ValueError:
                continue
            if ip not in self.terblokir:
                self.terblokir[ip] = kedaluwarsa
                ditambah.append(ip)
        for ip in sorted(set(self.terblokir) - grup):
            self.terblokir.pop(ip)
            dihapus.append(ip)
        self._simpan_status()
        log.info(f"Sinkronisasi router: {len(grup)} IP di BLOKIR_NDR, "
                 f"{len(ditambah)} ditambahkan, {len(dihapus)} dihapus dari daftar backend")
        return {"ditambah": ditambah, "dihapus": dihapus, "router": sorted(grup)}

    def daftar_terblokir(self):
        """Mengembalikan daftar IP terblokir beserta sisa waktunya."""
        sekarang = datetime.now()
        hasil = []
        for ip, kedaluwarsa in self.terblokir.items():
            sisa = (kedaluwarsa - sekarang).total_seconds()
            hasil.append(
                {
                    "ip": ip,
                    "kedaluwarsa": kedaluwarsa.isoformat(),
                    "sisa_detik": max(0, int(sisa)),
                }
            )
        return hasil

    # ------------------------------------------------------------ verifikasi

    def uji_koneksi(self):
        """Menguji apakah router dapat dijangkau melalui SSH."""
        if self.dry_run:
            log.info("[DRY RUN] Uji koneksi dilewati")
            return True

        try:
            koneksi = self._koneksi()
            hasil = koneksi.send_command("show version")
            koneksi.disconnect()
            log.info(f"Koneksi ke {self.host} berhasil")
            return True
        except Exception as e:
            log.error(f"Koneksi ke {self.host} gagal: {e}")
            return False


# ---------------------------------------------------------- perintah Cisco

# Disimpan sebagai referensi bila penelitian kembali menggunakan Cisco IOS.
# Untuk memakainya, ubah DEVICE_TYPE menjadi 'cisco_ios' dan sesuaikan
# metode blokir() serta cabut() agar menggunakan perintah di bawah ini.
CISCO_COMMANDS = {
    "blokir": [
        "ip access-list extended BLOKIR_NDR",
        " deny ip host {ip} any",
        " permit ip any any",
    ],
    "cabut": [
        "ip access-list extended BLOKIR_NDR",
        " no deny ip host {ip} any",
    ],
}


if __name__ == "__main__":
    # Pengujian dalam mode dry run, tidak mengirim apa pun ke router
    print("Uji modul mitigasi dalam mode DRY RUN\n")

    m = ModulMitigasi(
        host="192.168.10.1",
        username="vyos",
        password="vyos",
        dry_run=True,
    )

    m.uji_koneksi()
    print()
    m.siapkan_firewall()
    print()
    m.blokir("192.168.20.10", durasi_menit=15, alasan="DDoS Flood")
    print()
    m.blokir("192.168.20.55", durasi_menit=5, alasan="Port Scanning")
    print()

    print("Daftar IP terblokir:")
    for entri in m.daftar_terblokir():
        print(f"  {entri['ip']}  sisa {entri['sisa_detik']} detik")
    print()

    m.cabut("192.168.20.10")
