"use client";

import { useEffect, useMemo, useState } from "react";

import { IPV4, fAngka, fHitungMundur, urutIp } from "@/lib/format";
import type { Terblokir } from "@/lib/tipe";

interface Props {
  terblokir: Terblokir[];
  terblokirPada: number;
  allowlist?: string[];
  onCabut: (ip: string) => Promise<boolean>;
  onBlokir: (ip: string, durasi: number) => Promise<boolean>;
}

export default function DaftarTerblokir({ terblokir, terblokirPada, allowlist = [], onCabut, onBlokir }: Props) {
  // Detak lokal 1 detik hanya untuk hitung mundur; daftarnya sendiri
  // diperbarui dari REST setiap ada pesan mitigasi
  const [sekarang, setSekarang] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setSekarang(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const [cari, setCari] = useState("");
  const [ip, setIp] = useState("");
  const [durasi, setDurasi] = useState(15);
  const [kirim, setKirim] = useState(false);
  const [dicabut, setDicabut] = useState<Set<string>>(new Set());

  const berlalu = Math.max(0, Math.floor((sekarang - terblokirPada) / 1000));
  const daftar = useMemo(
    () => terblokir.filter((t) => t.ip.includes(cari.trim())).sort((a, b) => urutIp(a.ip, b.ip)),
    [terblokir, cari],
  );

  const ipValid = IPV4.test(ip.trim());
  const diAllowlist = allowlist.includes(ip.trim());

  const blokir = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ipValid || diAllowlist || durasi < 1) return;
    setKirim(true);
    if (await onBlokir(ip.trim(), durasi)) setIp("");
    setKirim(false);
  };

  const cabut = async (alamat: string) => {
    setDicabut((s) => new Set(s).add(alamat));
    await onCabut(alamat);
    setDicabut((s) => {
      const baru = new Set(s);
      baru.delete(alamat);
      return baru;
    });
  };

  return (
    <section className="kartu">
      <div className="kartu-kepala">
        <div>
          <h2>IP terblokir</h2>
          <p className="redup">Dicabut otomatis saat durasi habis (diperiksa backend tiap menit)</p>
        </div>
        <span className="hitungan">{fAngka(terblokir.length)}</span>
      </div>

      <form className="form-blokir" onSubmit={blokir}>
        <input
          aria-label="Alamat IP"
          placeholder="IP, mis. 192.168.20.99"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          className={ip && (!ipValid || diAllowlist) ? "salah" : ""}
        />
        <input
          aria-label="Durasi (menit)"
          type="number"
          min={1}
          max={1440}
          value={durasi}
          onChange={(e) => setDurasi(Number(e.target.value))}
        />
        <span className="redup">menit</span>
        <button className="tombol bahaya" disabled={!ipValid || diAllowlist || kirim}>
          Blokir
        </button>
      </form>
      {ip && !ipValid && <p className="pesan-salah">Format IPv4 tidak valid</p>}
      {diAllowlist && <p className="pesan-salah">IP ada di allowlist dan tidak boleh diblokir</p>}

      {terblokir.length > 8 && (
        <input className="cari" placeholder="Cari IP…" value={cari} onChange={(e) => setCari(e.target.value)} />
      )}

      {daftar.length === 0 ? (
        <div className="kosong">{terblokir.length ? "Tidak ada IP yang cocok" : "Belum ada IP terblokir"}</div>
      ) : (
        <ul className="daftar-blokir gulir">
          {daftar.map((t) => {
            const sisa = Math.max(0, t.sisa_detik - berlalu);
            return (
              <li key={t.ip}>
                <span className="mono">{t.ip}</span>
                <span className={`mundur ${sisa < 60 ? "hampir" : ""}`} title={`Kedaluwarsa ${t.kedaluwarsa}`}>
                  {fHitungMundur(sisa)}
                </span>
                <button className="tombol kecil" disabled={dicabut.has(t.ip)} onClick={() => cabut(t.ip)}>
                  Cabut
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
