"use client";

import { useState } from "react";

import { fAngka, fPersen, fTanggalJam } from "@/lib/format";
import type { Insiden } from "@/lib/tipe";

import { LencanaKelas } from "./Lencana";

interface Props {
  menunggu: Insiden[];
  ambangSedang?: number;
  ambangBlokir?: number;
  onSetujui: (id: number) => Promise<boolean>;
  onTolak: (id: number) => Promise<boolean>;
  onPilih: (id: number) => void;
}

export default function AntreanPersetujuan({ menunggu, ambangSedang, ambangBlokir, onSetujui, onTolak, onPilih }: Props) {
  // id insiden yang sedang diproses, supaya tombolnya tidak diklik dua kali
  const [proses, setProses] = useState<Set<number>>(new Set());

  const jalankan = async (id: number, fn: (id: number) => Promise<boolean>) => {
    setProses((p) => new Set(p).add(id));
    await fn(id);
    setProses((p) => {
      const baru = new Set(p);
      baru.delete(id);
      return baru;
    });
  };

  return (
    <section className="kartu">
      <div className="kartu-kepala">
        <div>
          <h2>Antrean persetujuan</h2>
          <p className="redup">
            Sumber lolos gerbang rasio dengan confidence {ambangSedang?.toFixed(2) ?? "–"}–
            {ambangBlokir?.toFixed(2) ?? "–"}; blokir hanya setelah disetujui admin
          </p>
        </div>
        <span className="hitungan">{fAngka(menunggu.length)}</span>
      </div>

      {menunggu.length === 0 ? (
        <div className="kosong">Tidak ada insiden yang menunggu persetujuan</div>
      ) : (
        <ul className="daftar-antrean">
          {menunggu.map((i) => {
            const sibuk = proses.has(i.id);
            return (
              <li key={i.id}>
                <button className="info-antrean" onClick={() => onPilih(i.id)}>
                  <span className="baris-lencana">
                    <span className="redup">#{i.id}</span>
                    <LencanaKelas kelas={i.kelas} />
                    <span className="mono">{i.kunci}</span>
                  </span>
                  <span className="redup">
                    {fTanggalJam(i.window)} · {fAngka(i.ip_kandidat.length)} IP kandidat · conf {fPersen(i.confidence)}
                  </span>
                </button>
                <div className="tombol-grup">
                  <button className="tombol utama" disabled={sibuk} onClick={() => jalankan(i.id, onSetujui)}>
                    Setujui
                  </button>
                  <button className="tombol" disabled={sibuk} onClick={() => jalankan(i.id, onTolak)}>
                    Tolak
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
