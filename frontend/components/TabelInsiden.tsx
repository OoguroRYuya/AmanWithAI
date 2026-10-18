"use client";

import { useState } from "react";

import { fAngka, fPersen, fTanggalJam } from "@/lib/format";
import type { Insiden, StatusInsiden } from "@/lib/tipe";

import { LencanaKelas, LencanaStatus } from "./Lencana";

const TAMPIL_AWAL = 100;

interface Props {
  insiden: Insiden[]; // sudah terurut terbaru di depan
  onPilih: (id: number) => void;
}

const FILTER: { nilai: StatusInsiden | "semua"; label: string }[] = [
  { nilai: "semua", label: "Semua" },
  { nilai: "blokir_otomatis", label: "Blokir otomatis" },
  { nilai: "menunggu_persetujuan", label: "Menunggu" },
  { nilai: "disetujui", label: "Disetujui" },
  { nilai: "ditolak", label: "Ditolak" },
  { nilai: "dicatat", label: "Dicatat" },
];

export default function TabelInsiden({ insiden, onPilih }: Props) {
  const [filter, setFilter] = useState<StatusInsiden | "semua">("semua");
  const [batas, setBatas] = useState(TAMPIL_AWAL);

  const tersaring = filter === "semua" ? insiden : insiden.filter((i) => i.status === filter);
  const tampil = tersaring.slice(0, batas);

  return (
    <section className="kartu">
      <div className="kartu-kepala">
        <div>
          <h2>Insiden</h2>
          <p className="redup">
            {fAngka(insiden.length)} insiden · klik baris untuk melihat narasi saran dan evaluasi sumber
          </p>
        </div>
        <select value={filter} onChange={(e) => setFilter(e.target.value as StatusInsiden | "semua")}>
          {FILTER.map((f) => (
            <option key={f.nilai} value={f.nilai}>
              {f.label}
            </option>
          ))}
        </select>
      </div>

      <div className="gulir tabel-insiden">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Jendela</th>
              <th>Kelas</th>
              <th>Kunci</th>
              <th className="angka">Flow</th>
              <th className="angka">Sumber</th>
              <th className="angka">Confidence</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {tampil.length === 0 && (
              <tr>
                <td colSpan={8} className="kosong">
                  Belum ada insiden
                </td>
              </tr>
            )}
            {tampil.map((i) => (
              <tr
                key={i.id}
                className="bisa-klik"
                tabIndex={0}
                onClick={() => onPilih(i.id)}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onPilih(i.id)}
              >
                <td className="redup">{i.id}</td>
                <td>{fTanggalJam(i.window)}</td>
                <td>
                  <LencanaKelas kelas={i.kelas} />
                </td>
                <td className="mono">{i.kunci}</td>
                <td className="angka">{fAngka(i.jumlah_flow)}</td>
                <td className="angka">{fAngka(i.jumlah_sumber)}</td>
                <td className="angka">{fPersen(i.confidence)}</td>
                <td>
                  <LencanaStatus status={i.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {tersaring.length > batas && (
        <button className="tombol-teks" onClick={() => setBatas((b) => b + TAMPIL_AWAL)}>
          Tampilkan {Math.min(TAMPIL_AWAL, tersaring.length - batas)} lagi
        </button>
      )}
    </section>
  );
}
