"use client";

import { useMemo, useState } from "react";

import AntreanPersetujuan from "@/components/AntreanPersetujuan";
import BarisStatus from "@/components/BarisStatus";
import DaftarTerblokir from "@/components/DaftarTerblokir";
import DetailInsiden from "@/components/DetailInsiden";
import GrafikTrafik from "@/components/GrafikTrafik";
import TabelInsiden from "@/components/TabelInsiden";
import { useDashboard } from "@/lib/useDashboard";

export default function Dashboard() {
  const { keadaan, toasts, aksi } = useDashboard();
  const [dipilih, setDipilih] = useState<number | null>(null);

  const insiden = useMemo(() => Object.values(keadaan.insiden).sort((a, b) => b.id - a.id), [keadaan.insiden]);
  // Antrean diturunkan dari insiden, jadi insiden yang dikirim ulang dengan
  // status disetujui/ditolak otomatis keluar dari antrean
  const menunggu = useMemo(
    () => insiden.filter((i) => i.status === "menunggu_persetujuan").sort((a, b) => a.id - b.id),
    [insiden],
  );
  // Panel detail mengikuti versi terbaru insiden yang sama
  const insidenDipilih = dipilih != null ? keadaan.insiden[dipilih] : undefined;
  const s = keadaan.status;

  return (
    <main className="halaman">
      <BarisStatus
        status={s}
        koneksi={keadaan.koneksi}
        pesanTerakhir={keadaan.pesanTerakhir}
        jumlahMenunggu={menunggu.length}
        jumlahTerblokir={keadaan.terblokir.length}
      />

      <GrafikTrafik trafik={keadaan.trafik} />

      <div className="dua-kolom">
        <AntreanPersetujuan
          menunggu={menunggu}
          ambangSedang={s?.ambang_sedang}
          ambangBlokir={s?.ambang_conf_blokir}
          onSetujui={aksi.setujui}
          onTolak={aksi.tolak}
          onPilih={setDipilih}
        />
        <DaftarTerblokir
          terblokir={keadaan.terblokir}
          terblokirPada={keadaan.terblokirPada}
          allowlist={s?.allowlist}
          onCabut={aksi.cabut}
          onBlokir={aksi.blokir}
        />
      </div>

      <TabelInsiden insiden={insiden} onPilih={setDipilih} />

      {insidenDipilih && (
        <DetailInsiden
          key={insidenDipilih.id}
          insiden={insidenDipilih}
          onTutup={() => setDipilih(null)}
          onSetujui={aksi.setujui}
          onTolak={aksi.tolak}
        />
      )}

      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.jenis}`}>
            {t.teks}
          </div>
        ))}
      </div>
    </main>
  );
}
