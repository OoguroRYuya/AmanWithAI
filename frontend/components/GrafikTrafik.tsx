"use client";

import { useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { LABEL_KELAS, fAngka, fJam } from "@/lib/format";
import { KELAS, type Kelas, type Trafik } from "@/lib/tipe";

const SERANGAN: Kelas[] = ["ddos_flood", "port_scanning"];

interface Titik {
  window: string;
  normal: number;
  ddos_flood: number;
  port_scanning: number;
  backscatter: number;
  insiden: number;
}

const ringkas = (n: number) =>
  n >= 1000 ? `${(n / 1000).toLocaleString("id-ID", { maximumFractionDigits: 1 })}K` : String(n);

function Tip({ active, payload }: { active?: boolean; payload?: { payload: Titik }[] }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="tooltip">
      <div className="tooltip-judul">Jendela {fJam(d.window)}</div>
      {[...KELAS].reverse().map((k) => (
        <div key={k} className="tooltip-baris">
          <span className={`kunci-seri seri-${k}`} aria-hidden />
          <span>{LABEL_KELAS[k]}</span>
          <strong>{fAngka(d[k])}</strong>
        </div>
      ))}
      <div className="tooltip-kaki">
        <span>{fAngka(d.insiden)} insiden</span>
        <span>{fAngka(d.backscatter)} flow backscatter dibuang</span>
      </div>
    </div>
  );
}

export default function GrafikTrafik({ trafik }: { trafik: Record<string, Trafik> }) {
  const [tampilNormal, setTampilNormal] = useState(true);

  const data: Titik[] = useMemo(
    () =>
      Object.values(trafik)
        .sort((a, b) => a.window.localeCompare(b.window))
        .map((t) => ({
          window: t.window,
          normal: t.per_kelas.normal ?? 0,
          ddos_flood: t.per_kelas.ddos_flood ?? 0,
          port_scanning: t.per_kelas.port_scanning ?? 0,
          backscatter: t.jumlah_backscatter,
          insiden: t.jumlah_insiden,
        })),
    [trafik],
  );

  const terakhir = data[data.length - 1];
  const seri = tampilNormal ? KELAS : SERANGAN;

  return (
    <section className="kartu">
      <div className="kartu-kepala">
        <div>
          <h2>Trafik per jendela 60 detik</h2>
          <p className="redup">Jumlah flow per kelas hasil klasifikasi, {data.length} jendela terakhir</p>
        </div>
        <label className="sakelar">
          <input type="checkbox" checked={tampilNormal} onChange={(e) => setTampilNormal(e.target.checked)} />
          Tampilkan normal
        </label>
      </div>

      {/* Legenda selalu ada; angka di sampingnya milik jendela terakhir saja,
          jadi jendelanya disebut agar tidak terbaca sebagai total */}
      <ul className="legenda">
        {terakhir && <li className="legenda-jendela">Jendela terakhir {fJam(terakhir.window)}</li>}
        {KELAS.map((k) => (
          <li key={k} className={seri.includes(k) ? "" : "nonaktif"}>
            <span className={`kunci-seri seri-${k}`} aria-hidden />
            {LABEL_KELAS[k]}
            {terakhir && <strong>{fAngka(terakhir[k])}</strong>}
          </li>
        ))}
      </ul>

      <div className="grafik">
        {data.length === 0 ? (
          <div className="kosong">Menunggu jendela trafik pertama…</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }} barCategoryGap="20%">
              <CartesianGrid vertical={false} stroke="var(--color-rule)" />
              <XAxis
                dataKey="window"
                tickFormatter={(w: string) => fJam(w)}
                tick={{ fill: "var(--color-muted)", fontSize: 12, fontFamily: "var(--font-outlier)" }}
                axisLine={{ stroke: "var(--color-rule-2)" }}
                tickLine={false}
                minTickGap={24}
              />
              <YAxis
                tickFormatter={ringkas}
                tick={{ fill: "var(--color-muted)", fontSize: 12, fontFamily: "var(--font-outlier)" }}
                axisLine={false}
                tickLine={false}
                width={44}
                tickCount={4}
              />
              <Tooltip content={<Tip />} cursor={{ fill: "var(--color-paper-3)" }} isAnimationActive={false} />
              {seri.map((k, i) => (
                <Bar
                  key={k}
                  dataKey={k}
                  name={LABEL_KELAS[k]}
                  stackId="kelas"
                  fill={`var(--seri-${k})`}
                  // celah 2px warna permukaan antar segmen tumpukan
                  stroke="var(--color-paper-2)"
                  strokeWidth={2}
                  maxBarSize={24}
                  radius={i === seri.length - 1 ? [2, 2, 0, 0] : 0}
                  isAnimationActive={false}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <details className="tabel-data">
        <summary>Lihat sebagai tabel</summary>
        <div className="gulir">
          <table>
            <thead>
              <tr>
                <th>Jendela</th>
                {KELAS.map((k) => (
                  <th key={k} className="angka">
                    {LABEL_KELAS[k]}
                  </th>
                ))}
                <th className="angka">Backscatter</th>
                <th className="angka">Insiden</th>
              </tr>
            </thead>
            <tbody>
              {[...data].reverse().map((d) => (
                <tr key={d.window}>
                  <td>{fJam(d.window)}</td>
                  {KELAS.map((k) => (
                    <td key={k} className="angka">
                      {fAngka(d[k])}
                    </td>
                  ))}
                  <td className="angka">{fAngka(d.backscatter)}</td>
                  <td className="angka">{fAngka(d.insiden)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}
