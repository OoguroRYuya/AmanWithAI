"use client";

import { useState } from "react";

import * as api from "@/lib/api";

interface Props {
  dikonfigurasi: boolean;
  onBerhasil: () => void;
}

export default function Masuk({ dikonfigurasi, onBerhasil }: Props) {
  const [password, setPassword] = useState("");
  const [galat, setGalat] = useState<string | null>(null);
  const [mengirim, setMengirim] = useState(false);

  async function kirim(e: React.FormEvent) {
    e.preventDefault();
    setMengirim(true);
    setGalat(null);
    try {
      await api.masuk(password);
      setPassword("");
      onBerhasil();
    } catch (err) {
      setGalat((err as Error).message);
    } finally {
      setMengirim(false);
    }
  }

  return (
    <main className="layar-masuk">
      <form className="kartu kartu-masuk" onSubmit={kirim}>
        <h1>NDR Kampus</h1>
        <p className="redup">Masuk sebagai admin untuk memantau dan memitigasi serangan.</p>
        {dikonfigurasi ? (
          <>
            <label htmlFor="password">Password admin</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              autoFocus
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={galat ? "salah" : undefined}
              aria-describedby={galat ? "galat-masuk" : undefined}
            />
            {galat && (
              <p id="galat-masuk" className="pesan-salah" role="alert">
                {galat}
              </p>
            )}
            <button className="tombol utama" type="submit" disabled={mengirim || !password}>
              {mengirim ? "Memeriksa…" : "Masuk"}
            </button>
          </>
        ) : (
          <p className="pesan-salah" role="alert">
            Login admin belum dikonfigurasi. Jalankan <code>python keamanan.py</code> di folder backend, isi
            ADMIN_PASSWORD_HASH di backend/.env, lalu jalankan ulang backend.
          </p>
        )}
      </form>
    </main>
  );
}
