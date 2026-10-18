"""
ws.py
=====
Pengelola koneksi WebSocket untuk umpan real-time dashboard (fase 3).

Setiap hasil pipeline (trafik per jendela, insiden, aksi mitigasi) disiarkan
ke seluruh klien yang tersambung ke /ws. Disimpan di memori saja, tanpa
broker eksternal.

Seluruh pengiriman ke soket melewati satu kunci, sehingga pesan tidak
pernah dikirim bersamaan ke soket yang sama dan snapshot awal klien baru
tidak tersisip di tengah siaran.
"""

import asyncio
import json
import logging

from fastapi import WebSocket
from fastapi.encoders import jsonable_encoder

log = logging.getLogger("ndr.ws")

# Klien yang tidak menerima pesan dalam batas ini dianggap mati, supaya
# satu klien macet tidak menahan pekerja antrean
BATAS_KIRIM_DETIK = 5


class KoneksiWS:
    def __init__(self):
        self.aktif: set = set()
        self._kunci = asyncio.Lock()

    async def connect(self, ws: WebSocket, pesan_awal=None):
        """
        Menerima koneksi, mengirim pesan awal (mis. snapshot), lalu
        mendaftarkannya. `pesan_awal` adalah fungsi async tanpa argumen yang
        dipanggil di dalam kunci, sehingga tidak ada siaran yang terlewat
        antara snapshot dan pendaftaran.
        """
        await ws.accept()
        async with self._kunci:
            if pesan_awal is not None:
                await ws.send_text(_ke_json(await pesan_awal()))
            self.aktif.add(ws)

    def disconnect(self, ws: WebSocket):
        self.aktif.discard(ws)

    async def broadcast(self, pesan: dict):
        """Mengirim pesan ke semua klien; klien yang gagal dikirimi dibuang."""
        if not self.aktif:
            return
        teks = _ke_json(pesan)
        async with self._kunci:
            klien = list(self.aktif)
            hasil = await asyncio.gather(
                *(asyncio.wait_for(ws.send_text(teks), BATAS_KIRIM_DETIK) for ws in klien),
                return_exceptions=True,
            )
            for ws, h in zip(klien, hasil):
                if isinstance(h, BaseException):
                    log.info(f"Klien WebSocket dilepas ({type(h).__name__})")
                    self.aktif.discard(ws)


def _ke_json(pesan):
    return json.dumps(jsonable_encoder(pesan))
