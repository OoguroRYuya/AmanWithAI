import pandas as pd
import pytest

import ekstraksi_fitur as ef
from conftest import FIXTURE_CSV, FIXTURE_GOLDEN


def test_tanpa_sertakan_ip_identik_dengan_golden(tmp_path):
    """Keluaran default harus sama persis (byte demi byte) dengan versi sebelum fase 2."""
    keluaran = tmp_path / "fitur.csv"
    ef.ekstrak(FIXTURE_CSV).to_csv(keluaran, index=False)
    assert keluaran.read_bytes() == FIXTURE_GOLDEN.read_bytes()


def test_sertakan_ip_false_eksplisit_identik():
    a = ef.ekstrak(FIXTURE_CSV)
    b = ef.ekstrak(FIXTURE_CSV, sertakan_ip=False)
    pd.testing.assert_frame_equal(a, b)
    assert list(a.columns) == ef.FEATURE_COLUMNS


def test_sertakan_ip_menambah_kolom_tanpa_mengubah_fitur():
    dasar = ef.ekstrak(FIXTURE_CSV)
    lengkap = ef.ekstrak(FIXTURE_CSV, sertakan_ip=True)

    assert list(lengkap.columns) == ef.FEATURE_COLUMNS + ["sa", "da", "dp", "window"]
    pd.testing.assert_frame_equal(lengkap[ef.FEATURE_COLUMNS], dasar)


def test_sertakan_ip_urutan_baris_cocok_dengan_csv():
    lengkap = ef.ekstrak(FIXTURE_CSV, sertakan_ip=True)
    mentah = ef.normalisasi_kolom(ef.baca_nfdump_csv(FIXTURE_CSV))

    assert len(lengkap) == len(mentah)
    assert (lengkap["sa"].values == mentah["sa"].astype(str).values).all()
    assert (lengkap["da"].values == mentah["da"].astype(str).values).all()
    # dp ICMP ditulis nfdump sebagai "tipe.kode" (mis. 3.3); ekstraksi
    # mengubahnya ke bilangan bulat
    dp = pd.to_numeric(mentah["dp"], errors="coerce").fillna(0).astype("int64")
    assert (lengkap["dp"].values == dp.values).all()
    # potongan fixture = satu jendela 60 detik
    assert lengkap["window"].nunique() == 1


def test_estimasi_paksa_mengganti_packet_count():
    asli = ef.ekstrak(FIXTURE_CSV)
    paksa = ef.ekstrak(FIXTURE_CSV, estimasi_paksa=True)

    berisi = asli["byte_count"] > 0
    harapan = (asli["byte_count"] / ef.ESTIMASI_UKURAN_PAKET).round().clip(lower=1)
    assert (paksa.loc[berisi, "packet_count"] == harapan[berisi]).all()
    # fitur yang tidak bergantung pada packet_count tidak berubah
    for kolom in ("duration", "byte_count", "dst_port_count", "unique_src_ip_per_dst"):
        pd.testing.assert_series_equal(paksa[kolom], asli[kolom])
    assert not paksa["packet_count"].equals(asli["packet_count"])


@pytest.mark.parametrize("sertakan_ip", [False, True])
def test_label_tetap_kolom_terakhir(sertakan_ip):
    df = ef.ekstrak(FIXTURE_CSV, label="normal", sertakan_ip=sertakan_ip)
    assert df.columns[-1] == "label"
