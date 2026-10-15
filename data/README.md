# Data

Folder ini **tidak** menyimpan dataset penuh (ukurannya besar dan di-`.gitignore`).

- `sample/` — potongan kecil tiap kelas untuk mencoba pipeline tanpa menjalankan lab.
- **Dataset penuh** diterbitkan lewat GitHub Releases (atau Zenodo untuk DOI yang bisa disitasi di skripsi).

## Cara meregenerasi dari lab
1. Jalankan satu sesi (lihat `../docs/eksperimen2.md`).
2. Ekspor flow dengan TCP flags:
   ```
   nfdump -R /data/nfcapd -o "fmt:%ts,%td,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt" > flows_sesiN.csv
   ```
3. Label: `python ../ml/label_per_window.py flows_sesiN.csv -o dataset_sesiN.csv`

Konvensi penamaan: `dataset_sesi1.csv`, `dataset_sesi2.csv`, … (satu file = satu sesi).
