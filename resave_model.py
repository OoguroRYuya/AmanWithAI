import sys; sys.path.insert(0, "ml")
import joblib, __main__
from pathlib import Path
from model_wrapper import XGBWrapper
if not hasattr(__main__, "XGBWrapper"):
    __main__.XGBWrapper = XGBWrapper   # shim muat pickle lama utk ambil .model
MDIR = Path("ml/model")
FITUR = ["duration","packet_count","byte_count","dst_port_count","avg_packet_size",
         "flow_rate","syn_flag_count","unique_src_ip_per_dst","protocol","mean_packet_interval"]
old = joblib.load(MDIR/"model_terbaik.pkl")
labels = list(joblib.load(MDIR/"label_kelas.pkl"))
assert hasattr(old, "model"), "bukan XGBWrapper (mungkin RF lama)"
peta = {k: i for i, k in enumerate(labels)}
baru = XGBWrapper(old.model, peta, FITUR)
assert list(baru.feature_names_in_) == FITUR
assert list(baru.classes_) == labels, (list(baru.classes_), labels)
joblib.dump(baru, MDIR/"model_terbaik.pkl")
print("RESAVE OK ->", type(baru).__module__ + "." + type(baru).__name__)
print("classes_:", list(baru.classes_))
