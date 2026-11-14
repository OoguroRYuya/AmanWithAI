"""Pembungkus model XGBoost agar berperilaku seperti estimator scikit-learn.

Didefinisikan di modul tersendiri (bukan di latih_model.py yang berjalan sebagai
__main__) supaya objek yang di-pickle bisa dimuat ulang oleh backend (uvicorn)
maupun pytest tanpa error "__main__ has no attribute 'XGBWrapper'".
"""

import numpy as np


class XGBWrapper:
    """Membungkus XGBClassifier (dilatih pada label integer) supaya predict()
    mengembalikan label teks dan menyediakan classes_ & feature_names_in_
    seperti estimator sklearn (dipakai/diperiksa backend)."""

    def __init__(self, model, peta, feature_names):
        self.model = model
        self.balik = {v: k for k, v in peta.items()}
        self.feature_importances_ = model.feature_importances_
        self.classes_ = np.array([self.balik[i] for i in range(len(self.balik))])
        self.feature_names_in_ = np.array(list(feature_names))

    def predict(self, X):
        return np.array([self.balik[i] for i in self.model.predict(X)])

    def predict_proba(self, X):
        return self.model.predict_proba(X)
