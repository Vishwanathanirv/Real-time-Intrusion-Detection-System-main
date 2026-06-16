# fallback_selector.py
import numpy as np

def classical_feature_selection(importance, k=17):
    return np.argsort(importance)[-k:].tolist()
