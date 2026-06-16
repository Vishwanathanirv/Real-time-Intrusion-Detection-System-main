import numpy as np
from quantum.quantum_manager import is_quantum_enabled
from quantum.feature_selection.qubo_builder import build_qubo
from quantum.feature_selection.quantum_selector import run_quantum_feature_selection
from quantum.feature_selection.fallback_selector import classical_feature_selection
from quantum.traffic_clustering.quantum_cluster import quantum_traffic_clustering
from quantum.traffic_clustering.fallback_cluster import classical_clustering

def apply_quantum_feature_selection(X, feature_importance, corr_matrix, k=15):
    if is_quantum_enabled():
        Q = build_qubo(corr_matrix, feature_importance, k=k)
        return run_quantum_feature_selection(Q)
    else:
        return classical_feature_selection(feature_importance)

def apply_quantum_clustering(X):
    if is_quantum_enabled():
        return quantum_traffic_clustering(X)
    else:
        return classical_clustering(X)
