# quantum_cluster.py
import numpy as np
from sklearn.cluster import DBSCAN
from .quantum_distance import quantum_distance

def quantum_traffic_clustering(X, eps=0.3, min_samples=5):
    dist_matrix = np.zeros((len(X), len(X)))

    for i in range(len(X)):
        for j in range(len(X)):
            dist_matrix[i][j] = quantum_distance(X[i], X[j])

    clustering = DBSCAN(metric="precomputed",
                         eps=eps,
                         min_samples=min_samples)
    labels = clustering.fit_predict(dist_matrix)

    return labels
