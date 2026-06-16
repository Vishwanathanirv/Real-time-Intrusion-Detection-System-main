# fallback_cluster.py
from sklearn.cluster import KMeans

def classical_clustering(X, k=2):
    return KMeans(n_clusters=k).fit_predict(X)
