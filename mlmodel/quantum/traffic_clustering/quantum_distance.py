# quantum_distance.py
import numpy as np

def quantum_distance(a, b):
    """
    Safe quantum-inspired cosine distance.
    Guarantees:
    - No NaN
    - No negative distances
    - No divide-by-zero
    """

    na = np.linalg.norm(a)
    nb = np.linalg.norm(b)

    # Handle zero vectors safely
    if na == 0 or nb == 0:
        return 1.0  # maximum distance fallback

    a = a / na
    b = b / nb

    dist = 1 - np.dot(a, b)

    # Numerical safety
    if np.isnan(dist) or dist < 0:
        return 0.0

    return dist
