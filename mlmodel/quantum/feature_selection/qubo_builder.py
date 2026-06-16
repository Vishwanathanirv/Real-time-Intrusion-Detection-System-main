import numpy as np

def build_qubo(corr_matrix, importance, alpha=0.5, k=15, P=1.0):
    n = len(importance)
    Q = {}

    # Linear terms: Importance maximization + Cardinality constraint linear part
    # Constraint: P * (sum(x) - k)^2 = P * (sum(x^2) + sum(xi*xj) - 2k*sum(x) + k^2)
    # Linear contribution: -importance[i] + P * (1 - 2*k)
    for i in range(n):
        Q[(i, i)] = -importance[i] + P * (1 - 2 * k)

    # Quadratic terms: Redundancy penalty + Cardinality constraint quadratic part
    # Quadratic contribution: alpha * |corr| + P * 2
    for i in range(n):
        for j in range(i + 1, n):
            Q[(i, j)] = alpha * abs(corr_matrix[i][j]) + 2 * P

    return Q
