import neal

def run_quantum_feature_selection(Q, num_reads=100):
    sampler = neal.SimulatedAnnealingSampler()
    response = sampler.sample_qubo(Q, num_reads=num_reads)
    best = response.first.sample
    selected = [i for i, v in best.items() if v == 1]
    return selected
