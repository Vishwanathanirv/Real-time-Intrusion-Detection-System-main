import { Rng } from "./rng";

/**
 * Isolation Forest (Liu et al., 2008): an unsupervised detector that needs no labels,
 * so it can flag new attack patterns the supervised model has never seen.
 */
export type IsoNode = { f: number; t: number; l: number; r: number; size: number };
export type IForestModel = { kind: "iforest"; trees: IsoNode[][]; sampleSize: number };

const H = (i: number) => Math.log(i) + 0.5772156649;
const c = (n: number) => (n <= 1 ? 0 : 2 * H(n - 1) - (2 * (n - 1)) / n);

export function trainIForest(X: number[][], opts: { trees?: number; sampleSize?: number; seed?: number } = {}): IForestModel {
  const { trees = 100, sampleSize = 256, seed = 11 } = opts;
  const rng = new Rng(seed);
  const limit = Math.ceil(Math.log2(sampleSize));
  const F = X[0].length;
  const forest: IsoNode[][] = [];
  for (let t = 0; t < trees; t++) {
    const sample = Array.from({ length: Math.min(sampleSize, X.length) }, () => X[Math.floor(rng.next() * X.length)]);
    const nodes: IsoNode[] = [];
    const grow = (rows: number[][], depth: number): number => {
      const id = nodes.length;
      nodes.push({ f: -1, t: 0, l: -1, r: -1, size: rows.length });
      if (depth >= limit || rows.length <= 1) return id;
      for (let tries = 0; tries < 5; tries++) {
        const f = Math.floor(rng.next() * F);
        let lo = Infinity;
        let hi = -Infinity;
        for (const r of rows) {
          lo = Math.min(lo, r[f]);
          hi = Math.max(hi, r[f]);
        }
        if (hi <= lo) continue;
        const thr = lo + rng.next() * (hi - lo);
        nodes[id].f = f;
        nodes[id].t = thr;
        nodes[id].l = grow(rows.filter((r) => r[f] < thr), depth + 1);
        nodes[id].r = grow(rows.filter((r) => r[f] >= thr), depth + 1);
        return id;
      }
      return id;
    };
    grow(sample, 0);
    forest.push(nodes);
  }
  return { kind: "iforest", trees: forest, sampleSize: Math.min(sampleSize, X.length) };
}

/** Anomaly score in (0, 1); around 0.5 is normal, values near 1 are strong outliers. */
export function anomalyScore(m: IForestModel, x: ArrayLike<number>): number {
  let total = 0;
  for (const nodes of m.trees) {
    let i = 0;
    let depth = 0;
    while (nodes[i].f >= 0) {
      i = x[nodes[i].f] < nodes[i].t ? nodes[i].l : nodes[i].r;
      depth++;
    }
    total += depth + c(nodes[i].size);
  }
  return 2 ** (-(total / m.trees.length) / c(m.sampleSize));
}
