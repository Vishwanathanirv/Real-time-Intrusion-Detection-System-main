import { Rng } from "../packages/core/src/rng";

/**
 * A small random forest (Breiman, 2001) for the public-dataset benchmark. Features are cut into
 * quantile bins once, so each split is a histogram scan instead of a sort.
 */
export type ForestOpts = { trees?: number; maxDepth?: number; minLeaf?: number; bins?: number; mtry?: number; seed?: number };
type Node = { f: number; bin: number; l: number; r: number; dist: Float64Array | null };
export type Forest = { edges: number[][]; trees: Node[][]; classes: number };

/** Upper edges of up to `bins` quantile bins per feature. */
function binEdges(X: number[][], bins: number): number[][] {
  const F = X[0].length;
  const out: number[][] = [];
  const step = Math.max(1, Math.floor(X.length / 4000));
  for (let f = 0; f < F; f++) {
    const vals: number[] = [];
    for (let i = 0; i < X.length; i += step) vals.push(X[i][f]);
    vals.sort((a, b) => a - b);
    const edges = new Set<number>();
    for (let b = 1; b < bins; b++) edges.add(vals[Math.floor((b / bins) * (vals.length - 1))]);
    out.push([...edges].sort((a, b) => a - b));
  }
  return out;
}

const binOf = (edges: number[], v: number) => {
  let lo = 0;
  let hi = edges.length;
  while (lo < hi) {
    const m = (lo + hi) >> 1;
    if (v <= edges[m]) hi = m;
    else lo = m + 1;
  }
  return lo; // bin index in [0, edges.length]
};

export function trainForest(X: number[][], y: number[], classes: number, opts: ForestOpts = {}): Forest {
  const { trees = 60, maxDepth = 24, minLeaf = 1, bins = 32, seed = 7 } = opts;
  const F = X[0].length;
  const mtry = opts.mtry ?? Math.max(1, Math.round(Math.sqrt(F)));
  const rng = new Rng(seed);
  const edges = binEdges(X, bins);
  const B = X.map((row) => Uint8Array.from(row, (v, f) => binOf(edges[f], v)));
  const forest: Node[][] = [];
  for (let t = 0; t < trees; t++) {
    const idx = Uint32Array.from({ length: X.length }, () => Math.floor(rng.next() * X.length));
    const nodes: Node[] = [];
    const leaf = (rows: Uint32Array) => {
      const d = new Float64Array(classes);
      for (const i of rows) d[y[i]]++;
      for (let c = 0; c < classes; c++) d[c] /= rows.length;
      nodes.push({ f: -1, bin: 0, l: -1, r: -1, dist: d });
      return nodes.length - 1;
    };
    const grow = (rows: Uint32Array, depth: number): number => {
      const counts = new Float64Array(classes);
      for (const i of rows) counts[y[i]]++;
      const pure = counts.some((c) => c === rows.length);
      if (pure || depth >= maxDepth || rows.length <= 2 * minLeaf) return leaf(rows);
      let best = { gain: 1e-12, f: -1, bin: 0 };
      const parentGini = 1 - counts.reduce((a, c) => a + (c / rows.length) ** 2, 0);
      for (let k = 0; k < mtry; k++) {
        const f = Math.floor(rng.next() * F);
        const nb = edges[f].length + 1;
        if (nb < 2) continue;
        const hist = new Float64Array(nb * classes);
        for (const i of rows) hist[B[i][f] * classes + y[i]]++;
        const left = new Float64Array(classes);
        let nl = 0;
        for (let b = 0; b < nb - 1; b++) {
          for (let c = 0; c < classes; c++) {
            left[c] += hist[b * classes + c];
            nl += hist[b * classes + c];
          }
          const nr = rows.length - nl;
          if (nl < minLeaf || nr < minLeaf) continue;
          let gl = 1;
          let gr = 1;
          for (let c = 0; c < classes; c++) {
            gl -= (left[c] / nl) ** 2;
            gr -= ((counts[c] - left[c]) / nr) ** 2;
          }
          const gain = parentGini - (nl * gl + nr * gr) / rows.length;
          if (gain > best.gain) best = { gain, f, bin: b };
        }
      }
      if (best.f < 0) return leaf(rows);
      const id = nodes.length;
      nodes.push({ f: best.f, bin: best.bin, l: -1, r: -1, dist: null });
      const l: number[] = [];
      const r: number[] = [];
      for (const i of rows) (B[i][best.f] <= best.bin ? l : r).push(i);
      nodes[id].l = grow(Uint32Array.from(l), depth + 1);
      nodes[id].r = grow(Uint32Array.from(r), depth + 1);
      return id;
    };
    grow(idx, 0);
    forest.push(nodes);
  }
  return { edges, trees: forest, classes };
}

/** Averaged class probabilities. */
export function predictProba(m: Forest, x: number[]): Float64Array {
  const b = x.map((v, f) => binOf(m.edges[f], v));
  const out = new Float64Array(m.classes);
  for (const nodes of m.trees) {
    let i = 0;
    while (nodes[i].f >= 0) i = b[nodes[i].f] <= nodes[i].bin ? nodes[i].l : nodes[i].r;
    const d = nodes[i].dist!;
    for (let c = 0; c < m.classes; c++) out[c] += d[c] / m.trees.length;
  }
  return out;
}

export const predict = (m: Forest, x: number[]) => {
  const p = predictProba(m, x);
  let best = 0;
  for (let c = 1; c < p.length; c++) if (p[c] > p[best]) best = c;
  return best;
};

export type ClassMetrics = { support: number; precision: number; recall: number; fpr: number; f1: number };

/** One-vs-rest precision, recall and false-positive rate for each class, plus the confusion matrix. */
export function perClassMetrics(yTrue: number[], yPred: number[], names: string[]) {
  const K = names.length;
  const confusion = names.map(() => new Array<number>(K).fill(0));
  yTrue.forEach((t, i) => confusion[t][yPred[i]]++);
  const n = yTrue.length;
  const perClass: Record<string, ClassMetrics> = {};
  names.forEach((name, c) => {
    const tp = confusion[c][c];
    const fn = confusion[c].reduce((a, v) => a + v, 0) - tp;
    const fp = confusion.reduce((a, row) => a + row[c], 0) - tp;
    const tn = n - tp - fn - fp;
    const precision = tp + fp ? tp / (tp + fp) : 0;
    const recall = tp + fn ? tp / (tp + fn) : 0;
    perClass[name] = { support: tp + fn, precision, recall, fpr: fp + tn ? fp / (fp + tn) : 0, f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0 };
  });
  const accuracy = names.reduce((a, _n, c) => a + confusion[c][c], 0) / n;
  return { perClass, confusion, accuracy };
}
