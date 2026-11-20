import { describe, expect, it } from "vitest";
import { Rng } from "../../packages/core/src/rng";
import { perClassMetrics, predict, trainForest } from "../forest";

describe("random forest", () => {
  it("learns a non-linear three-class problem it has not seen", () => {
    const rng = new Rng(3);
    const make = (n: number) => {
      const X: number[][] = [];
      const y: number[] = [];
      for (let i = 0; i < n; i++) {
        const a = rng.next() * 10;
        const b = rng.next() * 10;
        X.push([a, b, rng.next()]);
        y.push(a + b < 7 ? 0 : a > b ? 1 : 2);
      }
      return { X, y };
    };
    const train = make(3000);
    const test = make(1000);
    const m = trainForest(train.X, train.y, 3, { trees: 20, seed: 1 });
    const pred = test.X.map((x) => predict(m, x));
    expect(perClassMetrics(test.y, pred, ["a", "b", "c"]).accuracy).toBeGreaterThan(0.93);
  });

  it("computes one-vs-rest precision, recall and false-positive rate", () => {
    const r = perClassMetrics([0, 0, 1, 1, 2], [0, 1, 1, 1, 0], ["n", "x", "y"]);
    expect(r.perClass.n).toMatchObject({ support: 2, precision: 0.5, recall: 0.5 });
    expect(r.perClass.n.fpr).toBeCloseTo(1 / 3);
    expect(r.perClass.x).toMatchObject({ precision: 2 / 3, recall: 1 });
    expect(r.perClass.y).toMatchObject({ precision: 0, recall: 0, fpr: 0 });
    expect(r.accuracy).toBeCloseTo(0.6);
  });
});
