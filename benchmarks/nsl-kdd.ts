/**
 * Public-dataset benchmark on NSL-KDD (Tavallaee et al., 2009), using its official held-out
 * test set KDDTest+. Usage: `npm run benchmark` (downloads about 23 MB once, checks SHA-256).
 *
 * Two models are scored on the same held-out file:
 *  1. PacketEye's isolation forest (the same code as the live sensor's anomaly detector), trained
 *     only on normal training records, so it never sees an attack label. Threshold: the 99th
 *     percentile of its scores on normal training data, chosen before looking at the test set.
 *  2. A supervised random forest over the 41 connection features, for per-class metrics.
 *
 * KDDTest+ holds 17 attack types that never appear in KDDTrain+, so these numbers include
 * attacks the models have never seen.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { anomalyScore, trainIForest } from "../packages/core/src/iforest";
import { perClassMetrics, predict, trainForest } from "./forest";

const BASE = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master";
const FILES = {
  train: { name: "KDDTrain+.txt", sha256: "1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95" },
  test: { name: "KDDTest+.txt", sha256: "fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84" },
};
const CACHE = path.resolve(import.meta.dirname, ".cache");

export const CLASSES = ["normal", "dos", "probe", "r2l", "u2r"] as const;
/** The usual five-way grouping of NSL-KDD attack names (httptunnel is counted as R2L). */
const CATEGORY: Record<string, (typeof CLASSES)[number]> = { normal: "normal" };
for (const a of "back land neptune pod smurf teardrop apache2 mailbomb processtable udpstorm worm".split(" ")) CATEGORY[a] = "dos";
for (const a of "ipsweep nmap portsweep satan mscan saint".split(" ")) CATEGORY[a] = "probe";
for (const a of "ftp_write guess_passwd imap multihop phf spy warezclient warezmaster named sendmail snmpgetattack snmpguess xlock xsnoop httptunnel".split(" ")) CATEGORY[a] = "r2l";
for (const a of "buffer_overflow loadmodule perl rootkit ps sqlattack xterm".split(" ")) CATEGORY[a] = "u2r";

async function load(f: { name: string; sha256: string }): Promise<string> {
  mkdirSync(CACHE, { recursive: true });
  const file = path.join(CACHE, f.name);
  if (!existsSync(file)) {
    const res = await fetch(`${BASE}/${encodeURIComponent(f.name)}`);
    if (!res.ok) throw new Error(`Download of ${f.name} failed: HTTP ${res.status}`);
    writeFileSync(file, Buffer.from(await res.arrayBuffer()));
  }
  const buf = readFileSync(file);
  const sum = createHash("sha256").update(buf).digest("hex");
  if (sum !== f.sha256) throw new Error(`${f.name}: SHA-256 ${sum} does not match the pinned ${f.sha256}. Delete ${CACHE} and retry.`);
  return buf.toString("utf8");
}

type Row = { proto: string; service: string; flag: string; num: number[]; label: string; cls: number };

function parse(text: string): Row[] {
  return text
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => {
      const c = l.trim().split(",");
      const label = c[41];
      const cat = CATEGORY[label];
      if (!cat) throw new Error(`Unknown NSL-KDD label "${label}"`);
      // Columns 0 and 4..40 are numeric; 1..3 are protocol, service and TCP flag; 42 is difficulty.
      const num = [c[0], ...c.slice(4, 41)].map(Number);
      return { proto: c[1], service: c[2], flag: c[3], num, label, cls: CLASSES.indexOf(cat) };
    });
}

/** One-hot categories (vocabulary from the training file only) plus log-scaled heavy-tailed counts. */
function encoder(train: Row[]) {
  const vocab = (k: "proto" | "service" | "flag") => [...new Set(train.map((r) => r[k]))].sort();
  const v = { proto: vocab("proto"), service: vocab("service"), flag: vocab("flag") };
  return (r: Row) => [
    ...r.num.map((x, i) => (i <= 2 ? Math.log1p(x) : x)), // duration, src_bytes, dst_bytes
    ...v.proto.map((p) => +(r.proto === p)),
    ...v.flag.map((p) => +(r.flag === p)),
    ...v.service.map((p) => +(r.service === p)),
  ];
}

const pct = (x: number) => Math.round(x * 1000) / 10;

async function main() {
  const t0 = performance.now();
  const [train, test] = [parse(await load(FILES.train)), parse(await load(FILES.test))];
  const enc = encoder(train);
  const Xtr = train.map(enc);
  const Xte = test.map(enc);
  const ytr = train.map((r) => r.cls);
  const yte = test.map((r) => r.cls);
  const unseen = new Set(test.map((r) => r.label).filter((l) => !train.some((r) => r.label === l)));

  // 1. Isolation forest: unsupervised, trained on normal traffic only.
  const numericOnly = (x: number[]) => x.slice(0, 38);
  const normalTrain = Xtr.filter((_x, i) => ytr[i] === 0).map(numericOnly);
  const iso = trainIForest(normalTrain, { trees: 200, sampleSize: 256, seed: 11 });
  const trainScores = normalTrain.map((x) => anomalyScore(iso, x)).sort((a, b) => a - b);
  const threshold = trainScores[Math.floor(0.99 * (trainScores.length - 1))];
  const flagged = Xte.map((x) => anomalyScore(iso, numericOnly(x)) > threshold);
  const isoByClass = Object.fromEntries(
    CLASSES.map((name, c) => {
      const rows = yte.map((y, i) => [y, i] as const).filter(([y]) => y === c);
      return [name, { support: rows.length, flagged: rows.filter(([, i]) => flagged[i]).length }];
    }),
  );
  const tp = yte.filter((y, i) => y !== 0 && flagged[i]).length;
  const fp = yte.filter((y, i) => y === 0 && flagged[i]).length;
  const attacks = yte.filter((y) => y !== 0).length;
  const normals = yte.length - attacks;
  const isolationForest = { threshold, precision: tp / (tp + fp), recall: tp / attacks, fpr: fp / normals, byClass: isoByClass };

  // 2. Supervised random forest.
  const t1 = performance.now();
  const rf = trainForest(Xtr, ytr, CLASSES.length, { trees: 60, maxDepth: 24, seed: 7 });
  const trainSec = (performance.now() - t1) / 1000;
  const pred = Xte.map((x) => predict(rf, x));
  const randomForest = { ...perClassMetrics(yte, pred, [...CLASSES]), trainSeconds: Math.round(trainSec * 10) / 10 };
  const unseenRows = test.map((r, i) => [r, i] as const).filter(([r]) => unseen.has(r.label));
  const unseenRecall = unseenRows.filter(([, i]) => pred[i] !== 0).length / unseenRows.length;

  const report = {
    dataset: "NSL-KDD (KDDTrain+ for training, KDDTest+ held out)",
    source: BASE,
    licence: "Distributed by the Canadian Institute for Cybersecurity, University of New Brunswick, for research use; cite Tavallaee et al., 'A Detailed Analysis of the KDD CUP 99 Data Set', CISDA 2009. Not redistributed in this repository.",
    sha256: { [FILES.train.name]: FILES.train.sha256, [FILES.test.name]: FILES.test.sha256 },
    trainRecords: train.length,
    testRecords: test.length,
    unseenAttackTypes: [...unseen].sort(),
    unseenAttackRecords: unseenRows.length,
    randomForest: { ...randomForest, unseenAttackDetectionRate: unseenRecall },
    isolationForest,
    seconds: Math.round((performance.now() - t0) / 100) / 10,
  };

  console.log(`NSL-KDD: ${train.length.toLocaleString()} training records, ${test.length.toLocaleString()} held-out test records (${unseenRows.length.toLocaleString()} from ${unseen.size} attack types absent from training)\n`);
  console.log("Random forest, per class on KDDTest+:");
  console.log("| Class | Test records | Precision | Recall | False-positive rate |\n| --- | --- | --- | --- | --- |");
  for (const name of CLASSES) {
    const m = randomForest.perClass[name];
    console.log(`| ${name} | ${m.support.toLocaleString()} | ${pct(m.precision)}% | ${pct(m.recall)}% | ${pct(m.fpr)}% |`);
  }
  console.log(`\nAccuracy ${pct(randomForest.accuracy)}%. Unseen attack types flagged as an attack: ${pct(unseenRecall)}%.`);
  console.log(`\nIsolation forest (no attack labels): precision ${pct(isolationForest.precision)}%, recall ${pct(isolationForest.recall)}%, false-positive rate ${pct(isolationForest.fpr)}%`);
  for (const name of CLASSES.slice(1)) console.log(`  ${name}: ${isoByClass[name].flagged}/${isoByClass[name].support} flagged`);
  mkdirSync("reports", { recursive: true });
  writeFileSync("reports/nsl-kdd.json", JSON.stringify({ generatedAt: new Date().toISOString(), ...report }, null, 2) + "\n");
  console.log(`\nWrote reports/nsl-kdd.json in ${report.seconds} s`);
}

await main();
