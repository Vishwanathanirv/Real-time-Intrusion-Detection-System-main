import { mkdirSync, writeFileSync } from "node:fs";
import { ATTACK_LABELS, evaluate } from "../packages/core/src/index";

const minutes = Number(process.env.MINUTES ?? 60);
const seed = Number(process.env.SEED ?? 7);
const r = evaluate({ minutes, seed });

console.log(`Replayed ${r.packets.toLocaleString()} packets (${minutes} min of office traffic, ${r.attacks} attacks)\n`);
console.table(
  Object.fromEntries(
    Object.entries(r.perAttack).map(([k, v]) => [ATTACK_LABELS[k as keyof typeof ATTACK_LABELS], { detected: `${v.detected}/${v.injected}`, "time to detect": v.meanTimeToDetectMs === null ? "–" : `${(v.meanTimeToDetectMs / 1000).toFixed(1)} s` }]),
  ),
);
console.log(`False alerts on clean traffic: ${r.falseAlertsPerHour}/hour`, r.falseAlertsByType);
console.log(`Throughput: ${r.throughputPps.toLocaleString()} packets/s (${r.avgMicrosPerPacket} µs per packet, single core)`);
mkdirSync("reports", { recursive: true });
writeFileSync("reports/evaluation.json", JSON.stringify({ generatedAt: new Date().toISOString(), seed, ...r }, null, 2));
