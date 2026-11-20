import { trainBaseline, whatIf, type BaselineModel, type WhatIfInput } from "@packeteye/core";
import { traceSample } from "./how-data";

/** Runs heavy work off the main thread (what-if scenarios, the walkthrough's sample), so the scope keeps sweeping. */
let model: BaselineModel | null = null;
type Job = { id: number; op: "whatif"; input: WhatIfInput } | { id: number; op: "trace" };
self.onmessage = (e: MessageEvent<Job>) => {
  const job = e.data;
  let result: unknown;
  if (job.op === "trace") result = traceSample();
  else {
    model ??= trainBaseline({ seed: 99, minutes: 8 });
    result = whatIf({ ...job.input, model });
  }
  (self as unknown as Worker).postMessage({ id: job.id, result });
};
