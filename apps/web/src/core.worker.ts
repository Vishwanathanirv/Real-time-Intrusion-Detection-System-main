import { trainBaseline, whatIf, type BaselineModel, type WhatIfInput } from "@packeteye/core";

/** Runs what-if scenarios off the main thread, so the interface stays responsive. */
let model: BaselineModel | null = null;
type Job = { id: number; op: "whatif"; input: WhatIfInput };
self.onmessage = (e: MessageEvent<Job>) => {
  const job = e.data;
  model ??= trainBaseline({ seed: 99, minutes: 8 });
  const result = whatIf({ ...job.input, model });
  (self as unknown as Worker).postMessage({ id: job.id, result });
};
