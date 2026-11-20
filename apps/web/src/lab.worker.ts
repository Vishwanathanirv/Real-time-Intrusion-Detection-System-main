import { trainBaseline, whatIf, type BaselineModel, type WhatIfInput } from "@packeteye/core";

/** Runs what-if scenarios off the main thread, so the scope keeps sweeping while the lab works. */
let model: BaselineModel | null = null;
self.onmessage = (e: MessageEvent<{ id: number; input: WhatIfInput }>) => {
  model ??= trainBaseline({ seed: 99, minutes: 8 });
  const result = whatIf({ ...e.data.input, model });
  (self as unknown as Worker).postMessage({ id: e.data.id, result });
};
