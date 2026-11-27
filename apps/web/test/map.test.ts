import { describe, expect, it } from "vitest";
import { LAYOUT, place, slot } from "../src/map";

describe("map slots", () => {
  it("keeps every host inside the map when a column overflows", () => {
    const list = Array.from({ length: 60 }, (_, i) => `10.0.0.${i + 1}`);
    for (const ip of list) {
      const { y } = slot(list, ip, [-555, -435, -315], 8);
      expect(y).toBeGreaterThanOrEqual(LAYOUT.top);
      expect(y).toBeLessThanOrEqual(LAYOUT.bottom);
    }
  });

  it("gives distinct positions to hosts that fit", () => {
    const list = Array.from({ length: 20 }, (_, i) => `10.0.0.${i + 1}`);
    const keys = new Set(list.map((ip) => JSON.stringify(slot(list, ip, [-555, -435, -315], 8))));
    expect(keys.size).toBe(20);
  });

  it("places servers past the server capacity inside the map", () => {
    const servers = Array.from({ length: 30 }, (_, i) => `10.0.1.${i + 1}`);
    for (const ip of servers) {
      const { y } = place({ ip, bytes: 1, internal: true }, { servers, workstations: [], internet: [] });
      expect(y).toBeLessThanOrEqual(LAYOUT.bottom);
    }
  });
});
