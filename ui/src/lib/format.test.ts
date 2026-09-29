import { candidatePath, confidenceLabel, elapsed, relativeTime } from "./format";
import { describe, expect, it } from "vitest";

describe("UI formatting", () => {
  it("renders structured candidate paths", () => {
    expect(
      candidatePath([
        { kind: "property", value: "payload" },
        { kind: "index", value: 2 },
        { kind: "property", value: "flag.value" },
      ]),
    ).toBe('payload[2]["flag.value"]');
  });

  it("renders confidence and relative timestamps", () => {
    expect(confidenceLabel("very_high")).toBe("Very high");
    expect(relativeTime("2026-09-28T11:59:20Z", Date.parse("2026-09-28T12:00:00Z"))).toBe("40s ago");
  });

  it("renders elapsed monitoring time", () => {
    expect(elapsed("2026-09-28T10:17:42Z", Date.parse("2026-09-28T12:00:00Z"))).toBe("01:42:18");
  });
});
