import { render, screen, within } from "@testing-library/svelte";
import { describe, expect, it, vi } from "vitest";
import Findings from "./Findings.svelte";
import type { FindingDetail, FindingSummary } from "../types";

const summary: FindingSummary = {
  id: "finding-1",
  session_id: "session-1",
  value: "FLAG{decoded}",
  confidence: "very_high",
  discovered_at: "2026-09-29T12:00:00Z",
  occurrences: 1,
  source: { kind: "manual" },
};

const detail: FindingDetail = {
  summary,
  occurrences: [
    {
      source_event_id: "event-1",
      candidate_id: "candidate-matched",
      path: [],
      observed_at: summary.discovered_at,
      count: 1,
      source: { kind: "manual" },
      root_candidate_text: "RkxBR3tkZWNvZGVkfQ==",
      candidate_text: "FLAG{decoded}",
      candidate_original_length: 13,
      candidate_truncated: false,
      transformations: [
        {
          id: "transformation-1",
          input_candidate_id: "candidate-root",
          output_candidate_id: "candidate-matched",
          name: "base64",
          applied_at: summary.discovered_at,
        },
      ],
    },
  ],
  occurrences_truncated: false,
};

describe("Findings detail", () => {
  it("shows the root candidate as raw and keeps the match as the fragment", () => {
    render(Findings, {
      findings: [summary],
      details: { [summary.id]: detail },
      selectedId: summary.id,
      loadingDetail: false,
      onSelect: vi.fn(),
    });

    const rawStep = screen.getByText("Raw candidate").closest("li");
    const fragment = screen.getByText("Relevant fragment").closest("section");

    expect(rawStep).not.toBeNull();
    expect(fragment).not.toBeNull();
    expect(within(rawStep as HTMLElement).getByText("RkxBR3tkZWNvZGVkfQ==")).toBeTruthy();
    expect(within(fragment as HTMLElement).getByText("FLAG{decoded}")).toBeTruthy();
  });
});
