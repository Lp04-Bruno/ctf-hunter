import type { Api } from "./api";
import type {
  AnalysisPreview,
  DaemonStatus,
  FindingDetail,
  FindingSummary,
  Session,
  Sources,
} from "./types";

const sessionId = "018f2670-88a0-7d3a-8e8d-5efefc4f6461";
const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();
const wait = () => new Promise((resolve) => setTimeout(resolve, 90));

let sessions: Session[] = [
  {
    id: sessionId,
    name: "Autumn Finals",
    created_at: ago(180),
    started_at: ago(102),
    finished_at: null,
    status: "monitoring",
    flag_patterns: ["HTB{*}", "FLAG{*}"],
  },
  {
    id: "018f2670-88a0-7d3a-8e8d-5efefc4f6462",
    name: "Practice Lab",
    created_at: ago(1_440),
    started_at: ago(1_400),
    finished_at: ago(1_250),
    status: "finished",
    flag_patterns: ["PICOCTF{*}"],
  },
];

const values = [
  ["HTB{silent_terminal}", "very_high", 2],
  ["HTB{layer_by_layer}", "high", 14],
  ["HTB{watch_the_logs}", "high", 28],
  ["HTB{packet_whisperer}", "medium", 41],
  ["HTB{credentials_leak}", "high", 63],
  ["HTB{just_a_test}", "medium", 71],
  ["HTB{hidden_in_plain_sight}", "medium", 83],
  ["HTB{the_last_piece}", "high", 96],
] as const;

const findings: FindingSummary[] = values.map(([value, confidence, minutes], index) => ({
  id: `018f2670-88a0-7d3a-8e8d-5efefc4f65${String(index + 10).padStart(2, "0")}`,
  session_id: sessionId,
  value,
  confidence,
  discovered_at: ago(minutes),
  occurrences: index === 1 ? 2 : 1,
  source: sourceFor(index),
}));

function sourceFor(index: number) {
  if (index % 3 === 1) {
    return { kind: "file" as const, details: "/home/kali/ctf/output/results.json" };
  }
  return {
    kind: "terminal" as const,
    details: {
      process_id: 4821 + index,
      user_id: 1000,
      file_descriptor: 1,
      process_name: index === 0 ? "printf" : "python3",
      executable: "/usr/bin/python3",
      tty: "/dev/pts/1",
    },
  };
}

const details = new Map<string, FindingDetail>(
  findings.map((summary, index) => [
    summary.id,
    {
      summary,
      occurrences: [
        {
          source_event_id: `018f2670-88a0-7d3a-8e8d-5efefc4f66${index}0`,
          candidate_id: `018f2670-88a0-7d3a-8e8d-5efefc4f67${index}0`,
          path: [
            { kind: "property", value: "payload" },
            { kind: "property", value: "response" },
            { kind: "property", value: "token" },
          ],
          observed_at: summary.discovered_at,
          count: 1,
          source: sourceFor(index),
          candidate_text:
            index === 1 ? "SFRCe2xheWVyX2J5X2xheWVyfQ==" : `captured output containing ${summary.value}`,
          candidate_original_length: 32,
          candidate_truncated: false,
          transformations:
            index === 1
              ? [
                  {
                    id: "018f2670-88a0-7d3a-8e8d-5efefc4f6801",
                    input_candidate_id: "input",
                    output_candidate_id: "output",
                    name: "base64",
                    applied_at: summary.discovered_at,
                  },
                ]
              : [],
        },
      ],
      occurrences_truncated: false,
    },
  ]),
);

let sources: Sources = {
  terminals: ["/dev/pts/1"],
  directories: ["/home/kali/ctf/output"],
};

const status: DaemonStatus = {
  schema_version: 3,
  worker_count: 4,
  queue_capacity: 64,
  queue_depth: 0,
  accepted_connections: 128,
  rejected_connections: 0,
  completed_requests: 126,
  failed_requests: 2,
  file_collector: {
    events_received: 4_820,
    files_read: 98,
    duplicate_events: 8,
    oversized_files: 0,
    rate_limited_files: 0,
    dropped_events: 0,
    read_errors: 0,
    queue_overflows: 0,
    invalidated_watches: 0,
    analyzed_files: 90,
    analysis_errors: 0,
  },
  capture: {
    configured_sources: 1,
    active_sources: 1,
    connected_sources: 1,
    connection_attempts: 1,
    reconnects: 0,
    events_received: 12_361,
    events_analyzed: 12_361,
    analysis_errors: 0,
    dropped_events: 0,
    protocol_errors: 0,
    helper_errors: 0,
    ring_dropped: 0,
    read_failed: 0,
    fail_closed: 0,
  },
  analysis: {
    events_analyzed: 12_451,
    candidates_extracted: 18_932,
    candidates_decoded: 3_712,
    findings_detected: 8,
  },
};

function decodePreview(text: string): AnalysisPreview {
  const isExample = text.trim() === "SFRCe2xheWVyX2J5X2xheWVyfQ==";
  return {
    normalized: text.trim(),
    detections: isExample ? [{ format: "base64", confidence: 90 }] : [],
    transformations: isExample
      ? [
          {
            name: "base64",
            input: text.trim(),
            output: "HTB{layer_by_layer}",
          },
        ]
      : [],
    findings: isExample
      ? [
          {
            value: "HTB{layer_by_layer}",
            confidence: "high",
            path: [],
          },
        ]
      : [],
    statistics: {
      extracted_occurrences: 1,
      candidate_count: isExample ? 2 : 1,
      decoded_candidates: isExample ? 1 : 0,
      decoder_attempts: isExample ? 1 : 0,
    },
  };
}

export const mockApi: Api = {
  async status() {
    await wait();
    return structuredClone(status);
  },
  async sessions() {
    await wait();
    return structuredClone(sessions);
  },
  async createSession(name, flagPatterns) {
    await wait();
    const session: Session = {
      id: crypto.randomUUID(),
      name,
      created_at: new Date().toISOString(),
      started_at: null,
      finished_at: null,
      status: "inactive",
      flag_patterns: flagPatterns,
    };
    sessions = [session, ...sessions];
    return structuredClone(session);
  },
  async updateSession(sessionIdValue, name, flagPatterns) {
    await wait();
    const session = sessions.find((item) => item.id === sessionIdValue);
    if (!session) throw new Error("Session not found");
    session.name = name;
    session.flag_patterns = flagPatterns;
    return structuredClone(session);
  },
  async transitionSession(sessionIdValue, action) {
    await wait();
    const session = sessions.find((item) => item.id === sessionIdValue);
    if (!session) throw new Error("Session not found");
    if (action === "start") {
      session.status = "monitoring";
      session.started_at = new Date().toISOString();
    } else if (action === "pause") session.status = "paused";
    else if (action === "resume") session.status = "monitoring";
    else {
      session.status = "finished";
      session.finished_at = new Date().toISOString();
    }
    return structuredClone(session);
  },
  async sources() {
    await wait();
    return structuredClone(sources);
  },
  async addSource(_sessionId, kind, path) {
    await wait();
    const key = kind === "directory" ? "directories" : "terminals";
    if (!sources[key].includes(path)) sources[key].push(path);
    return [...sources[key]];
  },
  async removeSource(_sessionId, kind, path) {
    await wait();
    const key = kind === "directory" ? "directories" : "terminals";
    sources[key] = sources[key].filter((entry) => entry !== path);
    return [...sources[key]];
  },
  async findings(sessionIdValue, offset = 0, limit = 100) {
    await wait();
    return structuredClone(
      findings.filter((finding) => finding.session_id === sessionIdValue).slice(offset, offset + limit),
    );
  },
  async finding(findingId) {
    await wait();
    return structuredClone(details.get(findingId) ?? null);
  },
  async preview(_sessionId, text) {
    await wait();
    return decodePreview(text);
  },
  async submit(_sessionId, text) {
    await wait();
    const preview = decodePreview(text);
    return { event_id: crypto.randomUUID(), finding_ids: preview.findings.map(() => crypto.randomUUID()) };
  },
};
