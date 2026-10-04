export type Page = "overview" | "sessions" | "findings" | "decoder" | "sources" | "settings";
export type SessionStatus = "inactive" | "monitoring" | "paused" | "finished";
export type Confidence = "low" | "medium" | "high" | "very_high";

export interface Session {
  id: string;
  name: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  status: SessionStatus;
  flag_patterns: string[];
}

export interface AnalysisStatus {
  events_analyzed: number;
  candidates_extracted: number;
  candidates_decoded: number;
  findings_detected: number;
  duplicate_events: number;
}

export interface NotificationSettings {
  enabled: boolean;
  minimum_confidence: Confidence;
}

export interface NotificationStatus {
  queue_capacity: number;
  queue_depth: number;
  delivered: number;
  dropped: number;
  errors: number;
}

export interface FileCollectorStatus {
  events_received: number;
  files_read: number;
  duplicate_events: number;
  oversized_files: number;
  rate_limited_files: number;
  dropped_events: number;
  read_errors: number;
  queue_overflows: number;
  invalidated_watches: number;
  analyzed_files: number;
  analysis_errors: number;
}

export interface CaptureStatus {
  configured_sources: number;
  active_sources: number;
  connected_sources: number;
  connection_attempts: number;
  reconnects: number;
  events_received: number;
  events_analyzed: number;
  analysis_errors: number;
  dropped_events: number;
  protocol_errors: number;
  helper_errors: number;
  ring_dropped: number;
  read_failed: number;
  fail_closed: number;
}

export interface DaemonStatus {
  schema_version: number;
  worker_count: number;
  queue_capacity: number;
  queue_depth: number;
  accepted_connections: number;
  rejected_connections: number;
  completed_requests: number;
  failed_requests: number;
  file_collector: FileCollectorStatus;
  capture: CaptureStatus;
  analysis: AnalysisStatus;
  notifications: NotificationStatus;
}

export type PathSegment =
  | { kind: "property"; value: string }
  | { kind: "index"; value: number };
export type CandidatePath = PathSegment[];

export type SourceMetadata =
  | {
      kind: "terminal";
      details: {
        process_id: number;
        user_id: number;
        file_descriptor: number | null;
        process_name: string;
        executable: string | null;
        tty: string;
      };
    }
  | { kind: "file"; details: string }
  | { kind: "manual" };

export interface FindingSummary {
  id: string;
  session_id: string;
  value: string;
  confidence: Confidence;
  discovered_at: string;
  occurrences: number;
  source: SourceMetadata | null;
}

export interface TransformationStep {
  id: string;
  input_candidate_id: string;
  output_candidate_id: string;
  name: string;
  applied_at: string;
}

export interface FindingOccurrence {
  source_event_id: string;
  candidate_id: string;
  path: CandidatePath;
  observed_at: string;
  count: number;
  source: SourceMetadata;
  root_candidate_text: string | null;
  candidate_text: string | null;
  candidate_original_length: number;
  candidate_truncated: boolean;
  transformations: TransformationStep[];
}

export interface FindingDetail {
  summary: FindingSummary;
  occurrences: FindingOccurrence[];
  occurrences_truncated: boolean;
}

export interface Sources {
  directories: string[];
  terminals: string[];
}

export interface PreviewDetection {
  format: string;
  confidence: number;
}

export interface PreviewTransformation {
  name: string;
  input: string;
  output: string;
}

export interface PreviewFinding {
  value: string;
  confidence: Confidence;
  path: CandidatePath;
}

export interface AnalysisPreview {
  normalized: string;
  detections: PreviewDetection[];
  transformations: PreviewTransformation[];
  findings: PreviewFinding[];
  statistics: {
    extracted_occurrences: number;
    candidate_count: number;
    decoded_candidates: number;
    decoder_attempts: number;
  };
}

export interface Submission {
  event_id: string;
  finding_ids: string[];
}

export type HealthStatus = "ready" | "attention" | "pending" | "unavailable";

export interface HealthCheck {
  status: HealthStatus;
  title: string;
  detail: string;
  recovery_command: string | null;
}

export interface RuntimeDiagnostics {
  user_daemon: HealthCheck;
  capture_service: HealthCheck;
  kernel_btf: HealthCheck;
  terminal_access: HealthCheck;
  group_exists: boolean;
  account_in_group: boolean;
  session_has_group: boolean;
  requires_new_login: boolean;
  setup_available: boolean;
  terminal_capture_ready: boolean;
}
