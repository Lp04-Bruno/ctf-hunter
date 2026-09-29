import { invoke } from "@tauri-apps/api/core";
import { mockApi } from "./mock";
import type {
  AnalysisPreview,
  DaemonStatus,
  FindingDetail,
  FindingSummary,
  Session,
  Sources,
  Submission,
} from "./types";

export interface Api {
  status(): Promise<DaemonStatus>;
  sessions(): Promise<Session[]>;
  createSession(name: string, flagPatterns: string[]): Promise<Session>;
  updateSession(sessionId: string, name: string, flagPatterns: string[]): Promise<Session>;
  transitionSession(sessionId: string, action: "start" | "pause" | "resume" | "stop"): Promise<Session>;
  sources(sessionId: string): Promise<Sources>;
  addSource(sessionId: string, kind: "directory" | "terminal", path: string): Promise<string[]>;
  removeSource(sessionId: string, kind: "directory" | "terminal", path: string): Promise<string[]>;
  findings(sessionId: string, offset?: number, limit?: number): Promise<FindingSummary[]>;
  finding(findingId: string): Promise<FindingDetail | null>;
  preview(sessionId: string, text: string): Promise<AnalysisPreview>;
  submit(sessionId: string, text: string): Promise<Submission>;
}

const tauriApi: Api = {
  status: () => invoke("daemon_status"),
  sessions: () => invoke("list_sessions"),
  createSession: (name, flagPatterns) => invoke("create_session", { name, flagPatterns }),
  updateSession: (sessionId, name, flagPatterns) =>
    invoke("update_session", { sessionId, name, flagPatterns }),
  transitionSession: (sessionId, action) => invoke("transition_session", { sessionId, action }),
  sources: (sessionId) => invoke("list_sources", { sessionId }),
  addSource: (sessionId, kind, path) => invoke("add_source", { sessionId, kind, path }),
  removeSource: (sessionId, kind, path) => invoke("remove_source", { sessionId, kind, path }),
  findings: (sessionId, offset = 0, limit = 100) =>
    invoke("list_findings", { sessionId, offset, limit }),
  finding: (findingId) => invoke("get_finding", { findingId }),
  preview: (sessionId, text) => invoke("preview_text", { sessionId, text }),
  submit: (sessionId, text) => invoke("submit_text", { sessionId, text }),
};

const runningInTauri = typeof window !== "undefined" && window.__TAURI_INTERNALS__ !== undefined;

export const api: Api = runningInTauri ? tauriApi : mockApi;
export const usesPreviewData = !runningInTauri;
