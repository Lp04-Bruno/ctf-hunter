import type { CandidatePath, Confidence, SourceMetadata } from "./types";

export function confidenceLabel(value: Confidence): string {
  return value === "very_high" ? "Very high" : value[0].toUpperCase() + value.slice(1);
}

export function candidatePath(path: CandidatePath): string {
  if (path.length === 0) return "$";
  return path
    .map((segment, index) => {
      if (segment.kind === "index") return `[${segment.value}]`;
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(segment.value)) {
        return `${index === 0 ? "" : "."}${segment.value}`;
      }
      return `[${JSON.stringify(segment.value)}]`;
    })
    .join("");
}

export function relativeTime(value: string, now = Date.now()): string {
  const delta = Math.max(0, now - new Date(value).getTime());
  const seconds = Math.floor(delta / 1_000);
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function sourceLabel(source: SourceMetadata | undefined): string {
  if (!source) return "Unknown";
  if (source.kind === "terminal") return "Terminal";
  if (source.kind === "file") return "File";
  return "Manual";
}

export function sourceDetail(source: SourceMetadata | undefined): string {
  if (!source) return "No source metadata";
  if (source.kind === "terminal") {
    return `${source.details.process_name} (pid ${source.details.process_id}) · ${source.details.tty}`;
  }
  if (source.kind === "file") return source.details;
  return "Manual decoder submission";
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

export function elapsed(startedAt: string | null, now = Date.now()): string {
  if (!startedAt) return "00:00:00";
  const total = Math.max(0, Math.floor((now - new Date(startedAt).getTime()) / 1_000));
  const hours = Math.floor(total / 3_600);
  const minutes = Math.floor((total % 3_600) / 60);
  const seconds = total % 60;
  return [hours, minutes, seconds].map((part) => String(part).padStart(2, "0")).join(":");
}
