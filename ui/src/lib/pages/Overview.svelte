<script lang="ts">
  import {
    AlertTriangle,
    ArrowRight,
    Binary,
    CheckCircle2,
    FileText,
    Pause,
    Play,
    Radio,
    Square,
    TerminalSquare,
  } from "@lucide/svelte";
  import { confidenceLabel, elapsed, formatNumber, relativeTime, sourceLabel } from "../format";
  import type { DaemonStatus, FindingSummary, Page, Session } from "../types";

  export let session: Session | null;
  export let status: DaemonStatus | null;
  export let findings: FindingSummary[];
  export let busy: boolean;
  export let onTransition: (action: "start" | "pause" | "resume" | "stop") => void;
  export let onNavigate: (page: Page) => void;

  $: confirmed = findings.filter((item) => item.confidence === "high" || item.confidence === "very_high").length;
  $: possible = findings.length - confirmed;
  $: dropped = (status?.capture.dropped_events ?? 0) + (status?.file_collector.dropped_events ?? 0);
  $: activeSources = (status?.capture.active_sources ?? 0) + (session?.status === "monitoring" ? 1 : 0);
</script>

{#if !session}
  <section class="surface empty-state">
    <div>
      <h2>Create your first session</h2>
      <p>A session defines flag patterns and groups every capture source and finding.</p>
      <button class="button primary" type="button" onclick={() => onNavigate("sessions")}>Open Sessions</button>
    </div>
  </section>
{:else}
  <div class="page-stack">
    <section class="surface session-strip">
      <div class="session-name">
        <strong>{session.name}</strong>
        <span>{session.status === "monitoring" ? "Active session" : `${session.status} session`}</span>
      </div>
      <div class="strip-stat">
        <span>Flag patterns</span>
        <strong class="mono">{session.flag_patterns[0] ?? "Not set"}</strong>
      </div>
      <div class="strip-stat">
        <span>Elapsed time</span>
        <strong class="mono">{elapsed(session.started_at)}</strong>
      </div>
      <div class="session-controls">
        {#if session.status === "inactive"}
          <button class="button primary" type="button" disabled={busy} onclick={() => onTransition("start")}><Play size={16} /> Start</button>
        {:else if session.status === "monitoring"}
          <button class="button" type="button" disabled={busy} onclick={() => onTransition("pause")}><Pause size={16} /> Pause</button>
          <button class="button danger" type="button" disabled={busy} onclick={() => onTransition("stop")}><Square size={14} /> Stop</button>
        {:else if session.status === "paused"}
          <button class="button primary" type="button" disabled={busy} onclick={() => onTransition("resume")}><Play size={16} /> Resume</button>
          <button class="button danger" type="button" disabled={busy} onclick={() => onTransition("stop")}><Square size={14} /> Stop</button>
        {:else}
          <span class="status-badge finished">Finished</span>
        {/if}
      </div>
    </section>

    <section class="metrics" aria-label="Session metrics">
      <article class="surface metric">
        <div><CheckCircle2 size={18} /><span>Findings</span></div>
        <strong>{formatNumber(confirmed)}</strong>
        <small>High-confidence flags</small>
      </article>
      <article class="surface metric">
        <div><AlertTriangle size={18} /><span>Possible</span></div>
        <strong>{formatNumber(possible)}</strong>
        <small>Needs review</small>
      </article>
      <article class="surface metric">
        <div><FileText size={18} /><span>Events analyzed</span></div>
        <strong>{formatNumber(status?.analysis.events_analyzed ?? 0)}</strong>
        <small>{formatNumber(status?.analysis.candidates_extracted ?? 0)} candidates extracted</small>
      </article>
      <article class="surface metric">
        <div><AlertTriangle size={18} /><span>Dropped events</span></div>
        <strong class:danger-value={dropped > 0}>{formatNumber(dropped)}</strong>
        <small>{dropped === 0 ? "Capture queue is healthy" : "Inspect capture health"}</small>
      </article>
    </section>

    <div class="dashboard-grid">
      <section class="surface recent">
        <div class="panel-heading">
          <h2>Recent findings</h2>
          <button class="button" type="button" onclick={() => onNavigate("findings")}>View all <ArrowRight size={15} /></button>
        </div>
        {#if findings.length === 0}
          <div class="empty-state">No findings yet. Monitoring results will appear here.</div>
        {:else}
          <div class="table-wrap">
            <table>
              <thead><tr><th>Value</th><th>Confidence</th><th>Source</th><th>Seen</th></tr></thead>
              <tbody>
                {#each findings.slice(0, 8) as finding}
                  <tr class="selectable" onclick={() => onNavigate("findings")}>
                    <td class="mono value-cell"><span class="truncate">{finding.value}</span></td>
                    <td><span class="confidence {finding.confidence}">{confidenceLabel(finding.confidence)}</span></td>
                    <td>
                      <span class="source">
                        {#if finding.source?.kind === "terminal"}<TerminalSquare size={15} />{:else}<FileText size={15} />{/if}
                        {sourceLabel(finding.source ?? undefined)}
                      </span>
                    </td>
                    <td class="muted">{relativeTime(finding.discovered_at)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </section>

      <section class="surface health">
        <div class="panel-heading"><h2>Capture health</h2></div>
        <div class="health-list">
          <div><span><Radio size={16} /> Daemon</span><strong class="healthy"><span class="status-dot success"></span>Connected</strong></div>
          <div><span><TerminalSquare size={16} /> Helper</span><strong class:healthy={(status?.capture.connected_sources ?? 0) > 0}><span class="status-dot" class:success={(status?.capture.connected_sources ?? 0) > 0}></span>{(status?.capture.connected_sources ?? 0) > 0 ? "Connected" : "Idle"}</strong></div>
          <div><span><Binary size={16} /> Active sources</span><strong>{activeSources}</strong></div>
          <div><span><FileText size={16} /> Queue</span><strong>{status?.queue_depth ?? 0} / {status?.queue_capacity ?? 0}</strong></div>
          <div><span><AlertTriangle size={16} /> Read failures</span><strong>{formatNumber(status?.capture.read_failed ?? 0)}</strong></div>
        </div>
        <div class="activity">
          <div><span>Capture activity</span><span>{formatNumber(status?.capture.events_received ?? 0)} events</span></div>
          <div class="bars" aria-hidden="true">
            {#each [28, 42, 24, 52, 35, 68, 40, 78, 55, 88, 62, 72, 48, 83, 58, 74] as height}
              <span style={`height:${height}%`}></span>
            {/each}
          </div>
        </div>
      </section>
    </div>
  </div>
{/if}

<style>
  .session-strip {
    display: grid;
    grid-template-columns: minmax(210px, 1.3fr) repeat(2, minmax(145px, 0.8fr)) auto;
    align-items: center;
    gap: 0;
    min-height: 98px;
    padding: 18px 20px;
  }

  .session-name,
  .strip-stat {
    display: grid;
    gap: 5px;
  }

  .session-name span,
  .strip-stat span,
  .metric small {
    color: var(--muted);
    font-size: 0.75rem;
  }

  .strip-stat {
    padding-left: 22px;
    border-left: 1px solid var(--border);
  }

  .strip-stat strong { font-size: 0.92rem; }

  .session-controls {
    display: flex;
    justify-content: flex-end;
    gap: 9px;
  }

  .metrics {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
  }

  .metric { padding: 18px 20px; }
  .metric > div { display: flex; align-items: center; gap: 9px; color: var(--muted); font-size: 0.78rem; }
  .metric > strong { display: block; margin: 13px 0 5px; font-size: 2rem; line-height: 1; }
  .danger-value { color: var(--danger); }

  .dashboard-grid {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(290px, 0.9fr);
    gap: 12px;
    min-height: 390px;
  }

  .recent,
  .health { min-width: 0; overflow: hidden; }
  .value-cell { max-width: 250px; }
  .value-cell span { display: block; }
  .source { display: inline-flex; align-items: center; gap: 7px; }

  .health-list { padding: 4px 16px; }
  .health-list > div { display: flex; min-height: 47px; align-items: center; justify-content: space-between; gap: 12px; border-bottom: 1px solid var(--border); font-size: 0.8rem; }
  .health-list > div > span,
  .health-list strong { display: flex; align-items: center; gap: 8px; }
  .health-list strong { font-size: 0.78rem; }
  .healthy { color: var(--success); }

  .activity { padding: 16px; }
  .activity > div:first-child { display: flex; justify-content: space-between; color: var(--muted); font-size: 0.74rem; }
  .bars { display: flex; height: 72px; align-items: flex-end; gap: 5px; padding-top: 12px; }
  .bars span { flex: 1; min-width: 3px; border-radius: 2px 2px 0 0; background: var(--accent); opacity: 0.82; }

  @media (max-width: 1190px) {
    .session-strip { grid-template-columns: 1.3fr 1fr auto; }
    .strip-stat:nth-child(3) { display: none; }
    .metrics { grid-template-columns: repeat(2, 1fr); }
  }

  @media (max-width: 900px) {
    .dashboard-grid { grid-template-columns: 1fr; }
  }

  @media (max-width: 759px) {
    .session-strip { grid-template-columns: 1fr; gap: 14px; }
    .strip-stat { padding: 0; border: 0; }
    .session-controls { justify-content: flex-start; }
    .metrics { grid-template-columns: 1fr; }
  }
</style>
