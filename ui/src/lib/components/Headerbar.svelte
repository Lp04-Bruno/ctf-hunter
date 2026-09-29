<script lang="ts">
  import { RefreshCw } from "@lucide/svelte";
  import type { Page, Session } from "../types";

  export let page: Page;
  export let sessions: Session[];
  export let activeSessionId: string | null;
  export let connected: boolean;
  export let refreshing: boolean;
  export let onSelectSession: (id: string) => void;
  export let onRefresh: () => void;

  const titles: Record<Page, [string, string]> = {
    overview: ["Overview", "Monitor activity, discover flags, and inspect capture health."],
    sessions: ["Sessions", "Configure flag formats and control monitoring runs."],
    findings: ["Findings", "Review evidence and follow each transformation path."],
    decoder: ["Decoder", "Inspect encoded input using the daemon analysis pipeline."],
    sources: ["Sources", "Choose the terminals and directories monitored by this session."],
    settings: ["Settings", "Adjust this desktop client without changing the daemon."],
  };

  $: activeSession = sessions.find((session) => session.id === activeSessionId);
</script>

<header class="headerbar">
  <div class="title-block">
    <h1>{titles[page][0]}</h1>
    <p>{titles[page][1]}</p>
  </div>

  <div class="header-actions">
    <label class="session-select">
      <span class="sr-only">Active session</span>
      <select
        value={activeSessionId ?? ""}
        disabled={sessions.length === 0}
        onchange={(event) => onSelectSession(event.currentTarget.value)}
      >
        {#if sessions.length === 0}<option value="">No sessions</option>{/if}
        {#each sessions as session}
          <option value={session.id}>{session.name}</option>
        {/each}
      </select>
    </label>

    <div class="connection" class:offline={!connected} title={connected ? "Daemon connected" : "Daemon unavailable"}>
      <span class:success={connected} class:danger={!connected} class="status-dot"></span>
      <span>{connected ? activeSession?.status === "monitoring" ? "Monitoring" : "Connected" : "Offline"}</span>
    </div>

    <button class="button icon-only" type="button" aria-label="Refresh data" title="Refresh data" onclick={onRefresh}>
      <RefreshCw size={17} class={refreshing ? "spinning" : ""} />
    </button>
  </div>
</header>

<style>
  .headerbar {
    display: flex;
    min-height: 90px;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    padding: 18px 26px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }

  .title-block p {
    margin: 0;
    color: var(--muted);
    font-size: 0.82rem;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .session-select {
    width: 210px;
  }

  .connection {
    display: flex;
    min-height: 38px;
    align-items: center;
    gap: 8px;
    padding: 0 12px;
    border: 1px solid color-mix(in srgb, var(--success) 30%, var(--border));
    border-radius: 8px;
    background: var(--success-soft);
    color: var(--success);
    font-size: 0.79rem;
    font-weight: 700;
  }

  .connection.offline {
    border-color: color-mix(in srgb, var(--danger) 30%, var(--border));
    background: var(--danger-soft);
    color: var(--danger);
  }

  :global(.spinning) {
    animation: spin 700ms linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 759px) {
    .headerbar {
      min-height: 0;
      align-items: stretch;
      flex-direction: column;
      padding: 16px;
    }

    .title-block p {
      display: none;
    }

    .header-actions {
      width: 100%;
    }

    .session-select {
      width: auto;
      flex: 1;
    }

    .connection span:last-child {
      display: none;
    }
  }
</style>
