<script lang="ts">
  import { CheckCircle2, CircleAlert, Clock3, RefreshCw, ShieldCheck } from "@lucide/svelte";
  import type { HealthCheck, RuntimeDiagnostics } from "../types";

  export let diagnostics: RuntimeDiagnostics | null;
  export let busy: boolean;
  export let onRefresh: () => void;
  export let onEnableCapture: () => void;

  $: checks = diagnostics
    ? [
        diagnostics.user_daemon,
        diagnostics.capture_service,
        diagnostics.kernel_btf,
        diagnostics.terminal_access,
      ]
    : [];

  function statusLabel(check: HealthCheck) {
    if (check.status === "ready") return "Ready";
    if (check.status === "pending") return "Sign-in required";
    if (check.status === "attention") return "Setup needed";
    return "Unavailable";
  }
</script>

<section class="surface readiness-section">
  <div class="readiness-heading">
    <div class="section-title">
      <ShieldCheck size={18} />
      <div>
        <h2>System readiness</h2>
        <p>Local services and terminal-capture permissions.</p>
      </div>
    </div>
    <button class="button icon-only" type="button" aria-label="Refresh system checks" title="Refresh system checks" disabled={busy} onclick={onRefresh}>
      <span class:spinning={busy}><RefreshCw size={16} /></span>
    </button>
  </div>

  {#if diagnostics}
    <div class="health-grid">
      {#each checks as check}
        <article class="health-item" class:ready={check.status === "ready"} class:pending={check.status === "pending"} class:problem={check.status === "attention" || check.status === "unavailable"}>
          <div class="health-icon">
            {#if check.status === "ready"}
              <CheckCircle2 size={18} />
            {:else if check.status === "pending"}
              <Clock3 size={18} />
            {:else}
              <CircleAlert size={18} />
            {/if}
          </div>
          <div class="health-copy">
            <div class="health-title"><strong>{check.title}</strong><span>{statusLabel(check)}</span></div>
            <p>{check.detail}</p>
            {#if check.recovery_command}
              <code>{check.recovery_command}</code>
            {/if}
          </div>
        </article>
      {/each}
    </div>

    {#if diagnostics.setup_available}
      <div class="setup-action">
        <div>
          <strong>Enable terminal capture</strong>
          <p>An administrator dialog adds only your current account to the package-created <code>ctf-hunter</code> group. No command text from the interface is executed.</p>
        </div>
        <button class="button primary" type="button" disabled={busy} onclick={onEnableCapture}>Enable terminal capture</button>
      </div>
    {:else if diagnostics.requires_new_login}
      <div class="setup-action pending-action">
        <div>
          <strong>One final sign-in is required</strong>
          <p>Save your work, sign out of the Linux desktop completely, and sign back in. This refreshes the account's group membership.</p>
        </div>
      </div>
    {:else if diagnostics.terminal_capture_ready}
      <div class="ready-note"><CheckCircle2 size={16} /> Terminal capture is ready. The desktop interface and daemon remain unprivileged.</div>
    {/if}
  {:else}
    <div class="diagnostic-loading">System checks have not run yet.</div>
  {/if}
</section>

<style>
  .readiness-section { padding: 18px; }
  .readiness-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
  .section-title { display: flex; gap: 11px; margin-bottom: 16px; }
  .section-title > :global(svg) { margin-top: 2px; color: var(--muted); }
  .section-title h2 { margin-bottom: 4px; }
  .section-title p { margin: 0; color: var(--muted); font-size: 0.76rem; }
  .health-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); overflow: hidden; border: 1px solid var(--border); border-radius: 8px; }
  .health-item { display: flex; min-width: 0; gap: 11px; padding: 14px; border-bottom: 1px solid var(--border); }
  .health-item:nth-child(odd) { border-right: 1px solid var(--border); }
  .health-item:nth-last-child(-n + 2) { border-bottom: 0; }
  .health-icon { flex: 0 0 auto; color: var(--danger); }
  .health-item.ready .health-icon { color: var(--success); }
  .health-item.pending .health-icon { color: var(--warning); }
  .health-copy { min-width: 0; flex: 1; }
  .health-title { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
  .health-title strong { font-size: 0.8rem; }
  .health-title span { color: var(--muted); font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.045em; }
  .health-item.ready .health-title span { color: var(--success); }
  .health-item.pending .health-title span { color: var(--warning); }
  .health-item.problem .health-title span { color: var(--danger); }
  .health-copy p { margin: 5px 0 0; color: var(--muted); font-size: 0.72rem; line-height: 1.45; }
  .health-copy code { display: block; margin-top: 9px; padding: 7px 8px; overflow-x: auto; border-radius: 6px; background: var(--surface-muted); font: 0.68rem "JetBrains Mono", "Noto Sans Mono", monospace; white-space: nowrap; }
  .setup-action { display: flex; align-items: center; justify-content: space-between; gap: 20px; margin-top: 12px; padding: 13px 14px; border: 1px solid color-mix(in srgb, var(--accent) 28%, var(--border)); border-radius: 8px; background: var(--accent-soft); }
  .setup-action strong { font-size: 0.8rem; }
  .setup-action p { max-width: 590px; margin: 4px 0 0; color: var(--muted); font-size: 0.72rem; line-height: 1.45; }
  .setup-action code { font: inherit; font-weight: 700; }
  .pending-action { border-color: color-mix(in srgb, var(--warning) 35%, var(--border)); background: var(--warning-soft); }
  .ready-note { display: flex; align-items: center; gap: 8px; margin-top: 12px; padding: 10px 12px; border-radius: 7px; background: var(--success-soft); color: var(--success); font-size: 0.73rem; font-weight: 650; }
  .diagnostic-loading { padding: 20px; border: 1px dashed var(--border-strong); border-radius: 8px; color: var(--muted); text-align: center; font-size: 0.76rem; }
  .spinning { display: inline-flex; animation: spin 900ms linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (max-width: 680px) {
    .health-grid { grid-template-columns: 1fr; }
    .health-item:nth-child(odd) { border-right: 0; }
    .health-item:nth-last-child(2) { border-bottom: 1px solid var(--border); }
    .setup-action { align-items: stretch; flex-direction: column; }
  }
</style>
