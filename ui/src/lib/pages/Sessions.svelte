<script lang="ts">
  import { CalendarClock, Edit3, Pause, Play, Plus, Square } from "@lucide/svelte";
  import { relativeTime } from "../format";
  import type { Session } from "../types";
  import Modal from "../components/Modal.svelte";

  export let sessions: Session[];
  export let activeSessionId: string | null;
  export let busy: boolean;
  export let onSelect: (id: string) => void;
  export let onSave: (session: Session | null, name: string, patterns: string[]) => Promise<void>;
  export let onTransition: (session: Session, action: "start" | "pause" | "resume" | "stop") => void;

  let editing: Session | null | undefined = undefined;
  let name = "";
  let patternsText = "";
  let formError = "";

  function open(session: Session | null) {
    editing = session;
    name = session?.name ?? "";
    patternsText = session?.flag_patterns.join("\n") ?? "HTB{*}";
    formError = "";
  }

  async function save() {
    const patterns = patternsText.split("\n").map((value) => value.trim()).filter(Boolean);
    if (!name.trim()) {
      formError = "Enter a session name.";
      return;
    }
    if (patterns.length === 0) {
      formError = "Add at least one flag pattern.";
      return;
    }
    try {
      await onSave(editing ?? null, name.trim(), patterns);
      editing = undefined;
    } catch (error) {
      formError = error instanceof Error ? error.message : String(error);
    }
  }
</script>

<div class="page-stack">
  <div class="toolbar">
    <div class="grow muted">{sessions.length} {sessions.length === 1 ? "session" : "sessions"}</div>
    <button class="button primary" type="button" onclick={() => open(null)}><Plus size={16} /> New session</button>
  </div>

  <section class="surface session-list">
    {#if sessions.length === 0}
      <div class="empty-state">No sessions have been created.</div>
    {:else}
      {#each sessions as session}
        <article class:active={session.id === activeSessionId}>
          <button class="session-main" type="button" onclick={() => onSelect(session.id)}>
            <span class="session-icon"><CalendarClock size={19} /></span>
            <span class="session-copy">
              <span><strong>{session.name}</strong><span class="status-badge {session.status}">{session.status}</span></span>
              <small>Created {relativeTime(session.created_at)} · {session.flag_patterns.join(", ") || "No patterns"}</small>
            </span>
          </button>
          <div class="session-actions">
            {#if session.status === "inactive" || session.status === "paused"}
              <button class="button icon-only" type="button" title="Edit session" aria-label="Edit {session.name}" disabled={busy} onclick={() => open(session)}><Edit3 size={16} /></button>
            {/if}
            {#if session.status === "inactive"}
              <button class="button primary" type="button" disabled={busy} onclick={() => onTransition(session, "start")}><Play size={15} /> Start</button>
            {:else if session.status === "monitoring"}
              <button class="button" type="button" disabled={busy} onclick={() => onTransition(session, "pause")}><Pause size={15} /> Pause</button>
              <button class="button danger icon-only" type="button" title="Stop session" aria-label="Stop {session.name}" disabled={busy} onclick={() => onTransition(session, "stop")}><Square size={13} /></button>
            {:else if session.status === "paused"}
              <button class="button primary" type="button" disabled={busy} onclick={() => onTransition(session, "resume")}><Play size={15} /> Resume</button>
              <button class="button danger icon-only" type="button" title="Stop session" aria-label="Stop {session.name}" disabled={busy} onclick={() => onTransition(session, "stop")}><Square size={13} /></button>
            {/if}
          </div>
        </article>
      {/each}
    {/if}
  </section>
</div>

{#if editing !== undefined}
  <Modal title={editing ? "Edit session" : "New session"} onClose={() => (editing = undefined)}>
    <form onsubmit={(event) => { event.preventDefault(); void save(); }}>
      <label class="field-label">Session name<input class="field" bind:value={name} maxlength="256" autocomplete="off" /></label>
      <label class="field-label">Flag patterns<textarea class="mono" bind:value={patternsText} rows="5" spellcheck="false"></textarea><small>One pattern per line. Wildcards use the daemon's existing pattern syntax.</small></label>
      {#if formError}<p class="form-error">{formError}</p>{/if}
      <div class="form-actions">
        <button class="button" type="button" onclick={() => (editing = undefined)}>Cancel</button>
        <button class="button primary" type="submit" disabled={busy}>{editing ? "Save changes" : "Create session"}</button>
      </div>
    </form>
  </Modal>
{/if}

<style>
  .toolbar .muted { font-size: 0.82rem; }
  .session-list { overflow: hidden; }
  article { display: flex; min-height: 82px; align-items: center; gap: 14px; padding: 10px 14px 10px 8px; border-bottom: 1px solid var(--border); }
  article:last-child { border-bottom: 0; }
  article.active { background: var(--surface-hover); box-shadow: inset 3px 0 var(--accent); }
  .session-main { display: flex; min-width: 0; flex: 1; align-items: center; gap: 13px; padding: 8px; border: 0; background: transparent; color: var(--text); text-align: left; }
  .session-icon { display: grid; width: 38px; height: 38px; flex: 0 0 auto; place-items: center; border-radius: 8px; background: var(--surface-muted); color: var(--muted); }
  .session-copy { display: grid; min-width: 0; gap: 7px; }
  .session-copy > span { display: flex; align-items: center; gap: 9px; }
  .session-copy small { overflow: hidden; color: var(--muted); font-size: 0.75rem; text-overflow: ellipsis; white-space: nowrap; }
  .session-actions { display: flex; gap: 8px; }
  form { display: grid; gap: 17px; }
  .field-label small { color: var(--subtle); font-weight: 400; }
  .form-error { margin: 0; color: var(--danger); font-size: 0.8rem; }
  .form-actions { display: flex; justify-content: flex-end; gap: 8px; padding-top: 4px; }

  @media (max-width: 640px) {
    article { align-items: stretch; flex-direction: column; }
    .session-actions { padding: 0 8px 8px 59px; }
  }
</style>
