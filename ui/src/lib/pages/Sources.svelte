<script lang="ts">
  import { Folder, Plus, TerminalSquare, Trash2 } from "@lucide/svelte";
  import type { Session, Sources } from "../types";

  export let session: Session | null;
  export let sources: Sources | null;
  export let busy: boolean;
  export let onAdd: (kind: "directory" | "terminal", path: string) => Promise<void>;
  export let onRemove: (kind: "directory" | "terminal", path: string) => Promise<void>;

  let directory = "";
  let terminal = "";
  let error = "";

  async function add(kind: "directory" | "terminal") {
    const path = (kind === "directory" ? directory : terminal).trim();
    if (!path) return;
    try {
      error = "";
      await onAdd(kind, path);
      if (kind === "directory") directory = "";
      else terminal = "";
    } catch (reason) {
      error = reason instanceof Error ? reason.message : String(reason);
    }
  }
</script>

{#if !session}
  <section class="surface empty-state">Create a session before adding capture sources.</section>
{:else}
  <div class="page-stack">
    {#if session.status === "finished"}
      <div class="locked-note">Sources are read-only because this session is finished.</div>
    {/if}
    {#if error}<div class="source-error">{error}</div>{/if}
    <div class="source-grid">
      <section class="surface source-panel">
        <div class="panel-heading"><div><h2>Terminal capture</h2><p>Foreground output from explicitly registered TTYs.</p></div><TerminalSquare size={19} /></div>
        <form onsubmit={(event) => { event.preventDefault(); void add("terminal"); }}>
          <label class="field-label">TTY path<div class="add-row"><input class="field mono" bind:value={terminal} placeholder="/dev/pts/1" /><button class="button primary icon-only" type="submit" aria-label="Add terminal" title="Add terminal" disabled={busy || session.status === "finished"}><Plus size={16} /></button></div></label>
        </form>
        <div class="source-list">
          {#if (sources?.terminals.length ?? 0) === 0}<div class="empty-small">No terminal registered.</div>{/if}
          {#each sources?.terminals ?? [] as path}
            <div><span class="source-icon"><TerminalSquare size={16} /></span><code>{path}</code><span class="source-state"><span class="status-dot" class:success={session.status === "monitoring"}></span>{session.status === "monitoring" ? "Active" : "Idle"}</span><button class="button icon-only" type="button" aria-label="Remove {path}" title="Remove source" disabled={busy || session.status === "finished"} onclick={() => void onRemove("terminal", path)}><Trash2 size={15} /></button></div>
          {/each}
        </div>
      </section>

      <section class="surface source-panel">
        <div class="panel-heading"><div><h2>Watched directories</h2><p>New and changed files are read through the daemon.</p></div><Folder size={19} /></div>
        <form onsubmit={(event) => { event.preventDefault(); void add("directory"); }}>
          <label class="field-label">Directory path<div class="add-row"><input class="field mono" bind:value={directory} placeholder="/home/kali/ctf/output" /><button class="button primary icon-only" type="submit" aria-label="Add directory" title="Add directory" disabled={busy || session.status === "finished"}><Plus size={16} /></button></div></label>
        </form>
        <div class="source-list">
          {#if (sources?.directories.length ?? 0) === 0}<div class="empty-small">No directory watched.</div>{/if}
          {#each sources?.directories ?? [] as path}
            <div><span class="source-icon"><Folder size={16} /></span><code>{path}</code><span class="source-state"><span class="status-dot" class:success={session.status === "monitoring"}></span>{session.status === "monitoring" ? "Active" : "Idle"}</span><button class="button icon-only" type="button" aria-label="Remove {path}" title="Remove source" disabled={busy || session.status === "finished"} onclick={() => void onRemove("directory", path)}><Trash2 size={15} /></button></div>
          {/each}
        </div>
      </section>
    </div>
  </div>
{/if}

<style>
  .source-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; align-items: start; }
  .source-panel { overflow: hidden; }
  .panel-heading > div p { margin: 4px 0 0; color: var(--muted); font-size: 0.73rem; }
  .panel-heading > :global(svg) { color: var(--muted); }
  form { padding: 16px; border-bottom: 1px solid var(--border); }
  .add-row { display: flex; gap: 8px; }
  .source-list > div { display: grid; grid-template-columns: 34px minmax(0, 1fr) auto 36px; align-items: center; gap: 9px; min-height: 56px; padding: 9px 14px; border-bottom: 1px solid var(--border); }
  .source-list > div:last-child { border-bottom: 0; }
  .source-list code { min-width: 0; overflow: hidden; font: 0.76rem "JetBrains Mono", "Noto Sans Mono", monospace; text-overflow: ellipsis; white-space: nowrap; }
  .source-icon { display: grid; width: 30px; height: 30px; place-items: center; border-radius: 6px; background: var(--surface-muted); color: var(--muted); }
  .source-state { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 0.7rem; }
  .empty-small { display: block !important; min-height: 80px !important; padding: 30px 16px !important; color: var(--muted); font-size: 0.78rem; text-align: center; }
  .locked-note,
  .source-error { padding: 10px 13px; border-radius: 8px; background: var(--warning-soft); color: var(--warning); font-size: 0.77rem; }
  .source-error { background: var(--danger-soft); color: var(--danger); }
  @media (max-width: 1000px) { .source-grid { grid-template-columns: 1fr; } }
</style>
