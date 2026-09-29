<script lang="ts">
  import { Eye, Monitor, Moon, ShieldCheck, Sun } from "@lucide/svelte";

  export let theme: "system" | "light" | "dark";
  export let refreshInterval: number;
  export let previewMode: boolean;
  export let onTheme: (theme: "system" | "light" | "dark") => void;
  export let onRefreshInterval: (seconds: number) => void;
</script>

<div class="settings-stack">
  <section class="surface settings-section">
    <div class="section-title"><Monitor size={18} /><div><h2>Appearance</h2><p>Match the desktop or choose a fixed application theme.</p></div></div>
    <div class="theme-options" role="radiogroup" aria-label="Color theme">
      <button type="button" class:active={theme === "system"} role="radio" aria-checked={theme === "system"} onclick={() => onTheme("system")}><Monitor size={18} /><strong>System</strong><span>Follow Linux appearance</span></button>
      <button type="button" class:active={theme === "light"} role="radio" aria-checked={theme === "light"} onclick={() => onTheme("light")}><Sun size={18} /><strong>Light</strong><span>Bright neutral surfaces</span></button>
      <button type="button" class:active={theme === "dark"} role="radio" aria-checked={theme === "dark"} onclick={() => onTheme("dark")}><Moon size={18} /><strong>Dark</strong><span>Low-light workspace</span></button>
    </div>
  </section>

  <section class="surface settings-section">
    <div class="section-title"><Eye size={18} /><div><h2>Data refresh</h2><p>Polling is limited to this desktop client and does not alter daemon capture.</p></div></div>
    <label class="setting-row"><span><strong>Automatic refresh</strong><small>Status, sessions, sources, and findings</small></span><select value={refreshInterval} onchange={(event) => onRefreshInterval(Number(event.currentTarget.value))}><option value="0">Off</option><option value="5">Every 5 seconds</option><option value="15">Every 15 seconds</option><option value="30">Every 30 seconds</option></select></label>
    <div class="setting-row"><span><strong>Daemon socket</strong><small>Unix-domain IPC; never exposed to frontend JavaScript</small></span><code>$XDG_RUNTIME_DIR/ctf-hunter/daemon.sock</code></div>
  </section>

  <section class="surface settings-section">
    <div class="section-title"><ShieldCheck size={18} /><div><h2>Privacy boundary</h2><p>The GUI is a client. Closing it never stops capture or the daemon.</p></div></div>
    <ul>
      <li>Decoder and scoring execute in the Rust daemon.</li>
      <li>The Tauri layer is the only component that opens the Unix socket.</li>
      <li>Raw event payloads are not persisted by the desktop interface.</li>
    </ul>
    {#if previewMode}<div class="preview-note">Browser preview mode is active. Sample data is used only by the Vite development server; packaged builds always use Tauri IPC.</div>{/if}
  </section>
</div>

<style>
  .settings-stack { display: grid; max-width: 880px; gap: 14px; }
  .settings-section { padding: 18px; }
  .section-title { display: flex; gap: 11px; margin-bottom: 16px; }
  .section-title > :global(svg) { margin-top: 2px; color: var(--muted); }
  .section-title h2 { margin-bottom: 4px; }
  .section-title p { margin: 0; color: var(--muted); font-size: 0.76rem; }
  .theme-options { display: grid; grid-template-columns: repeat(3, 1fr); gap: 9px; }
  .theme-options button { display: grid; min-height: 102px; justify-items: start; gap: 5px; padding: 13px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text); text-align: left; }
  .theme-options button:hover { background: var(--surface-muted); }
  .theme-options button.active { border-color: var(--accent); background: var(--accent-soft); box-shadow: inset 0 0 0 1px var(--accent); }
  .theme-options button :global(svg) { color: var(--muted); }
  .theme-options strong { font-size: 0.8rem; }
  .theme-options span { color: var(--muted); font-size: 0.7rem; }
  .setting-row { display: flex; min-height: 62px; align-items: center; justify-content: space-between; gap: 18px; padding: 10px 0; border-top: 1px solid var(--border); }
  .setting-row > span { display: grid; gap: 4px; }
  .setting-row strong { font-size: 0.8rem; }
  .setting-row small { color: var(--muted); }
  .setting-row select { width: 180px; }
  .setting-row code { padding: 7px 9px; border-radius: 6px; background: var(--surface-muted); font: 0.72rem "JetBrains Mono", "Noto Sans Mono", monospace; }
  ul { display: grid; gap: 8px; margin: 0; padding-left: 22px; color: var(--muted); font-size: 0.77rem; }
  .preview-note { margin-top: 15px; padding: 10px 12px; border-radius: 7px; background: var(--accent-soft); color: var(--accent); font-size: 0.73rem; }
  @media (max-width: 600px) { .theme-options { grid-template-columns: 1fr; } .setting-row { align-items: stretch; flex-direction: column; } .setting-row select { width: 100%; } .setting-row code { overflow-wrap: anywhere; } }
</style>
