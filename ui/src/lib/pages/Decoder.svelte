<script lang="ts">
  import { ArrowDown, Binary, CheckCircle2, Clipboard, LoaderCircle, Server } from "@lucide/svelte";
  import { candidatePath, confidenceLabel } from "../format";
  import type { AnalysisPreview, Session } from "../types";

  export let session: Session | null;
  export let busy: boolean;
  export let onAnalyze: (text: string) => Promise<AnalysisPreview>;
  export let onSubmit: (text: string) => Promise<number>;

  let input = "SFRCe2xheWVyX2J5X2xheWVyfQ==";
  let preview: AnalysisPreview | null = null;
  let error = "";
  let saved = "";
  let copied = false;

  async function analyze() {
    error = "";
    saved = "";
    if (!input.trim()) {
      error = "Enter text to analyze.";
      return;
    }
    try {
      preview = await onAnalyze(input);
    } catch (reason) {
      error = reason instanceof Error ? reason.message : String(reason);
    }
  }

  async function submit() {
    try {
      const count = await onSubmit(input);
      saved = `${count} ${count === 1 ? "finding" : "findings"} saved to the active session.`;
    } catch (reason) {
      error = reason instanceof Error ? reason.message : String(reason);
    }
  }

  async function copy(value: string) {
    await navigator.clipboard.writeText(value);
    copied = true;
    setTimeout(() => (copied = false), 1_500);
  }
</script>

<div class="decoder-grid">
  <section class="surface input-panel">
    <div class="panel-heading">
      <div><h2>Manual input</h2><p>Paste encoded output, structured data, or a possible flag.</p></div>
    </div>
    <div class="input-body">
      <label class="field-label">Input<textarea class="mono" bind:value={input} spellcheck="false" placeholder="Paste captured text…"></textarea></label>
      <div class="input-meta">
        <span>{new TextEncoder().encode(input).length} bytes</span>
        <span>Session: {session?.name ?? "None"}</span>
      </div>
      {#if error}<p class="message error">{error}</p>{/if}
      {#if saved}<p class="message saved"><CheckCircle2 size={15} /> {saved}</p>{/if}
      <button class="button primary analyze" type="button" disabled={!session || busy} onclick={() => void analyze()}>
        {#if busy}<LoaderCircle size={16} class="spinning" /> Analyzing{:else}<Binary size={16} /> Analyze input{/if}
      </button>
      <div class="service-note"><Server size={18} /><div><strong>Decoded by CTF Hunter</strong><span>The Rust analysis service performs detection, decoding, and scoring. Input is not processed in the browser.</span></div></div>
    </div>
  </section>

  <section class="surface result-panel">
    <div class="panel-heading"><h2>Analysis result</h2>{#if preview}<span class="muted">{preview.statistics.candidate_count} candidates</span>{/if}</div>
    {#if !preview}
      <div class="empty-state"><div><h2>Ready to analyze</h2><p>Results and transformation steps appear here without modifying the session.</p></div></div>
    {:else}
      <div class="result-body">
        <div class="summary-grid">
          <div><span>Detected format</span><strong>{preview.detections[0]?.format ?? "Plain text"}</strong></div>
          <div><span>Confidence</span><strong>{preview.detections[0] ? `${preview.detections[0].confidence}%` : "—"}</strong></div>
          <div><span>Decoded</span><strong>{preview.statistics.decoded_candidates}</strong></div>
          <div><span>Classified</span><strong>{preview.findings.length}</strong></div>
        </div>

        <section class="result-section">
          <h3>Transformation path</h3>
          {#if preview.transformations.length === 0}
            <p class="muted small">No supported encoding was detected.</p>
          {:else}
            <div class="preview-steps">
              <div><span>Input</span><code>{preview.normalized}</code></div>
              {#each preview.transformations as step}
                <ArrowDown size={16} />
                <div><span>{step.name} decode</span><code>{step.output}</code></div>
              {/each}
            </div>
          {/if}
        </section>

        <section class="result-section">
          <h3>Classification</h3>
          {#if preview.findings.length === 0}
            <p class="muted small">No configured flag pattern matched the analyzed candidates.</p>
          {:else}
            {#each preview.findings as finding}
              <div class="classification">
                <div><code>{finding.value}</code><span class="confidence {finding.confidence}">{confidenceLabel(finding.confidence)}</span></div>
                <small>Path {candidatePath(finding.path)}</small>
                <button class="button icon-only" type="button" title="Copy finding" aria-label="Copy finding" onclick={() => void copy(finding.value)}>{#if copied}<CheckCircle2 size={16} />{:else}<Clipboard size={16} />{/if}</button>
              </div>
            {/each}
          {/if}
        </section>

        {#if session?.status === "monitoring"}
          <button class="button" type="button" disabled={busy} onclick={() => void submit()}>Save analysis to {session.name}</button>
        {:else}
          <p class="monitor-note">Start or resume this session to persist manual analysis as an event.</p>
        {/if}
      </div>
    {/if}
  </section>
</div>

<style>
  .decoder-grid { display: grid; grid-template-columns: minmax(330px, 0.82fr) minmax(460px, 1.18fr); gap: 14px; align-items: start; }
  .panel-heading p { margin: 4px 0 0; color: var(--muted); font-size: 0.75rem; }
  .input-body,
  .result-body { display: grid; gap: 16px; padding: 16px; }
  textarea { min-height: 220px; }
  .input-meta { display: flex; justify-content: space-between; color: var(--muted); font-size: 0.71rem; }
  .analyze { width: 100%; }
  .service-note { display: flex; gap: 11px; padding: 12px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-muted); }
  .service-note :global(svg) { flex: 0 0 auto; margin-top: 2px; color: var(--success); }
  .service-note strong,
  .service-note span { display: block; }
  .service-note strong { margin-bottom: 4px; font-size: 0.76rem; }
  .service-note span { color: var(--muted); font-size: 0.69rem; line-height: 1.45; }
  .message { display: flex; align-items: center; gap: 7px; margin: 0; font-size: 0.76rem; }
  .message.error { color: var(--danger); }
  .message.saved { color: var(--success); }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .summary-grid > div { display: grid; gap: 6px; padding: 12px; border-right: 1px solid var(--border); }
  .summary-grid > div:last-child { border-right: 0; }
  .summary-grid span { color: var(--muted); font-size: 0.68rem; }
  .summary-grid strong { font-size: 0.83rem; text-transform: capitalize; }
  .result-section { padding-top: 2px; }
  .small { font-size: 0.76rem; }
  .preview-steps { display: grid; justify-items: center; gap: 7px; }
  .preview-steps > div { width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 7px; background: var(--surface-muted); }
  .preview-steps span { display: block; margin-bottom: 6px; color: var(--muted); font-size: 0.67rem; font-weight: 700; text-transform: capitalize; }
  .preview-steps code { display: block; font: 0.75rem/1.45 "JetBrains Mono", "Noto Sans Mono", monospace; overflow-wrap: anywhere; }
  .classification { position: relative; display: grid; gap: 6px; padding: 12px 48px 12px 12px; border: 1px solid var(--border); border-radius: 8px; background: var(--success-soft); }
  .classification > div { display: flex; flex-wrap: wrap; align-items: center; gap: 9px; }
  .classification code { font: 0.8rem "JetBrains Mono", "Noto Sans Mono", monospace; overflow-wrap: anywhere; }
  .classification small { color: var(--muted); }
  .classification button { position: absolute; top: 10px; right: 10px; }
  .monitor-note { margin: 0; padding: 10px 12px; border-radius: 7px; background: var(--warning-soft); color: var(--warning); font-size: 0.73rem; }

  @media (max-width: 960px) { .decoder-grid { grid-template-columns: 1fr; } }
  @media (max-width: 560px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } .summary-grid > div:nth-child(2) { border-right: 0; } .summary-grid > div:nth-child(-n + 2) { border-bottom: 1px solid var(--border); } }
</style>
