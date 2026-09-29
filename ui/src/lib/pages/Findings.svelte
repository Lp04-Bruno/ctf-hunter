<script lang="ts">
  import {
    ArrowLeft,
    Check,
    Clipboard,
    FileText,
    Search,
    TerminalSquare,
  } from "@lucide/svelte";
  import {
    candidatePath,
    confidenceLabel,
    relativeTime,
    sourceDetail,
    sourceLabel,
  } from "../format";
  import type { Confidence, FindingDetail, FindingSummary } from "../types";

  export let findings: FindingSummary[];
  export let details: Record<string, FindingDetail>;
  export let selectedId: string | null;
  export let loadingDetail: boolean;
  export let onSelect: (id: string | null) => void;

  let search = "";
  let confidence: "all" | "high" | "possible" = "all";
  let source: "all" | "terminal" | "file" | "manual" = "all";
  let copied = false;

  const rank: Record<Confidence, number> = { low: 0, medium: 1, high: 2, very_high: 3 };
  $: filtered = findings.filter((finding) => {
    const matchesSearch = finding.value.toLowerCase().includes(search.trim().toLowerCase());
    const matchesConfidence =
      confidence === "all" ||
      (confidence === "high" ? rank[finding.confidence] >= 2 : rank[finding.confidence] < 2);
    const findingSource = finding.source?.kind;
    const matchesSource = source === "all" || findingSource === source;
    return matchesSearch && matchesConfidence && matchesSource;
  });
  $: selected = selectedId ? details[selectedId] : undefined;
  $: occurrence = selected?.occurrences[0];

  async function copyValue(value: string) {
    await navigator.clipboard.writeText(value);
    copied = true;
    setTimeout(() => (copied = false), 1_600);
  }
</script>

<div class="findings-shell" class:show-detail={selectedId !== null}>
  <section class="finding-master">
    <div class="filterbar">
      <label class="search-box">
        <Search size={16} />
        <span class="sr-only">Search findings</span>
        <input bind:value={search} placeholder="Search findings…" />
      </label>
      <select bind:value={confidence} aria-label="Confidence filter">
        <option value="all">All confidence</option>
        <option value="high">High & above</option>
        <option value="possible">Possible flags</option>
      </select>
      <select bind:value={source} aria-label="Source filter">
        <option value="all">All sources</option>
        <option value="terminal">Terminal</option>
        <option value="file">File</option>
        <option value="manual">Manual</option>
      </select>
    </div>

    <div class="finding-columns"><span>Value</span><span>Confidence</span><span>Source</span><span>Seen</span></div>
    <div class="finding-rows">
      {#if filtered.length === 0}
        <div class="empty-state">No findings match these filters.</div>
      {:else}
        {#each filtered as finding}
          <button type="button" class:selected={finding.id === selectedId} onclick={() => onSelect(finding.id)}>
            <span class="mono truncate value">{finding.value}</span>
            <span>{confidenceLabel(finding.confidence)}</span>
            <span class="source-label">
              {#if finding.source?.kind === "terminal"}<TerminalSquare size={14} />{:else}<FileText size={14} />{/if}
              {sourceLabel(finding.source ?? undefined)}
            </span>
            <span>{relativeTime(finding.discovered_at)}</span>
          </button>
        {/each}
      {/if}
    </div>
    <footer>{filtered.length} {filtered.length === 1 ? "finding" : "findings"}</footer>
  </section>

  <section class="finding-detail">
    {#if loadingDetail}
      <div class="empty-state">Loading finding detail…</div>
    {:else if selected}
      <div class="detail-scroll">
        <button class="back button" type="button" onclick={() => onSelect(null)}><ArrowLeft size={15} /> Findings</button>
        <header class="detail-header">
          <div>
            <h2 class="mono">{selected.summary.value}</h2>
            <div class="detail-meta">
              <span class="confidence {selected.summary.confidence}">{confidenceLabel(selected.summary.confidence)} confidence</span>
              <span>First seen {relativeTime(selected.summary.discovered_at)}</span>
              <span>Occurrences {selected.summary.occurrences}</span>
            </div>
          </div>
          <button class="button" type="button" onclick={() => copyValue(selected.summary.value)}>
            {#if copied}<Check size={15} /> Copied{:else}<Clipboard size={15} /> Copy{/if}
          </button>
        </header>

        <div class="origin-grid">
          <section class="detail-card">
            <h3>Origin</h3>
            <dl>
              <dt>Source</dt><dd>{sourceLabel(occurrence?.source)}</dd>
              <dt>Details</dt><dd class="mono">{sourceDetail(occurrence?.source)}</dd>
              <dt>Observed</dt><dd>{occurrence ? relativeTime(occurrence.observed_at) : "Unknown"}</dd>
            </dl>
          </section>
          <section class="detail-card">
            <h3>Candidate path</h3>
            <div class="code-field mono">{candidatePath(occurrence?.path ?? [])}</div>
          </section>
        </div>

        <section class="detail-card transformation-card">
          <h3>Transformation path</h3>
          <ol class="steps">
            <li>
              <span class="step-index">1</span>
              <div><strong>Raw candidate</strong><code>{occurrence?.candidate_text ?? "Candidate data unavailable"}</code></div>
            </li>
            {#each occurrence?.transformations ?? [] as transformation, index}
              <li>
                <span class="step-index">{index + 2}</span>
                <div><strong>{transformation.name} decode</strong><code>{index === (occurrence?.transformations.length ?? 0) - 1 ? selected.summary.value : "Decoded intermediate candidate"}</code></div>
              </li>
            {/each}
            <li>
              <span class="step-index matched">{(occurrence?.transformations.length ?? 0) + 2}</span>
              <div><strong>Matched flag</strong><code>{selected.summary.value}</code></div>
            </li>
          </ol>
        </section>

        <section class="detail-card">
          <h3>Relevant fragment</h3>
          <pre>{occurrence?.candidate_text ?? selected.summary.value}</pre>
          {#if occurrence?.candidate_truncated}<p class="truncated-note">Stored fragment was truncated from {occurrence.candidate_original_length} bytes.</p>{/if}
        </section>

        <section class="detail-card occurrences">
          <h3>{selected.summary.occurrences} {selected.summary.occurrences === 1 ? "occurrence" : "occurrences"}</h3>
          {#each selected.occurrences as item}
            <div><span>{relativeTime(item.observed_at)}</span><span>{sourceLabel(item.source)}</span><span class="mono truncate">{sourceDetail(item.source)}</span></div>
          {/each}
          {#if selected.occurrences_truncated}<p class="muted">Only the first occurrences are shown.</p>{/if}
        </section>
      </div>
    {:else}
      <div class="empty-state"><div><h2>Select a finding</h2><p>Choose a row to inspect its source, candidate path, and transformations.</p></div></div>
    {/if}
  </section>
</div>

<style>
  .findings-shell { display: grid; grid-template-columns: minmax(420px, 0.86fr) minmax(520px, 1.14fr); min-height: calc(100vh - 139px); margin: -22px -24px; background: var(--surface); }
  .finding-master { display: grid; min-width: 0; grid-template-rows: auto auto minmax(0, 1fr) auto; border-right: 1px solid var(--border); }
  .filterbar { display: grid; grid-template-columns: minmax(170px, 1fr) 150px 130px; gap: 8px; padding: 12px; border-bottom: 1px solid var(--border); }
  .search-box { display: flex; min-height: 38px; align-items: center; gap: 8px; padding: 0 10px; border: 1px solid var(--border-strong); border-radius: 8px; background: var(--surface); color: var(--muted); }
  .search-box input { min-width: 0; flex: 1; border: 0; outline: 0; background: transparent; }
  .finding-columns,
  .finding-rows button { display: grid; grid-template-columns: minmax(160px, 1.45fr) 96px 100px 70px; align-items: center; gap: 10px; }
  .finding-columns { padding: 9px 12px; border-bottom: 1px solid var(--border); background: var(--surface-muted); color: var(--muted); font-size: 0.69rem; font-weight: 750; letter-spacing: 0.025em; text-transform: uppercase; }
  .finding-rows { overflow-y: auto; }
  .finding-rows button { width: 100%; min-height: 46px; padding: 8px 12px; border: 0; border-bottom: 1px solid var(--border); background: transparent; color: var(--text); font-size: 0.77rem; text-align: left; }
  .finding-rows button:hover,
  .finding-rows button.selected { background: var(--surface-hover); }
  .finding-rows button.selected { box-shadow: inset 3px 0 var(--accent); }
  .finding-rows .value { color: var(--text); font-weight: 650; }
  .source-label { display: inline-flex; align-items: center; gap: 6px; }
  .finding-master footer { padding: 9px 12px; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.71rem; }
  .finding-detail { min-width: 0; background: var(--canvas); }
  .detail-scroll { height: 100%; padding: 20px; overflow-y: auto; }
  .back { display: none; margin-bottom: 12px; }
  .detail-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 16px; }
  .detail-header h2 { margin: 0 0 9px; font-size: 1.2rem; overflow-wrap: anywhere; }
  .detail-meta { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 14px; color: var(--muted); font-size: 0.75rem; }
  .origin-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .detail-card { min-width: 0; margin-bottom: 10px; padding: 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); }
  .detail-card h3 { margin-bottom: 11px; }
  dl { display: grid; grid-template-columns: 70px minmax(0, 1fr); gap: 7px 10px; margin: 0; font-size: 0.77rem; }
  dt { color: var(--muted); }
  dd { min-width: 0; margin: 0; overflow-wrap: anywhere; }
  .code-field,
  pre,
  code { border: 1px solid var(--border); border-radius: 6px; background: var(--surface-muted); }
  .code-field { padding: 10px; font-size: 0.77rem; overflow-wrap: anywhere; }
  .steps { display: grid; gap: 0; margin: 0; padding: 0; list-style: none; }
  .steps li { position: relative; display: grid; grid-template-columns: 28px 1fr; gap: 10px; min-height: 64px; }
  .steps li:not(:last-child)::after { position: absolute; width: 1px; top: 25px; bottom: 0; left: 11px; background: var(--border-strong); content: ""; }
  .step-index { position: relative; z-index: 1; display: grid; width: 23px; height: 23px; place-items: center; border-radius: 50%; background: var(--accent); color: white; font-size: 0.69rem; font-weight: 750; }
  .step-index.matched { background: var(--success); }
  .steps strong { display: block; margin: 3px 0 7px; font-size: 0.77rem; text-transform: capitalize; }
  .steps code { display: block; padding: 7px 9px; color: var(--muted); font-size: 0.72rem; overflow-wrap: anywhere; }
  pre { margin: 0; padding: 12px; overflow: auto; color: var(--text); font: 0.74rem/1.6 "JetBrains Mono", "Noto Sans Mono", monospace; white-space: pre-wrap; }
  .truncated-note { margin: 8px 0 0; color: var(--warning); font-size: 0.72rem; }
  .occurrences > div { display: grid; grid-template-columns: 72px 70px minmax(0, 1fr); gap: 10px; padding: 9px 0; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.72rem; }

  @media (max-width: 1150px) {
    .findings-shell { grid-template-columns: minmax(340px, 0.8fr) minmax(440px, 1.2fr); }
    .filterbar { grid-template-columns: 1fr 140px; }
    .filterbar select:last-child { display: none; }
    .finding-columns,
    .finding-rows button { grid-template-columns: minmax(150px, 1.4fr) 86px 68px; }
    .finding-columns span:nth-child(3),
    .finding-rows button > span:nth-child(3) { display: none; }
  }

  @media (max-width: 820px) {
    .findings-shell { display: block; min-height: calc(100vh - 180px); }
    .finding-master,
    .finding-detail { min-height: calc(100vh - 180px); }
    .findings-shell.show-detail .finding-master { display: none; }
    .findings-shell:not(.show-detail) .finding-detail { display: none; }
    .back { display: inline-flex; }
  }

  @media (max-width: 560px) {
    .origin-grid { grid-template-columns: 1fr; }
    .detail-header { flex-direction: column; }
  }
</style>
