<script lang="ts">
  import { onMount } from "svelte";
  import { AlertCircle, CheckCircle2 } from "@lucide/svelte";
  import { api, usesPreviewData } from "./lib/api";
  import Headerbar from "./lib/components/Headerbar.svelte";
  import Sidebar from "./lib/components/Sidebar.svelte";
  import Decoder from "./lib/pages/Decoder.svelte";
  import Findings from "./lib/pages/Findings.svelte";
  import Overview from "./lib/pages/Overview.svelte";
  import Sessions from "./lib/pages/Sessions.svelte";
  import Settings from "./lib/pages/Settings.svelte";
  import SourcesPage from "./lib/pages/Sources.svelte";
  import type {
    AnalysisPreview,
    DaemonStatus,
    FindingDetail,
    FindingSummary,
    Page,
    Session,
    Sources,
  } from "./lib/types";

  let page: Page = "overview";
  let sessions: Session[] = [];
  let activeSessionId: string | null = null;
  let status: DaemonStatus | null = null;
  let findings: FindingSummary[] = [];
  let findingDetails: Record<string, FindingDetail> = {};
  let selectedFindingId: string | null = null;
  let sources: Sources | null = null;
  let connected = false;
  let refreshing = false;
  let busy = false;
  let loadingDetail = false;
  let error = "";
  let toast = "";
  let refreshInterval = 15;
  let theme: "system" | "light" | "dark" = "system";
  let pollingTimer: ReturnType<typeof setInterval> | undefined;

  $: activeSession = sessions.find((session) => session.id === activeSessionId) ?? null;

  function showToast(message: string) {
    toast = message;
    setTimeout(() => {
      if (toast === message) toast = "";
    }, 2_200);
  }

  async function loadScoped(sessionId: string, selectDefault = false) {
    const [nextFindings, nextSources] = await Promise.all([
      api.findings(sessionId),
      api.sources(sessionId),
    ]);
    findings = nextFindings;
    sources = nextSources;
    const selectedStillExists = findings.some((finding) => finding.id === selectedFindingId);
    if (!selectedStillExists) selectedFindingId = selectDefault ? findings[0]?.id ?? null : null;
    if (selectedFindingId) await loadFinding(selectedFindingId);
  }

  async function refresh(selectDefault = false) {
    if (refreshing) return;
    refreshing = true;
    try {
      const [nextStatus, nextSessions] = await Promise.all([api.status(), api.sessions()]);
      status = nextStatus;
      sessions = nextSessions;
      connected = true;
      error = "";
      let nextActiveId = activeSessionId;
      if (!nextActiveId || !sessions.some((session) => session.id === nextActiveId)) {
        nextActiveId = sessions.find((session) => session.status === "monitoring")?.id ?? sessions[0]?.id ?? null;
      }
      activeSessionId = nextActiveId;
      if (nextActiveId) await loadScoped(nextActiveId, selectDefault);
      else {
        findings = [];
        sources = null;
        selectedFindingId = null;
      }
    } catch (reason) {
      connected = false;
      error = reason instanceof Error ? reason.message : String(reason);
    } finally {
      refreshing = false;
    }
  }

  async function loadFinding(id: string) {
    selectedFindingId = id;
    if (findingDetails[id]) return;
    loadingDetail = true;
    try {
      const detail = await api.finding(id);
      if (detail) findingDetails = { ...findingDetails, [id]: detail };
    } catch (reason) {
      error = reason instanceof Error ? reason.message : String(reason);
    } finally {
      loadingDetail = false;
    }
  }

  async function selectSession(id: string) {
    activeSessionId = id;
    selectedFindingId = null;
    findingDetails = {};
    try {
      await loadScoped(id, page === "findings");
    } catch (reason) {
      error = reason instanceof Error ? reason.message : String(reason);
    }
  }

  async function transition(session: Session, action: "start" | "pause" | "resume" | "stop") {
    busy = true;
    try {
      const updated = await api.transitionSession(session.id, action);
      sessions = sessions.map((item) => (item.id === updated.id ? updated : item));
      activeSessionId = updated.id;
      showToast(`Session ${action === "stop" ? "stopped" : action === "pause" ? "paused" : "is monitoring"}.`);
      await refresh();
    } catch (reason) {
      error = reason instanceof Error ? reason.message : String(reason);
    } finally {
      busy = false;
    }
  }

  async function saveSession(session: Session | null, name: string, patterns: string[]) {
    busy = true;
    try {
      const saved = session
        ? await api.updateSession(session.id, name, patterns)
        : await api.createSession(name, patterns);
      sessions = session
        ? sessions.map((item) => (item.id === saved.id ? saved : item))
        : [saved, ...sessions];
      activeSessionId = saved.id;
      findings = [];
      sources = { directories: [], terminals: [] };
      showToast(session ? "Session updated." : "Session created.");
    } finally {
      busy = false;
    }
  }

  async function addSource(kind: "directory" | "terminal", path: string) {
    if (!activeSessionId || !sources) return;
    busy = true;
    try {
      const values = await api.addSource(activeSessionId, kind, path);
      sources = { ...sources, [kind === "directory" ? "directories" : "terminals"]: values };
      showToast(kind === "directory" ? "Directory added." : "Terminal added.");
    } finally {
      busy = false;
    }
  }

  async function removeSource(kind: "directory" | "terminal", path: string) {
    if (!activeSessionId || !sources) return;
    busy = true;
    try {
      const values = await api.removeSource(activeSessionId, kind, path);
      sources = { ...sources, [kind === "directory" ? "directories" : "terminals"]: values };
      showToast("Source removed.");
    } finally {
      busy = false;
    }
  }

  async function analyze(text: string): Promise<AnalysisPreview> {
    if (!activeSessionId) throw new Error("Select a session first.");
    busy = true;
    try {
      return await api.preview(activeSessionId, text);
    } finally {
      busy = false;
    }
  }

  async function submit(text: string): Promise<number> {
    if (!activeSessionId) throw new Error("Select a session first.");
    busy = true;
    try {
      const result = await api.submit(activeSessionId, text);
      await loadScoped(activeSessionId);
      return result.finding_ids.length;
    } finally {
      busy = false;
    }
  }

  function navigate(next: Page) {
    page = next;
    if (next === "findings" && !selectedFindingId && findings[0]) void loadFinding(findings[0].id);
  }

  function applyTheme(next: "system" | "light" | "dark") {
    theme = next;
    localStorage.setItem("ctf-hunter-theme", next);
    if (next === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = next;
  }

  function applyRefreshInterval(seconds: number) {
    refreshInterval = seconds;
    localStorage.setItem("ctf-hunter-refresh", String(seconds));
    if (pollingTimer) clearInterval(pollingTimer);
    pollingTimer = seconds > 0 ? setInterval(() => void refresh(), seconds * 1_000) : undefined;
  }

  onMount(() => {
    const savedTheme = localStorage.getItem("ctf-hunter-theme");
    if (savedTheme === "light" || savedTheme === "dark" || savedTheme === "system") applyTheme(savedTheme);
    const savedRefresh = Number(localStorage.getItem("ctf-hunter-refresh") ?? "15");
    applyRefreshInterval(Number.isFinite(savedRefresh) ? savedRefresh : 15);
    void refresh(true);
    return () => {
      if (pollingTimer) clearInterval(pollingTimer);
    };
  });
</script>

<div class="app-shell">
  <Sidebar {page} onNavigate={navigate} />
  <div class="workspace">
    <Headerbar
      {page}
      {sessions}
      {activeSessionId}
      {connected}
      {refreshing}
      onSelectSession={(id) => void selectSession(id)}
      onRefresh={() => void refresh()}
    />
    {#if error}
      <div class="error-banner"><AlertCircle size={16} /><span>{error}</span><button type="button" onclick={() => (error = "")}>Dismiss</button></div>
    {/if}
    <main>
      {#if page === "overview"}
        <Overview
          session={activeSession}
          {status}
          {findings}
          {busy}
          onTransition={(action) => activeSession && void transition(activeSession, action)}
          onNavigate={navigate}
        />
      {:else if page === "sessions"}
        <Sessions
          {sessions}
          {activeSessionId}
          {busy}
          onSelect={(id) => void selectSession(id)}
          onSave={saveSession}
          onTransition={(session, action) => void transition(session, action)}
        />
      {:else if page === "findings"}
        <Findings
          {findings}
          details={findingDetails}
          selectedId={selectedFindingId}
          {loadingDetail}
          onSelect={(id) => (id ? void loadFinding(id) : (selectedFindingId = null))}
        />
      {:else if page === "decoder"}
        <Decoder session={activeSession} {busy} onAnalyze={analyze} onSubmit={submit} />
      {:else if page === "sources"}
        <SourcesPage session={activeSession} {sources} {busy} onAdd={addSource} onRemove={removeSource} />
      {:else}
        <Settings
          {theme}
          {refreshInterval}
          previewMode={usesPreviewData}
          onTheme={applyTheme}
          onRefreshInterval={applyRefreshInterval}
        />
      {/if}
    </main>
    <footer class="statusbar">
      <span>ctf-hunterd · schema {status?.schema_version ?? "—"} · protocol v1</span>
      <span class:preview={usesPreviewData}><span class="status-dot" class:success={connected}></span>{usesPreviewData ? "Preview data" : connected ? "Socket connected" : "Socket unavailable"}</span>
    </footer>
  </div>
</div>

{#if toast}
  <div class="toast" role="status"><CheckCircle2 size={16} />{toast}</div>
{/if}

<style>
  .app-shell { display: flex; min-height: 100vh; background: var(--canvas); color: var(--text); }
  .workspace { display: grid; min-width: 0; height: 100vh; flex: 1; grid-template-rows: auto auto minmax(0, 1fr) 36px; }
  main { padding: 22px 24px; overflow: auto; }
  .statusbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 0 20px; border-top: 1px solid var(--border); background: var(--surface); color: var(--muted); font-size: 0.68rem; }
  .statusbar > span:last-child { display: flex; align-items: center; gap: 7px; }
  .statusbar .preview { color: var(--accent); }
  .error-banner button { margin-left: auto; border: 0; background: transparent; color: inherit; font-size: 0.74rem; font-weight: 700; }
  .toast { position: fixed; z-index: 60; right: 22px; bottom: 52px; display: flex; align-items: center; gap: 9px; padding: 11px 14px; border: 1px solid color-mix(in srgb, var(--success) 35%, var(--border)); border-radius: 8px; background: var(--surface); box-shadow: 0 8px 24px rgb(15 24 33 / 18%); color: var(--success); font-size: 0.78rem; font-weight: 650; }
  @media (max-width: 759px) {
    .app-shell { display: block; }
    .workspace { height: auto; min-height: calc(100vh - 56px); grid-template-rows: auto auto minmax(0, 1fr) 34px; }
    main { padding: 16px; }
    .statusbar { padding-inline: 12px; }
    .statusbar > span:first-child { display: none; }
    .statusbar { justify-content: flex-end; }
  }
</style>
