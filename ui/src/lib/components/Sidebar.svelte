<script lang="ts">
  import {
    Binoculars,
    Braces,
    Database,
    LayoutDashboard,
    ListChecks,
    Settings,
  } from "@lucide/svelte";
  import type { Page } from "../types";

  export let page: Page;
  export let onNavigate: (page: Page) => void;

  const items = [
    { id: "overview" as const, label: "Overview", icon: LayoutDashboard },
    { id: "sessions" as const, label: "Sessions", icon: ListChecks },
    { id: "findings" as const, label: "Findings", icon: Binoculars },
    { id: "decoder" as const, label: "Decoder", icon: Braces },
    { id: "sources" as const, label: "Sources", icon: Database },
    { id: "settings" as const, label: "Settings", icon: Settings },
  ];
</script>

<aside class="sidebar">
  <div class="brand">
    <span class="brand-mark" aria-hidden="true"><span></span></span>
    <div>
      <strong>CTF Hunter</strong>
      <small>Find. Decode. Capture.</small>
    </div>
  </div>

  <nav aria-label="Primary navigation">
    {#each items as item}
      <button
        type="button"
        class:active={page === item.id}
        aria-current={page === item.id ? "page" : undefined}
        title={item.label}
        onclick={() => onNavigate(item.id)}
      >
        <item.icon size={18} strokeWidth={1.9} />
        <span>{item.label}</span>
      </button>
    {/each}
  </nav>

  <div class="sidebar-foot">
    <span class="status-dot success"></span>
    <span>Desktop 0.1.1</span>
  </div>
</aside>

<style>
  .sidebar {
    display: flex;
    width: 220px;
    min-width: 220px;
    min-height: 100vh;
    flex-direction: column;
    padding: 22px 12px 14px;
    background: var(--sidebar);
    color: #f4f7fa;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 56px;
    padding: 0 10px 20px;
  }

  .brand strong,
  .brand small {
    display: block;
  }

  .brand strong {
    font-size: 0.98rem;
    letter-spacing: 0.01em;
  }

  .brand small {
    margin-top: 4px;
    color: #b8c1cb;
    font-size: 0.7rem;
  }

  .brand-mark {
    position: relative;
    width: 26px;
    height: 26px;
    flex: 0 0 auto;
    border: 2px solid #f4f7fa;
    border-radius: 50%;
  }

  .brand-mark::before,
  .brand-mark::after,
  .brand-mark span::before,
  .brand-mark span::after {
    position: absolute;
    width: 7px;
    height: 2px;
    background: #f4f7fa;
    content: "";
  }

  .brand-mark::before { left: -5px; top: 10px; }
  .brand-mark::after { right: -5px; top: 10px; }
  .brand-mark span::before { left: 8px; top: -5px; transform: rotate(90deg); }
  .brand-mark span::after { left: 8px; bottom: -5px; transform: rotate(90deg); }

  nav {
    display: grid;
    gap: 4px;
  }

  nav button {
    display: flex;
    min-height: 44px;
    align-items: center;
    gap: 12px;
    padding: 0 12px;
    border: 0;
    border-radius: 7px;
    background: transparent;
    color: #dce2e8;
    font-size: 0.86rem;
    text-align: left;
    transition: background 120ms ease, color 120ms ease;
  }

  nav button:hover {
    background: var(--sidebar-hover);
    color: white;
  }

  nav button.active {
    background: var(--accent);
    color: white;
  }

  .sidebar-foot {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: auto;
    padding: 14px 10px 0;
    border-top: 1px solid rgb(255 255 255 / 12%);
    color: #aeb8c2;
    font-size: 0.71rem;
  }

  @media (max-width: 1099px) and (min-width: 760px) {
    .sidebar {
      width: 74px;
      min-width: 74px;
      align-items: center;
      padding-inline: 9px;
    }

    .brand {
      padding-inline: 0;
    }

    .brand div,
    nav button span,
    .sidebar-foot span:last-child {
      display: none;
    }

    nav button {
      width: 48px;
      justify-content: center;
      padding: 0;
    }
  }

  @media (max-width: 759px) {
    .sidebar {
      position: sticky;
      z-index: 20;
      top: 0;
      width: 100%;
      min-height: 0;
      padding: 8px 10px;
      overflow-x: auto;
    }

    .brand,
    .sidebar-foot {
      display: none;
    }

    nav {
      display: flex;
      min-width: max-content;
    }

    nav button {
      min-height: 40px;
      gap: 7px;
      padding-inline: 10px;
      font-size: 0.78rem;
    }
  }
</style>
