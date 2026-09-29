<script lang="ts">
  import { X } from "@lucide/svelte";

  export let title: string;
  export let onClose: () => void;
</script>

<svelte:window onkeydown={(event) => event.key === "Escape" && onClose()} />

<div class="scrim" role="presentation" onclick={(event) => event.target === event.currentTarget && onClose()}>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <header>
      <h2 id="modal-title">{title}</h2>
      <button class="button icon-only" type="button" aria-label="Close dialog" title="Close" onclick={onClose}>
        <X size={17} />
      </button>
    </header>
    <div class="body"><slot></slot></div>
  </div>
</div>

<style>
  .scrim {
    position: fixed;
    z-index: 50;
    inset: 0;
    display: grid;
    place-items: center;
    padding: 20px;
    background: rgb(10 15 20 / 50%);
  }

  .modal {
    width: min(540px, 100%);
    overflow: hidden;
    border: 1px solid var(--border-strong);
    border-radius: 12px;
    background: var(--surface);
    box-shadow: var(--shadow);
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
  }

  h2 { margin: 0; }
  .body { padding: 18px; }
</style>
