<script lang="ts">
  // A dialog that takes focus, keeps Tab inside, closes with Escape, and
  // gives focus back when it goes away.
  import { onMount, type Snippet } from 'svelte';
  import { focusables, uid } from '../ui';

  let {
    title,
    onClose,
    role = 'dialog',
    modal = true,
    wide = false,
    children,
  }: {
    title: string;
    onClose: () => void;
    role?: 'dialog' | 'alertdialog';
    modal?: boolean;
    wide?: boolean;
    children: Snippet;
  } = $props();

  const headingId = uid('dialog-title');
  let el: HTMLDivElement | undefined = $state();

  onMount(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (el) (focusables(el)[0] ?? el).focus();
    return () => {
      if (previous?.isConnected) previous.focus();
    };
  });

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onClose();
    } else if (e.key === 'Tab' && el && modal) {
      const items = focusables(el);
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }
</script>

<div class:backdrop={modal}>
  <div
    bind:this={el}
    class="dialog"
    class:wide
    class:floating={!modal}
    {role}
    aria-modal={modal}
    aria-labelledby={headingId}
    tabindex="-1"
    {onkeydown}
  >
    <header>
      <h2 id={headingId}>{title}</h2>
      <button type="button" class="icon" aria-label="Close" onclick={onClose}>×</button>
    </header>
    {@render children()}
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: color-mix(in srgb, CanvasText 25%, transparent);
    display: grid;
    place-items: center;
    z-index: 20;
  }
  .dialog {
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem 1rem;
    min-width: 20rem;
    max-width: min(40rem, 95vw);
    max-height: 90vh;
    overflow: auto;
    box-shadow: 0 8px 30px color-mix(in srgb, CanvasText 30%, transparent);
  }
  .dialog.wide {
    max-width: min(70rem, 95vw);
  }
  .floating {
    position: fixed;
    right: 1rem;
    bottom: 1rem;
    z-index: 15;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
  }
  h2 {
    font-size: 1.05rem;
    margin: 0.25rem 0 0.5rem;
  }
</style>
