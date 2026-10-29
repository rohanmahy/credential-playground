<script lang="ts">
  // A popup menu (role=menu): focus moves into it, arrow keys move between
  // items, Enter/Space or a click picks one, Escape or a click outside closes.
  import { onMount } from 'svelte';
  import type { MenuItem } from '../ui';

  let {
    label,
    items,
    onClose,
    x = null,
    y = null,
  }: {
    label: string;
    items: MenuItem[];
    onClose: () => void;
    /** Viewport position for context menus; otherwise below the trigger. */
    x?: number | null;
    y?: number | null;
  } = $props();

  let el: HTMLDivElement | undefined = $state();

  function buttons(): HTMLElement[] {
    return el ? [...el.querySelectorAll<HTMLElement>('[role^="menuitem"]')] : [];
  }

  onMount(() => {
    const first = buttons().find((b) => b.getAttribute('aria-disabled') !== 'true');
    first?.focus();
    const outside = (e: PointerEvent) => {
      if (el && e.target instanceof Node && !el.contains(e.target)) onClose();
    };
    // Registered after the click that opened the menu has finished.
    const t = setTimeout(() => window.addEventListener('pointerdown', outside), 0);
    return () => {
      clearTimeout(t);
      window.removeEventListener('pointerdown', outside);
    };
  });

  function pick(item: MenuItem) {
    if (item.disabled) return;
    onClose();
    item.action();
  }

  function onkeydown(e: KeyboardEvent) {
    const all = buttons();
    const at = all.indexOf(document.activeElement as HTMLElement);
    const move = (i: number) => all[(i + all.length) % all.length]?.focus();
    switch (e.key) {
      case 'ArrowDown':
        move(at + 1);
        break;
      case 'ArrowUp':
        move(at - 1);
        break;
      case 'Home':
        move(0);
        break;
      case 'End':
        move(all.length - 1);
        break;
      case 'Escape':
      case 'Tab':
        onClose();
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  }
</script>

<div
  bind:this={el}
  class="menu"
  class:fixed={x !== null && y !== null}
  style:left={x !== null ? `${x}px` : null}
  style:top={y !== null ? `${y}px` : null}
  role="menu"
  aria-label={label}
  tabindex="-1"
  {onkeydown}
>
  {#each items as item (item.label)}
    <button
      type="button"
      role={item.role ?? 'menuitem'}
      aria-checked={item.role && item.role !== 'menuitem' ? (item.checked ?? false) : undefined}
      aria-disabled={item.disabled ? 'true' : undefined}
      tabindex="-1"
      onclick={() => pick(item)}
    >
      {#if item.role && item.role !== 'menuitem'}<span class="check" aria-hidden="true"
          >{item.checked ? '✓' : ''}</span
        >{/if}{item.label}
    </button>
  {/each}
</div>

<style>
  .menu {
    position: absolute;
    z-index: 30;
    display: flex;
    flex-direction: column;
    min-width: 12rem;
    padding: 0.25rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: 0 4px 16px color-mix(in srgb, CanvasText 25%, transparent);
  }
  .menu.fixed {
    position: fixed;
  }
  button {
    text-align: left;
    border: 0;
    background: none;
    padding: 0.3rem 0.5rem;
    border-radius: 4px;
  }
  button:hover,
  button:focus-visible {
    background: var(--hover);
  }
  button[aria-disabled='true'] {
    color: var(--muted);
  }
  .check {
    display: inline-block;
    width: 1.2em;
  }
</style>
