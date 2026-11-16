// Resize handles (role="separator"): the keyboard step and clamping shared
// by the disclosures splitter and the disclosures column handles (SPEC §4.1).

/** px per arrow key press; Shift moves four steps. */
export const RESIZE_STEP = 16;

export function clamp(value: number, min: number, max: number): number {
  return Math.round(Math.min(Math.max(value, min), Math.max(min, max)));
}

/** The size change for a key on a separator, or null for other keys. A
 *  vertical separator (between columns) grows with ArrowRight; a
 *  horizontal one above a view grows that view with ArrowUp. */
export function resizeKeyDelta(
  e: KeyboardEvent,
  orientation: 'vertical' | 'horizontal',
): number | null {
  const step = e.shiftKey ? RESIZE_STEP * 4 : RESIZE_STEP;
  const [grow, shrink] =
    orientation === 'vertical' ? ['ArrowRight', 'ArrowLeft'] : ['ArrowUp', 'ArrowDown'];
  if (e.key === grow) return step;
  if (e.key === shrink) return -step;
  return null;
}

/** Follows a pointer drag on `handle` (with pointer capture) and reports
 *  the offset from where it started along the axis. */
export function dragResize(
  e: PointerEvent,
  axis: 'x' | 'y',
  onMove: (delta: number) => void,
): void {
  if (e.button !== 0) return;
  const handle = e.currentTarget as HTMLElement;
  const start = axis === 'x' ? e.clientX : e.clientY;
  e.preventDefault();
  handle.setPointerCapture?.(e.pointerId);
  const move = (m: PointerEvent) => onMove((axis === 'x' ? m.clientX : m.clientY) - start);
  const end = () => {
    handle.removeEventListener('pointermove', move);
    handle.removeEventListener('pointerup', end);
    handle.removeEventListener('pointercancel', end);
    if (handle.hasPointerCapture?.(e.pointerId)) handle.releasePointerCapture(e.pointerId);
  };
  handle.addEventListener('pointermove', move);
  handle.addEventListener('pointerup', end);
  handle.addEventListener('pointercancel', end);
}
