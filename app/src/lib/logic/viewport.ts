// Windowing for long documents: both panes render only the lines in view
// (every line has the same height, so the window is plain arithmetic).

/** Height of one main-pane line and one hex block, in CSS pixels. */
export const LINE_HEIGHT = 20;

/** Below this many visible lines everything is rendered. */
export const VIRTUALIZE_FROM = 400;

export interface Slice {
  /** First rendered index into the visible lines. */
  start: number;
  /** One past the last rendered index. */
  end: number;
}

/** The lines to render for a scroll position, or null to render them all. */
export function windowFor(
  count: number,
  scrollTop: number,
  height: number,
  overscan = 40,
): Slice | null {
  if (count < VIRTUALIZE_FROM || height <= 0) return null;
  const first = Math.floor(scrollTop / LINE_HEIGHT);
  const shown = Math.ceil(height / LINE_HEIGHT);
  return {
    start: Math.max(0, first - overscan),
    end: Math.min(count, first + shown + overscan),
  };
}
