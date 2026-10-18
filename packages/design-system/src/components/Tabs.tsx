import { useLayoutEffect, useRef, useState, type KeyboardEvent, type RefObject } from "react";
import styles from "./Tabs.module.css";
import type { ForcedState } from "./util";

export interface TabItem {
  id: string;
  label: string;
  disabled?: boolean;
  force?: Exclude<ForcedState, "active">;
}

interface TabsProps {
  items: TabItem[];
  value: string;
  onChange?: (id: string) => void;
  variant: string;
  label: string;
}

interface IndicatorBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * Keeps one shared indicator over the selected tab. Moving a single element
 * (instead of one per tab) is what lets the underline, pill or segment slide
 * from the previous tab to the new one.
 */
function useIndicator(list: RefObject<HTMLDivElement | null>, value: string) {
  const [box, setBox] = useState<IndicatorBox | null>(null);
  const [animate, setAnimate] = useState(false);

  useLayoutEffect(() => {
    const el = list.current;
    if (!el) return;
    const measure = () => {
      const tab = el.querySelector<HTMLElement>(`[data-tab="${CSS.escape(value)}"]`);
      setBox(tab ? { x: tab.offsetLeft, y: tab.offsetTop, width: tab.offsetWidth, height: tab.offsetHeight } : null);
    };
    measure();
    // Tab widths change with fonts, type tokens and window size; follow them.
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    for (const tab of el.querySelectorAll("[data-tab]")) observer.observe(tab);
    void document.fonts?.ready.then(measure);
    return () => observer.disconnect();
  }, [list, value]);

  // Place the indicator without motion first, then animate later moves.
  useLayoutEffect(() => {
    if (!box || animate) return;
    const frame = requestAnimationFrame(() => setAnimate(true));
    return () => cancelAnimationFrame(frame);
  }, [box, animate]);

  return { box, animate };
}

export function Tabs({ items, value, onChange, variant, label }: TabsProps) {
  const list = useRef<HTMLDivElement>(null);
  const { box, animate } = useIndicator(list, value);

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
    const enabled = items.filter((item) => !item.disabled);
    const index = enabled.findIndex((item) => item.id === value);
    const step = event.key === "ArrowRight" ? 1 : -1;
    const next = enabled[(index + step + enabled.length) % enabled.length];
    if (!next) return;
    onChange?.(next.id);
    list.current?.querySelector<HTMLButtonElement>(`[data-tab="${next.id}"]`)?.focus();
  };

  return (
    <div ref={list} className={styles.list} data-ds="tabs" role="tablist" aria-label={label} data-variant={variant} onKeyDown={onKeyDown}>
      {box && (
        <span
          className={styles.indicator}
          data-animate={animate || undefined}
          style={{ width: box.width, height: box.height, transform: `translate(${box.x}px, ${box.y}px)` }}
          aria-hidden
        />
      )}
      {items.map((item) => {
        const selected = item.id === value;
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            className={styles.tab}
            data-ds="tab"
            data-tab={item.id}
            data-force={item.force}
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            disabled={item.disabled}
            onClick={() => onChange?.(item.id)}
          >
            {item.label}
          </button>
        );
      })}
    </div>
  );
}
