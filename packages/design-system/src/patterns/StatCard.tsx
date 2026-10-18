import { useId } from "react";
import { Card, Skeleton } from "../components/index";
import { Icon } from "./icons";
import styles from "./StatCard.module.css";

export interface StatCardProps {
  label: string;
  value: string;
  /** Change against the previous period. `good` decides the colour, so a falling error rate can be green. */
  delta?: { value: string; direction: "up" | "down" | "flat"; good?: boolean };
  hint?: string;
  /** Recent values, drawn as a small area chart. */
  trend?: number[];
  loading?: boolean;
}

function sparkPath(values: number[], width: number, height: number): { line: string; area: string } {
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values.map((value, index) => [index * step, height - 2 - ((value - min) / range) * (height - 4)] as const);
  const line = points.map(([x, y], index) => `${index === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  return { line, area: `${line} L${width} ${height} L0 ${height} Z` };
}

/** One number that matters, with its change and recent trend. */
export function StatCard({ label, value, delta, hint, trend, loading = false }: StatCardProps) {
  const gradient = useId();
  const tone = !delta || delta.direction === "flat" ? "neutral" : (delta.good ?? delta.direction === "up") ? "good" : "bad";
  const spark = trend && trend.length > 1 ? sparkPath(trend, 120, 36) : null;

  return (
    <Card className={styles.card} data-ds="stat-card" aria-busy={loading || undefined}>
      <p className={styles.label}>{label}</p>
      {loading ? (
        <div className={styles.loading}>
          <Skeleton width="60%" height={28} />
          <Skeleton width="40%" />
        </div>
      ) : (
        <>
          <div className={styles.row}>
            <p className={styles.value}>{value}</p>
            {spark && (
              <svg className={styles.spark} viewBox="0 0 120 36" preserveAspectRatio="none" aria-hidden>
                <defs>
                  <linearGradient id={gradient} x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="currentColor" stopOpacity="0.22" />
                    <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
                  </linearGradient>
                </defs>
                <path d={spark.area} fill={`url(#${gradient})`} />
                <path d={spark.line} fill="none" stroke="currentColor" strokeWidth="1.75" vectorEffect="non-scaling-stroke" />
              </svg>
            )}
          </div>
          <div className={styles.foot}>
            {delta && (
              <span className={styles.delta} data-tone={tone}>
                <Icon name={delta.direction === "up" ? "arrow-up" : delta.direction === "down" ? "arrow-down" : "minus"} size={12} />
                {delta.value}
              </span>
            )}
            {hint && <span className={styles.hint}>{hint}</span>}
          </div>
        </>
      )}
    </Card>
  );
}
