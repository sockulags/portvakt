import type { HTMLAttributes, ReactNode } from "react";
import styles from "./Display.module.css";
import { cx } from "./util";

export type Tone = "neutral" | "primary" | "info" | "success" | "warning" | "danger";
export type StatusTone = Exclude<Tone, "neutral" | "primary">;

export function Badge({
  color = "neutral",
  variant = "soft",
  children,
}: {
  color?: Tone;
  variant?: "soft" | "solid" | "outline";
  children: ReactNode;
}) {
  return (
    <span className={styles.badge} data-ds="badge" data-color={color} data-variant={variant}>
      {children}
    </span>
  );
}

const ICONS: Record<StatusTone, ReactNode> = {
  info: <path d="M8 7.25v4M8 4.75v.01" />,
  success: <path d="M5 8.25l2 2 4-4.5" />,
  warning: <path d="M8 5v3.75M8 11v.01" />,
  danger: <path d="M5.75 5.75l4.5 4.5M10.25 5.75l-4.5 4.5" />,
};

export function StatusIcon({ tone }: { tone: StatusTone }) {
  return (
    <svg className={styles.statusIcon} data-color={tone} viewBox="0 0 16 16" aria-hidden>
      <circle cx="8" cy="8" r="7" />
      <g fill="none" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
        {ICONS[tone]}
      </g>
    </svg>
  );
}

export function Alert({ tone, title, children }: { tone: StatusTone; title: string; children: ReactNode }) {
  return (
    <div className={styles.alert} data-ds="alert" data-variant={tone} data-color={tone} role={tone === "danger" ? "alert" : "status"}>
      <StatusIcon tone={tone} />
      <div>
        <p className={styles.alertTitle}>{title}</p>
        <p className={styles.alertBody}>{children}</p>
      </div>
    </div>
  );
}

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  interactive?: boolean;
  selected?: boolean;
  force?: "hover" | "focus";
}

export function Card({ interactive, selected, force, className, ...rest }: CardProps) {
  return (
    <div
      className={cx(styles.card, className)}
      data-ds="card"
      data-interactive={interactive || undefined}
      data-selected={selected || undefined}
      data-force={force}
      tabIndex={interactive ? 0 : undefined}
      {...rest}
    />
  );
}

export function Progress({ value, label = "Progress" }: { value?: number; label?: string }) {
  const indeterminate = value === undefined;
  return (
    <div
      className={styles.progress}
      data-ds="progress"
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value}
      data-indeterminate={indeterminate || undefined}
    >
      <div className={styles.progressFill} style={indeterminate ? undefined : { width: `${value}%` }} />
    </div>
  );
}

export function Spinner({ size = 20 }: { size?: number }) {
  return <span className={styles.spinner} data-ds="spinner" style={{ width: size, height: size }} role="status" aria-label="Loading" />;
}

export function Skeleton({ width, height = 12, round }: { width: number | string; height?: number; round?: boolean }) {
  return <span className={styles.skeleton} data-ds="skeleton" style={{ width, height, borderRadius: round ? "50%" : undefined }} />;
}

export function Avatar({ initials, tone = "primary" }: { initials: string; tone?: Tone }) {
  return (
    <span className={styles.avatar} data-ds="avatar" data-color={tone}>
      {initials}
    </span>
  );
}
