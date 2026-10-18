import type { ReactNode } from "react";
import { Icon, type IconName } from "./icons";
import styles from "./EmptyState.module.css";

export interface EmptyStateProps {
  icon?: IconName;
  title: string;
  description?: string;
  /** What the user can do about it, typically one primary button. */
  actions?: ReactNode;
  /** Error states use the danger colour for the icon. */
  tone?: "neutral" | "danger";
  /** Less padding, for use inside tables and cards. */
  compact?: boolean;
}

/** What to show when there is nothing to show: first use, no results, or something went wrong. */
export function EmptyState({ icon = "inbox", title, description, actions, tone = "neutral", compact = false }: EmptyStateProps) {
  return (
    <div className={styles.empty} data-ds="empty-state" data-tone={tone} data-compact={compact || undefined}>
      <span className={styles.icon}>
        <Icon name={icon} size={compact ? 18 : 22} />
      </span>
      <p className={styles.title}>{title}</p>
      {description && <p className={styles.description}>{description}</p>}
      {actions && <div className={styles.actions}>{actions}</div>}
    </div>
  );
}
