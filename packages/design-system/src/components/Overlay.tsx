import type { ReactNode } from "react";
import { Button } from "./Button";
import { StatusIcon, type StatusTone } from "./Display";
import styles from "./Overlay.module.css";
import { cx } from "./util";

/** Static tooltip bubble, or a live one revealed when its trigger is hovered or focused. */
export function Tooltip({ text, children, open }: { text: string; children: ReactNode; open?: boolean }) {
  return (
    <span className={styles.tooltipAnchor} data-open={open || undefined}>
      {children}
      <span className={styles.tooltip} data-ds="tooltip" role="tooltip">
        {text}
      </span>
    </span>
  );
}

interface ToastProps {
  tone: StatusTone;
  title: string;
  children: ReactNode;
  action?: string;
  animate?: "enter" | "exit";
  onClose?: () => void;
}

export function Toast({ tone, title, children, action, animate, onClose }: ToastProps) {
  return (
    <div className={cx(styles.toast, animate && styles[animate])} data-ds="toast" data-variant={tone} role="status">
      <StatusIcon tone={tone} />
      <div className={styles.toastText}>
        <p className={styles.toastTitle}>{title}</p>
        <p className={styles.toastBody}>{children}</p>
        {action && (
          <Button size="sm" variant="secondary" className={styles.toastAction}>
            {action}
          </Button>
        )}
      </div>
      <button type="button" className={styles.close} aria-label="Dismiss" onClick={onClose}>
        <svg viewBox="0 0 16 16" aria-hidden>
          <path d="M4.5 4.5l7 7M11.5 4.5l-7 7" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
      </button>
    </div>
  );
}

interface DialogProps {
  title: string;
  children: ReactNode;
  footer: ReactNode;
  animate?: boolean;
}

/** Dialog rendered inside a positioned stage (not portaled) so it can sit in the gallery. */
export function DialogStage({ title, children, footer, animate }: DialogProps) {
  return (
    <div className={cx(styles.stage, animate && styles.animate)}>
      <div className={styles.scrim} />
      <div className={styles.dialog} data-ds="dialog" role="dialog" aria-label={title}>
        <h3 className={styles.dialogTitle}>{title}</h3>
        <div className={styles.dialogBody}>{children}</div>
        <div className={styles.dialogFooter}>{footer}</div>
      </div>
    </div>
  );
}
