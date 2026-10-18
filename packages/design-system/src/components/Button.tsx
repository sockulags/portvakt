import type { ButtonHTMLAttributes } from "react";
import styles from "./Button.module.css";
import { cx, type ForcedState } from "./util";

export type ButtonVariant = "primary" | "secondary" | "outline" | "ghost" | "danger";
export type ButtonSize = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  force?: ForcedState;
}

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  force,
  className,
  children,
  type = "button",
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      className={cx(styles.button, className)}
      data-ds="button"
      data-variant={variant}
      data-size={size}
      data-force={force}
      data-loading={loading || undefined}
      aria-busy={loading || undefined}
      {...rest}
    >
      {loading && <span className={styles.spinner} aria-hidden />}
      <span className={styles.label}>{children}</span>
    </button>
  );
}
