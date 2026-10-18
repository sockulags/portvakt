import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";
import styles from "./Field.module.css";
import type { ForcedState } from "./util";

interface FieldProps {
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}

export function Field({ label, hint, error, children }: FieldProps) {
  return (
    <label className={styles.field} data-state-label={label}>
      <span className={styles.label}>{label}</span>
      {children}
      {error ? <span className={styles.error}>{error}</span> : hint && <span className={styles.hint}>{hint}</span>}
    </label>
  );
}

interface Forceable {
  force?: Exclude<ForcedState, "active">;
  invalid?: boolean;
}

export function TextInput({ force, invalid, ...rest }: InputHTMLAttributes<HTMLInputElement> & Forceable) {
  return <input className={styles.input} data-ds="input" data-force={force} aria-invalid={invalid || undefined} {...rest} />;
}

export function Textarea({ force, invalid, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement> & Forceable) {
  return (
    <textarea
      className={`${styles.input} ${styles.textarea}`}
      data-ds="textarea"
      data-force={force}
      aria-invalid={invalid || undefined}
      {...rest}
    />
  );
}

export function Select({ force, invalid, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement> & Forceable) {
  return (
    <span className={styles.selectWrap}>
      <select
        className={`${styles.input} ${styles.select}`}
        data-ds="select"
        data-force={force}
        aria-invalid={invalid || undefined}
        {...rest}
      >
        {children}
      </select>
      <svg className={styles.chevron} viewBox="0 0 16 16" aria-hidden>
        <path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}
