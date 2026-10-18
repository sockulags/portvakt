import type { FormHTMLAttributes, ReactNode } from "react";
import styles from "./FormSection.module.css";

export interface FormSectionProps {
  title: string;
  description?: string;
  children: ReactNode;
}

/** One group of related fields, with its explanation beside it on wide screens and above it on narrow ones. */
export function FormSection({ title, description, children }: FormSectionProps) {
  return (
    <section className={styles.section} data-ds="form-section">
      <div className={styles.intro}>
        <h3 className={styles.title}>{title}</h3>
        {description && <p className={styles.description}>{description}</p>}
      </div>
      <div className={styles.fields}>{children}</div>
    </section>
  );
}

/** The buttons that finish a form. */
export function FormActions({ children, note }: { children: ReactNode; note?: ReactNode }) {
  return (
    <div className={styles.actions} data-ds="form-actions">
      {note && <span className={styles.note}>{note}</span>}
      <div className={styles.buttons}>{children}</div>
    </div>
  );
}

/** A form laid out as stacked sections. */
export function FormLayout({ children, ...rest }: FormHTMLAttributes<HTMLFormElement> & { children: ReactNode }) {
  return (
    <form className={styles.layout} {...rest}>
      {children}
    </form>
  );
}
