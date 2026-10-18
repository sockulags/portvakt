import { useEffect, useRef, type InputHTMLAttributes, type ReactNode } from "react";
import styles from "./Controls.module.css";
import { cx, type ForcedState } from "./util";

interface ControlProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: ReactNode;
  force?: Exclude<ForcedState, "active">;
}

export function Checkbox({ label, force, indeterminate = false, ...rest }: ControlProps & { indeterminate?: boolean }) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate;
  }, [indeterminate]);
  return (
    <label className={styles.control} data-ds="checkbox" data-force={force}>
      <input ref={ref} type="checkbox" className={styles.native} {...rest} />
      <span className={styles.box}>
        <svg className={styles.check} viewBox="0 0 16 16" aria-hidden>
          <path d="M3.5 8.5l3 3 6-7" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <svg className={styles.dash} viewBox="0 0 16 16" aria-hidden>
          <path d="M4 8h8" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      </span>
      {label && <span>{label}</span>}
    </label>
  );
}

export function Radio({ label, force, ...rest }: ControlProps) {
  return (
    <label className={cx(styles.control, styles.radio)} data-ds="radio" data-force={force}>
      <input type="radio" className={styles.native} {...rest} />
      <span className={styles.box} />
      {label && <span>{label}</span>}
    </label>
  );
}

export function Switch({ label, force, ...rest }: ControlProps) {
  return (
    <label className={styles.control} data-ds="switch" data-force={force}>
      <input type="checkbox" role="switch" className={styles.native} {...rest} />
      <span className={styles.track}>
        <span className={styles.thumb} />
      </span>
      {label && <span>{label}</span>}
    </label>
  );
}
