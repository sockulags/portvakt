import type { ReactNode } from "react";
import styles from "./AppShell.module.css";

export interface AppShellProps {
  /** Usually a Navbar. */
  navbar?: ReactNode;
  /** Usually a SidebarNav. */
  sidebar?: ReactNode;
  children: ReactNode;
  /** Fills its container instead of the viewport, for previews and embedded demos. */
  contained?: boolean;
}

/** The frame of an application: bar on top, navigation on the side, scrolling content in the middle. */
export function AppShell({ navbar, sidebar, children, contained = false }: AppShellProps) {
  return (
    <div className={styles.shell} data-ds="app-shell" data-contained={contained || undefined}>
      {navbar && <div className={styles.navbar}>{navbar}</div>}
      <div className={styles.body}>
        {sidebar && <div className={styles.sidebar}>{sidebar}</div>}
        <main className={styles.main}>{children}</main>
      </div>
    </div>
  );
}
