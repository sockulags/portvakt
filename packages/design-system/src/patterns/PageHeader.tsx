import type { ReactNode } from "react";
import { Icon } from "./icons";
import styles from "./PageHeader.module.css";

export interface Crumb {
  label: string;
  href?: string;
}

/** Where the current page sits; the last item is the current page. */
export function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav aria-label="Breadcrumb" data-ds="breadcrumbs">
      <ol className={styles.crumbs}>
        {items.map((item, index) => {
          const last = index === items.length - 1;
          return (
            <li key={`${item.label}-${index}`}>
              {last ? (
                <span aria-current="page">{item.label}</span>
              ) : (
                <>
                  <a href={item.href ?? "#"}>{item.label}</a>
                  <Icon name="chevron-right" size={14} className={styles.separator} />
                </>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export interface PageHeaderProps {
  title: string;
  description?: string;
  breadcrumbs?: Crumb[];
  /** Buttons on the right, such as the page's primary action. */
  actions?: ReactNode;
  /** Small items under the title, such as status badges. */
  meta?: ReactNode;
  /** Content below the header, typically tabs. */
  children?: ReactNode;
}

/** The top of a page: where you are, what it is, and what you can do here. */
export function PageHeader({ title, description, breadcrumbs, actions, meta, children }: PageHeaderProps) {
  return (
    <header className={styles.header} data-ds="page-header">
      {breadcrumbs && <Breadcrumbs items={breadcrumbs} />}
      <div className={styles.row}>
        <div className={styles.text}>
          <h1 className={styles.title}>{title}</h1>
          {meta && <div className={styles.meta}>{meta}</div>}
          {description && <p className={styles.description}>{description}</p>}
        </div>
        {actions && <div className={styles.actions}>{actions}</div>}
      </div>
      {children && <div className={styles.below}>{children}</div>}
    </header>
  );
}
