import type { ReactNode } from "react";
import { Badge } from "../components/index";
import { Icon, type IconName } from "./icons";
import styles from "./SidebarNav.module.css";

export interface SidebarNavItem {
  id: string;
  label: string;
  icon?: IconName;
  /** A count or short label after the item, such as unread items. */
  badge?: string | number;
  disabled?: boolean;
  /** Pins hover or focus, for the gallery. */
  force?: "hover" | "focus";
}

export interface SidebarNavSection {
  title?: string;
  items: SidebarNavItem[];
}

export interface SidebarNavProps {
  sections: SidebarNavSection[];
  active?: string;
  onNavigate?: (id: string) => void;
  /** Shown above the sections, such as a workspace switcher. */
  header?: ReactNode;
  /** Shown at the bottom, such as the signed-in user. */
  footer?: ReactNode;
  /** Icons only; labels move to tooltips. */
  collapsed?: boolean;
  label?: string;
}

/** Side navigation for an application: grouped links with icons, counts and a collapsed rail. */
export function SidebarNav({ sections, active, onNavigate, header, footer, collapsed = false, label = "Sections" }: SidebarNavProps) {
  return (
    <nav className={styles.sidebar} data-ds="sidebar" data-collapsed={collapsed || undefined} aria-label={label}>
      {header && <div className={styles.header}>{header}</div>}
      <div className={styles.sections}>
        {sections.map((section, index) => (
          <div key={section.title ?? index} className={styles.section}>
            {section.title && <p className={styles.title}>{section.title}</p>}
            <ul>
              {section.items.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    className={styles.item}
                    aria-current={item.id === active ? "page" : undefined}
                    data-force={item.force}
                    disabled={item.disabled}
                    title={collapsed ? item.label : undefined}
                    onClick={() => onNavigate?.(item.id)}
                  >
                    {item.icon && <Icon name={item.icon} className={styles.icon} />}
                    <span className={styles.label}>{item.label}</span>
                    {item.badge !== undefined && !collapsed && (
                      <span className={styles.badge}>
                        <Badge color={item.id === active ? "primary" : "neutral"}>{item.badge}</Badge>
                      </span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      {footer && <div className={styles.footer}>{footer}</div>}
    </nav>
  );
}
