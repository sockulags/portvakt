import { useId, type ReactNode } from "react";
import { Avatar } from "../components/index";
import { Icon } from "./icons";
import styles from "./Navbar.module.css";

export interface NavbarLink {
  id: string;
  label: string;
  href?: string;
  /** Pins hover or focus, for the gallery. */
  force?: "hover" | "focus";
}

export interface NavbarProps {
  brand: ReactNode;
  links: NavbarLink[];
  active?: string;
  onNavigate?: (id: string) => void;
  /** Shows a search field with this placeholder. */
  searchPlaceholder?: string;
  /** Extra controls before the avatar, such as buttons. */
  actions?: ReactNode;
  user?: { initials: string; name: string };
  /** The bottom shadow used once the page has scrolled under the bar. */
  elevated?: boolean;
  /** Narrow layout: links move behind a menu button. */
  compact?: boolean;
  menuOpen?: boolean;
  onMenuToggle?: () => void;
}

/** Top application bar: brand, primary links, search, actions and the signed-in user. */
export function Navbar({
  brand,
  links,
  active,
  onNavigate,
  searchPlaceholder,
  actions,
  user,
  elevated = false,
  compact = false,
  menuOpen = false,
  onMenuToggle,
}: NavbarProps) {
  const menuId = useId();

  const renderLink = (link: NavbarLink, className: string | undefined) => (
    <a
      key={link.id}
      href={link.href ?? "#"}
      className={className}
      aria-current={link.id === active ? "page" : undefined}
      data-force={link.force}
      onClick={(event) => {
        if (!onNavigate) return;
        event.preventDefault();
        onNavigate(link.id);
      }}
    >
      {link.label}
    </a>
  );

  return (
    <header className={styles.navbar} data-ds="navbar" data-elevated={elevated || undefined} data-compact={compact || undefined}>
      <div className={styles.bar}>
        {compact && (
          <button
            type="button"
            className={styles.menuButton}
            aria-expanded={menuOpen}
            aria-controls={menuId}
            aria-label={menuOpen ? "Close menu" : "Open menu"}
            onClick={onMenuToggle}
          >
            <Icon name={menuOpen ? "close" : "menu"} size={18} />
          </button>
        )}
        <div className={styles.brand}>{brand}</div>
        {!compact && (
          <nav className={styles.links} aria-label="Main">
            {links.map((link) => renderLink(link, styles.link))}
          </nav>
        )}
        <div className={styles.end}>
          {searchPlaceholder && !compact && (
            <label className={styles.search}>
              <span className={styles.visuallyHidden}>Search</span>
              <Icon name="search" className={styles.searchIcon} />
              <input type="search" placeholder={searchPlaceholder} />
            </label>
          )}
          {actions}
          {user && (
            <span className={styles.user} title={user.name}>
              <Avatar initials={user.initials} />
            </span>
          )}
        </div>
      </div>
      {compact && menuOpen && (
        <nav id={menuId} className={styles.menu} aria-label="Main">
          {links.map((link) => renderLink(link, styles.menuLink))}
        </nav>
      )}
    </header>
  );
}
