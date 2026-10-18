import { Button } from "@portvakt/design-system/components";
import { useEffect, useRef, type ReactNode } from "react";
import { LOCALES, MESSAGES, useI18n } from "../i18n";

interface PageProps {
  /** The page's heading; focused when the view changes so screen readers announce it. */
  readonly heading: string;
  /** Changes whenever the view changes, to move focus to the new heading. */
  readonly viewKey: string;
  readonly context?: string | undefined;
  readonly children: ReactNode;
  readonly testId: string;
}

/** The frame of every login page: language switch, a focused heading and the content card. */
export function Page({ heading, viewKey, context, children, testId }: PageProps) {
  const { locale, t, setLocale } = useI18n();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const other = LOCALES.find((candidate) => candidate !== locale) ?? locale;

  useEffect(() => {
    headingRef.current?.focus();
  }, [viewKey]);

  useEffect(() => {
    document.title = `${heading} – ${t.pageTitle === heading ? "Portvakt" : t.pageTitle}`;
  }, [heading, t.pageTitle]);

  return (
    <div className="pv-page">
      <header className="pv-topbar">
        <span className="pv-brand">{context ?? "Portvakt"}</span>
        <Button
          variant="ghost"
          size="sm"
          lang={other}
          aria-label={MESSAGES[other].switchLanguage}
          data-testid="language-toggle"
          onClick={() => setLocale(other)}
        >
          {MESSAGES[other].languageName}
        </Button>
      </header>
      <main className="pv-main" data-testid={testId}>
        <h1 className="pv-heading" ref={headingRef} tabIndex={-1}>
          {heading}
        </h1>
        {children}
      </main>
    </div>
  );
}
