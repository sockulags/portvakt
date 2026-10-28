import { Button, Field, TextInput } from "@portvakt/design-system/components";
import { useId, useState, type FormEvent } from "react";
import { useI18n } from "../i18n";

/** A plausible email address: something@domain.tld, no spaces. */
export const isEmail = (value: string): boolean => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());

/** `busy`: another login request of the page is still being answered; nothing was sent. */
export type HomeRealmOutcome = "redirecting" | "not_found" | "rate_limited" | "failed" | "busy";

interface HomeRealmFormProps {
  readonly initialEmail?: string | null;
  /** Looks the email's domain up; resolves how it went (redirecting means: leave the page). */
  readonly onSubmit: (email: string) => Promise<HomeRealmOutcome>;
  readonly disabled?: boolean;
}

/**
 * Home realm discovery: the email's domain picks the organisation's login method. Validation
 * errors are shown on the field and announced; focus stays in the field.
 */
export function HomeRealmForm({ initialEmail, onSubmit, disabled = false }: HomeRealmFormProps) {
  const { t } = useI18n();
  const [email, setEmail] = useState(initialEmail ?? "");
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const headingId = useId();
  const hintId = `${headingId}-hint`;
  const errorId = `${headingId}-error`;

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (!isEmail(email)) {
      setError(t.hrd.invalid);
      return;
    }
    setError(undefined);
    setBusy(true);
    const outcome = await onSubmit(email.trim());
    if (outcome === "redirecting") return;
    setBusy(false);
    if (outcome === "busy") return;
    setError(
      outcome === "not_found"
        ? t.hrd.notFound
        : outcome === "rate_limited"
          ? t.errors.rate_limited.body
          : t.errors.request_failed.body,
    );
  };

  // The design system's Field renders hint and error inside the label, which would make them
  // part of the input's name and announce the error twice. Here Field gives the label only; the
  // hint and the error are separate, described-by elements, and the error is the one live region.
  return (
    <section className="pv-hrd" aria-labelledby={headingId}>
      <h2 className="pv-group-heading" id={headingId}>
        {t.hrd.heading}
      </h2>
      <form noValidate onSubmit={(event) => void submit(event)} className="pv-hrd-form">
        <div className="pv-field">
          <Field label={t.hrd.label}>
            <TextInput
              type="email"
              name="email"
              autoComplete="email"
              inputMode="email"
              spellCheck={false}
              value={email}
              invalid={error !== undefined}
              aria-describedby={error === undefined ? hintId : `${hintId} ${errorId}`}
              data-testid="hrd-email"
              onChange={(event) => setEmail(event.target.value)}
            />
          </Field>
          <p id={hintId} className="pv-field-hint">
            {t.hrd.hint}
          </p>
          <p id={errorId} className="pv-field-error" role="alert" data-testid="hrd-error">
            {error ?? ""}
          </p>
        </div>
        <Button
          type="submit"
          variant="secondary"
          loading={busy}
          disabled={disabled || busy}
          data-testid="hrd-submit"
        >
          {t.hrd.submit}
        </Button>
      </form>
    </section>
  );
}
