import { Spinner } from "@portvakt/design-system/components";

/**
 * The design system's spinner without its own live region: `Spinner` is a `role="status"`
 * named "Loading" in English, which would be announced inside the page's own (translated)
 * status. The surrounding status carries the text; the spinner is decoration.
 */
export function QuietSpinner() {
  return (
    <span className="pv-spinner" aria-hidden="true">
      <Spinner />
    </span>
  );
}
