import { StatusIcon } from "@portvakt/design-system/components";
import type { LoginErrorCode } from "../api";
import { Page } from "../components/Page";
import { format, useI18n } from "../i18n";

/** An error outside a usable interaction: what happened and what to do; no retry here. */
export function ErrorView({
  code,
  oauthError,
}: {
  code: LoginErrorCode;
  oauthError?: string | undefined;
}) {
  const { t } = useI18n();
  const text = t.errors[code];
  return (
    <Page heading={text.title} viewKey={`error-${code}`} testId="error-view">
      <div className="pv-error" data-testid="error-code" data-error={code}>
        <StatusIcon tone="danger" />
        <div>
          <p className="pv-intro">{text.body}</p>
          {oauthError !== undefined && (
            <p className="pv-muted">{format(t.errorCode, { code: oauthError })}</p>
          )}
        </div>
      </div>
    </Page>
  );
}
