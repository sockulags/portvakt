import { Button } from "@portvakt/design-system/components";
import { Page } from "../components/Page";
import { useI18n } from "../i18n";

/** oidc-provider's hidden logout form (with its xsrf token), rendered by the server. */
export const LOGOUT_FORM_ID = "op.logoutForm";

/**
 * RP-initiated logout confirmation. The buttons submit the server's hidden form: "logout=yes"
 * signs out; the other button submits without it and returns to the application signed in.
 */
export function LogoutView() {
  const { t } = useI18n();
  return (
    <Page heading={t.logout.heading} viewKey="logout" testId="logout-view">
      <p className="pv-intro">{t.logout.body}</p>
      <div className="pv-actions pv-actions-split">
        <Button
          type="submit"
          form={LOGOUT_FORM_ID}
          name="logout"
          value="yes"
          variant="primary"
          data-testid="logout-confirm"
        >
          {t.logout.confirm}
        </Button>
        <Button type="submit" form={LOGOUT_FORM_ID} variant="secondary" data-testid="logout-cancel">
          {t.logout.stay}
        </Button>
      </div>
    </Page>
  );
}

export function LoggedOutView() {
  const { t } = useI18n();
  return (
    <Page heading={t.loggedOut.heading} viewKey="logged-out" testId="logged-out-view">
      <p className="pv-intro">{t.loggedOut.body}</p>
    </Page>
  );
}
