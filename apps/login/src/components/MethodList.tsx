import { Button, Card } from "@portvakt/design-system/components";
import type { LoginMethodView, MethodKind } from "../api";
import { format, useI18n } from "../i18n";

export interface MethodGroup {
  readonly kind: MethodKind;
  readonly methods: readonly LoginMethodView[];
}

const ORDER: readonly MethodKind[] = ["employee", "citizen"];

/**
 * Groups login methods by kind, employees first, keeping the server's order (by display name)
 * within a group. Empty groups are left out.
 */
export function groupMethods(methods: readonly LoginMethodView[]): MethodGroup[] {
  return ORDER.map((kind) => ({ kind, methods: methods.filter((m) => m.kind === kind) })).filter(
    (group) => group.methods.length > 0,
  );
}

interface MethodListProps {
  readonly methods: readonly LoginMethodView[];
  readonly onChoose: (method: LoginMethodView) => void;
  readonly disabled?: boolean;
}

/**
 * One card per login method. With both kinds present, each group gets a heading (employee vs
 * citizen); with one kind, the cards stand alone.
 */
export function MethodList({ methods, onChoose, disabled = false }: MethodListProps) {
  const { t } = useI18n();
  const groups = groupMethods(methods);
  const labelled = groups.length > 1;
  return (
    <div className="pv-groups" data-testid="method-list">
      {groups.map((group) => {
        const headingId = `method-group-${group.kind}`;
        return (
          <section
            key={group.kind}
            className="pv-group"
            aria-labelledby={labelled ? headingId : undefined}
            data-testid={headingId}
          >
            {labelled && (
              <h2 className="pv-group-heading" id={headingId}>
                {t.groups[group.kind]}
              </h2>
            )}
            <ul className="pv-methods">
              {group.methods.map((method) => (
                <li key={method.id}>
                  <Card className="pv-method">
                    <span className="pv-method-name">{method.displayName}</span>
                    <Button
                      variant="primary"
                      disabled={disabled}
                      data-testid={`method-${method.id}`}
                      onClick={() => onChoose(method)}
                    >
                      {format(t.method, { name: method.displayName })}
                    </Button>
                  </Card>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}
