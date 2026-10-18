import { useState } from "react";
import { Button } from "./Button";
import { Alert, Avatar, Badge, Card, Progress, Skeleton, Spinner, type Tone } from "./Display";
import { Toast } from "./Overlay";
import { defineSpecimen } from "./specimen";

const BADGE_TEXT: Record<Tone, string> = {
  neutral: "Draft",
  primary: "New",
  info: "Beta",
  success: "Live",
  warning: "Pending",
  danger: "Failed",
};

const stack = { display: "grid", gap: "var(--space-3)" } as const;
const title = { margin: 0, color: "var(--color-text)", fontSize: "var(--text-sm)", fontWeight: "var(--weight-semibold)" } as const;
const meta = { margin: "2px 0 0", color: "var(--color-text-muted)", fontSize: "var(--text-sm)" } as const;

function PersonCard(props: { interactive?: boolean; selected?: boolean; force?: "hover" | "focus" }) {
  return (
    <Card {...props} style={{ width: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
        <Avatar initials="AL" />
        <div>
          <p style={title}>Ada Lovelace</p>
          <p style={meta}>Analyst · London</p>
        </div>
      </div>
    </Card>
  );
}

const PLANS = [
  { id: "starter", name: "Starter", price: "Free", copy: "For side projects and trying things out." },
  { id: "pro", name: "Pro", price: "€12 / mo", copy: "Unlimited projects and version history." },
  { id: "team", name: "Team", price: "€29 / mo", copy: "Shared libraries, roles and review flows." },
];

export default defineSpecimen([
  {
    id: "feedback",
    title: "Feedback & status",
    description: "Badges, alerts, toasts and loading states across the four status tones.",
    order: 40,
    blocks: [
      {
        kind: "matrix",
        title: "Badges",
        rows: ["soft", "solid", "outline"],
        columns: ["neutral", "primary", "info", "success", "warning", "danger"],
        minColumn: 80,
        render: ({ row, column }) => (
          <Badge variant={row as "soft" | "solid" | "outline"} color={column as Tone}>
            {BADGE_TEXT[column as Tone]}
          </Badge>
        ),
      },
      {
        kind: "block",
        title: "Alerts",
        render: () => (
          <div style={stack}>
            <Alert tone="info" title="Scheduled maintenance">
              The API will be read-only on Sunday between 02:00 and 03:00 UTC.
            </Alert>
            <Alert tone="success" title="Deployment finished">
              Version 2.4.0 is live on all regions.
            </Alert>
            <Alert tone="warning" title="Approaching your quota">
              You have used 86% of this month's build minutes.
            </Alert>
            <Alert tone="danger" title="Payment failed">
              We could not charge the card ending in 4242. Update it to keep your workspace active.
            </Alert>
          </div>
        ),
      },
      {
        kind: "block",
        title: "Toasts",
        render: function ToastDemo() {
          const [key, setKey] = useState(0);
          const [phase, setPhase] = useState<"enter" | "exit" | null>(null);
          return (
            <div style={{ display: "grid", justifyItems: "start", alignContent: "start", gap: "var(--space-3)", minHeight: 200 }}>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => {
                  setKey((value) => value + 1);
                  setPhase("enter");
                }}
              >
                Play enter
              </Button>
              <Toast tone="success" title="Invite sent" action="Undo">
                Maya will get an email with a link to join.
              </Toast>
              {phase && (
                <Toast key={key} tone="danger" title="Couldn't save draft" animate={phase} onClose={() => setPhase("exit")}>
                  Check your connection and try again.
                </Toast>
              )}
            </div>
          );
        },
      },
      {
        kind: "grid",
        title: "Loading",
        min: 200,
        items: [
          { label: "progress 35%", render: () => <div style={{ width: "100%" }}><Progress value={35} label="Statement export" /></div> },
          { label: "progress 80%", render: () => <div style={{ width: "100%" }}><Progress value={80} label="Account verification" /></div> },
          { label: "indeterminate", render: () => <div style={{ width: "100%" }}><Progress label="Syncing transactions" /></div> },
          {
            label: "spinner",
            render: () => (
              <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
                <Spinner size={16} />
                <Spinner size={24} />
                <Spinner size={32} />
              </div>
            ),
          },
          {
            label: "skeleton",
            render: () => (
              <Card style={{ width: "100%" }}>
                <div style={{ display: "flex", gap: "var(--space-4)" }}>
                  <Skeleton width={40} height={40} round />
                  <div style={{ display: "grid", flex: 1, gap: "var(--space-2)" }}>
                    <Skeleton width="45%" height={14} />
                    <Skeleton width="90%" />
                    <Skeleton width="70%" />
                  </div>
                </div>
              </Card>
            ),
          },
        ],
      },
    ],
  },
  {
    id: "surfaces",
    title: "Cards",
    description: "Static, hovered, focused and selected surfaces, then a live picker that lifts on hover.",
    order: 60,
    blocks: [
      {
        kind: "grid",
        min: 200,
        items: [
          { label: "default", render: () => <PersonCard /> },
          { label: "hover", render: () => <PersonCard interactive force="hover" /> },
          { label: "focus-visible", render: () => <PersonCard interactive force="focus" /> },
          { label: "selected", render: () => <PersonCard selected /> },
        ],
      },
      {
        kind: "block",
        title: "Live",
        render: function PlanPicker() {
          const [selected, setSelected] = useState("pro");
          return (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 200px), 1fr))", gap: "var(--space-5)" }}>
              {PLANS.map((plan) => (
                <Card
                  key={plan.id}
                  interactive
                  selected={selected === plan.id}
                  onClick={() => setSelected(plan.id)}
                  onKeyDown={(event) => (event.key === "Enter" || event.key === " ") && setSelected(plan.id)}
                  role="radio"
                  aria-checked={selected === plan.id}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "var(--space-2)" }}>
                    <p style={title}>{plan.name}</p>
                    {plan.id === "pro" && (
                      <Badge color="primary" variant="soft">
                        Popular
                      </Badge>
                    )}
                  </div>
                  <p
                    style={{
                      margin: "var(--space-3) 0 var(--space-1)",
                      color: "var(--color-text)",
                      fontFamily: "var(--font-display)",
                      fontSize: "var(--text-2xl)",
                      fontWeight: "var(--weight-bold)",
                      letterSpacing: "var(--tracking-tight)",
                    }}
                  >
                    {plan.price}
                  </p>
                  <p style={meta}>{plan.copy}</p>
                </Card>
              ))}
            </div>
          );
        },
      },
    ],
  },
]);
