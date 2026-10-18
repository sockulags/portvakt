import { useState } from "react";
import { Button, type ButtonVariant } from "./Button";
import { defineSpecimen, forced } from "./specimen";

const row = { display: "flex", flexWrap: "wrap", alignItems: "center", gap: "var(--space-3)" } as const;

export default defineSpecimen({
  id: "buttons",
  title: "Buttons",
  description: "Five variants in every interaction state. Hover, pressed and focus are pinned so you can compare them side by side.",
  order: 10,
  blocks: [
    {
      kind: "matrix",
      rows: ["primary", "secondary", "outline", "ghost", "danger"],
      columns: ["default", "hover", "pressed", "focus-visible", "disabled", "loading"],
      render: ({ row: variant, column: state }) => (
        <Button
          variant={variant as ButtonVariant}
          force={forced(state)}
          disabled={state === "disabled"}
          loading={state === "loading"}
        >
          Continue
        </Button>
      ),
    },
    {
      kind: "row",
      title: "Sizes",
      render: () => (
        <>
          <Button size="sm">Small</Button>
          <Button size="md">Medium</Button>
          <Button size="lg">Large</Button>
          <Button size="sm" variant="outline">
            Small
          </Button>
          <Button size="md" variant="outline">
            Medium
          </Button>
          <Button size="lg" variant="outline">
            Large
          </Button>
        </>
      ),
    },
    {
      kind: "block",
      title: "Live · hover, press, tab to focus",
      render: function LiveButtons() {
        const [busy, setBusy] = useState(false);
        return (
          <div style={row}>
            <Button
              loading={busy}
              onClick={() => {
                setBusy(true);
                setTimeout(() => setBusy(false), 1600);
              }}
            >
              Save changes
            </Button>
            <Button variant="secondary">Cancel</Button>
            <Button variant="outline">Preview</Button>
            <Button variant="ghost">Skip</Button>
            <Button variant="danger">Delete project</Button>
          </div>
        );
      },
    },
  ],
});
