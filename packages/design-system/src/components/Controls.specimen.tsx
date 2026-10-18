import { useState } from "react";
import { Checkbox, Radio, Switch } from "./Controls";
import { defineSpecimen, forced } from "./specimen";

const row = { display: "flex", flexWrap: "wrap", alignItems: "center", gap: "var(--space-4)" } as const;

export default defineSpecimen({
  id: "selection",
  title: "Selection controls",
  description: "Checkbox, radio and switch, including indeterminate. Toggle the live row to feel the transition.",
  order: 30,
  blocks: [
    {
      kind: "matrix",
      rows: ["checkbox", "checked", "indeterminate", "radio", "selected", "switch off", "switch on"],
      columns: ["default", "hover", "focus-visible", "disabled"],
      minColumn: 90,
      render: ({ row, column }) => {
        const force = forced(column);
        const props = {
          force: force === "active" ? undefined : force,
          disabled: column === "disabled",
          readOnly: true,
          "aria-label": `${row} ${column}`,
        };
        if (row === "checkbox" || row === "checked" || row === "indeterminate") {
          return <Checkbox {...props} checked={row !== "checkbox"} indeterminate={row === "indeterminate"} />;
        }
        if (row === "radio" || row === "selected") return <Radio {...props} checked={row === "selected"} />;
        return <Switch {...props} checked={row === "switch on"} />;
      },
    },
    {
      kind: "block",
      title: "Live",
      render: function LiveControls() {
        const [notify, setNotify] = useState(true);
        const [plan, setPlan] = useState("monthly");
        return (
          <div style={row}>
            <Switch label="Email notifications" checked={notify} onChange={(event) => setNotify(event.target.checked)} />
            <Checkbox label="Remember me" defaultChecked />
            <Radio label="Monthly" name="plan" checked={plan === "monthly"} onChange={() => setPlan("monthly")} />
            <Radio label="Yearly" name="plan" checked={plan === "yearly"} onChange={() => setPlan("yearly")} />
          </div>
        );
      },
    },
  ],
});
